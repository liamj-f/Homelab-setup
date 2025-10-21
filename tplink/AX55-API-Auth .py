#!/usr/bin/env python3
"""
TPLink Router API - Complete Login Implementation with RSA+AES Encryption
Based on analysis of update-store-BP3PGMSQ.js

Login Flow:
1. GET /login?form=keys - Get RSA public key (nn, ee) and password encryption parameters
2. GET /login?form=auth - Get authentication parameters (hash, sequence)
3. POST /login?form=login - Login with encrypted password using sign+data fields
"""

import requests
import base64
import json
import hashlib
import hmac
from Crypto.Cipher import DES3, AES
from Crypto.Util.Padding import pad, unpad
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import secrets


class TPLinkDESEncryption:
    """Old DES encryption for basic password storage"""
    PADDING_STR = "PKCS5Padding"
    IV = "26951234"
    
    @classmethod
    def encrypt(cls, plaintext):
        if not plaintext:
            return plaintext
        key = cls.PADDING_STR.ljust(24, "0").encode('utf-8')
        iv = cls.IV.encode('utf-8')
        cipher = DES3.new(key, DES3.MODE_CBC, iv)
        plaintext_bytes = plaintext.encode('utf-8')
        padded_data = pad(plaintext_bytes, DES3.block_size)
        ciphertext = cipher.encrypt(padded_data)
        return base64.b64encode(ciphertext).decode('utf-8')


class AESEncryptor:
    """AES-128-CBC encryption for secure login"""
    def __init__(self):
        # Generate random 16-byte key and IV (using digits only like JS)
        self.key = self._generate_random_digits(16)
        self.iv = self._generate_random_digits(16)
    
    def _generate_random_digits(self, length):
        """Generate random string of digits"""
        return ''.join(str(secrets.randbelow(10)) for _ in range(length))
    
    def get_formatted_key(self):
        """Return key in format: k=KEY&i=IV"""
        return f"k={self.key}&i={self.iv}"
    
    def encrypt(self, plaintext):
        """Encrypt data with AES-128-CBC"""
        cipher = AES.new(self.key.encode(), AES.MODE_CBC, self.iv.encode())
        padded = pad(plaintext.encode(), AES.block_size)
        encrypted = cipher.encrypt(padded)
        return base64.b64encode(encrypted).decode()
    
    def decrypt(self, ciphertext):
        """Decrypt data with AES-128-CBC"""
        cipher = AES.new(self.key.encode(), AES.MODE_CBC, self.iv.encode())
        decrypted = cipher.decrypt(base64.b64decode(ciphertext))
        return unpad(decrypted, AES.block_size).decode()


class RSAEncryptor:
    """RSA encryption for signatures"""
    def __init__(self, n_hex, e_hex):
        self.n = int(n_hex, 16)
        self.e = int(e_hex, 16)
        # Calculate the key size in bytes
        self.key_size = (self.n.bit_length() + 7) // 8
    
    def encrypt(self, plaintext):
        """Encrypt with RSA public key and return hex string padded to key size"""
        # Create RSA public key
        key = RSA.construct((self.n, self.e))
        cipher = PKCS1_OAEP.new(key)
        
        # Encrypt
        encrypted = cipher.encrypt(plaintext.encode())
        
        # Convert to hex and pad to match key size * 2 (hex chars)
        hex_result = encrypted.hex()
        expected_length = self.key_size * 2
        
        # Pad with leading zeros if needed
        if len(hex_result) < expected_length:
            hex_result = hex_result.zfill(expected_length)
        
        return hex_result


class TPLinkEncryptor:
    """Main encryptor handling the full login encryption scheme"""
    SIGNATURE_OFFSET = 53
    
    def __init__(self):
        self.aes = AESEncryptor()
        self.auth_rsa = None  # RSA for auth signature
        self.hash = ""  # Initial hash (empty for first login)
        self.sequence = 0
    
    def init(self, auth_nn, auth_ee, sequence):
        """Initialize with auth parameters"""
        self.sequence = sequence
        self.auth_rsa = RSAEncryptor(auth_nn, auth_ee)
        # Hash is SHA256 of empty string for initial login
        # SHA256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
        self.hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    
    def _generate_signature(self, length):
        """Generate signature for login request"""
        # Build signature string: k=<key>&i=<iv>&h=<hash>&s=<sequence>
        sig_data = f"{self.aes.get_formatted_key()}&h={self.hash}&s={length}"
        
        print(f"\n  Signature data: {sig_data}")
        print(f"  Total signature data length: {len(sig_data)}")
        
        # Encrypt signature in chunks with RSA
        result = ""
        offset = 0
        chunk_num = 0
        
        while offset < len(sig_data):
            chunk = sig_data[offset:offset + self.SIGNATURE_OFFSET]
            print(f"  Chunk {chunk_num + 1}: '{chunk}' (length: {len(chunk)})")
            
            encrypted_chunk = self.auth_rsa.encrypt(chunk)
            print(f"  Encrypted chunk {chunk_num + 1} length: {len(encrypted_chunk)}")
            
            result += encrypted_chunk
            offset += self.SIGNATURE_OFFSET
            chunk_num += 1
        
        print(f"  Total signature length: {len(result)} (expected: 1536)")
        
        return result
    
    def encrypt_login(self, data):
        """
        Encrypt login request data
        Returns dict with 'sign' and 'data' fields
        """
        if not self.sequence:
            return {}
        
        # Serialize data to JSON with NO SPACES (compact format)
        json_data = json.dumps(data, separators=(',', ':'))
        
        print(f"\n  JSON data to encrypt: {json_data}")
        print(f"  JSON data length: {len(json_data)}")
        
        # Encrypt with AES
        encrypted_data = self.aes.encrypt(json_data)
        
        # Calculate sequence for signature (sequence + encrypted data length)
        seq_value = self.sequence + len(encrypted_data)
        
        print(f"  Encrypted data length: {len(encrypted_data)}")
        print(f"  Sequence for signature: {self.sequence} + {len(encrypted_data)} = {seq_value}")
        
        # Generate signature
        signature = self._generate_signature(seq_value)
        
        return {
            "sign": signature,
            "data": encrypted_data
        }


class TPLinkRouterAPI:
    """TPLink Router API Client with full encryption support"""
    
    def __init__(self, router_ip="192.168.0.1"):
        self.base_url = f"http://{router_ip}"
        self.session = requests.Session()
        self.token = None
        self.encryptor = None
        
    def _make_request(self, endpoint, data=None, method="POST", is_form_data=False):
        """Make HTTP request"""
        url = f"{self.base_url}/cgi-bin/luci/;stok={self.token or ''}{endpoint}"
        
        headers = {
            "Accept": "application/json, text/plain, */*",
            "Cache-Control": "no-cache",
            "Referer": f"{self.base_url}/",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        }
        
        try:
            if method == "GET":
                response = self.session.get(url, headers=headers)
            else:
                if is_form_data:
                    # Send as form data (application/x-www-form-urlencoded)
                    headers["Content-Type"] = "application/x-www-form-urlencoded"
                    response = self.session.post(url, data=data, headers=headers)
                else:
                    # Send as JSON
                    headers["Content-Type"] = "application/json"
                    response = self.session.post(url, json=data, headers=headers)
            
            result = response.json()
            print(f"Response: {json.dumps(result, indent=2)}")
            return result
        except Exception as e:
            print(f"✗ Request error: {e}")
            print(f"Response text: {response.text if 'response' in locals() else 'No response'}")
            return None
    
    def get_keys(self):
        """Step 1: Get RSA public keys"""
        print("Step 1: Getting RSA keys...")
        result = self._make_request("/login?form=keys", 
                                    data="operation=read",
                                    method="POST",
                                    is_form_data=True)
        
        if result and result.get("success"):
            data = result.get("data", {})
            # Keys are under data.password as a list
            password_data = data.get("password", [])
            if isinstance(password_data, list) and len(password_data) >= 2:
                nn = password_data[0]  # RSA modulus
                ee = password_data[1]  # RSA exponent
                print(f"✓ Got RSA keys:")
                print(f"  nn={nn[:60]}...")
                print(f"  ee={ee}")
                return nn, ee
        
        print("✗ Failed to get RSA keys")
        return None, None
    
    def get_auth(self):
        """Step 2: Get authentication parameters"""
        print("Step 2: Getting auth parameters...")
        result = self._make_request("/login?form=auth", 
                                    data="operation=read",
                                    method="POST",
                                    is_form_data=True)
        
        if result and result.get("success"):
            data = result.get("data", {})
            
            # The 'key' field contains [nn, ee] for auth RSA key (different from password RSA key)
            auth_key = data.get("key", [])
            sequence = data.get("seq", 0)
            
            if auth_key and len(auth_key) >= 2:
                nn = auth_key[0]  # Auth RSA modulus
                ee = auth_key[1]  # Auth RSA exponent
                print(f"✓ Got auth params:")
                print(f"  Auth key nn={nn[:60]}...")
                print(f"  Auth key ee={ee}")
                print(f"  Sequence={sequence}")
                return nn, ee, sequence
        
        print("✗ Failed to get auth parameters")
        return None, None, None
    
    def login(self, password):
        """
        Complete login process:
        1. Get RSA keys for password encryption
        2. Get auth parameters (RSA keys for signature + sequence)
        3. Send encrypted login request
        """
        print("\n=== TPLink Router Login ===\n")
        
        # Step 1: Get RSA keys for password encryption
        password_nn, password_ee = self.get_keys()
        if not password_nn or not password_ee:
            return False
        
        # Step 2: Get auth parameters (different RSA key + sequence)
        auth_nn, auth_ee, sequence = self.get_auth()
        if not auth_nn or not auth_ee or sequence is None:
            return False
        
        # Step 3: Initialize encryptor with auth parameters
        print("\nStep 3: Initializing encryptor...")
        self.encryptor = TPLinkEncryptor()
        self.encryptor.init(auth_nn, auth_ee, sequence)
        print("✓ Encryptor initialized")
        
        # Step 4: Encrypt password with RSA (using password keys, not auth keys)
        print("\nStep 4: Encrypting password...")
        password_rsa = RSAEncryptor(password_nn, password_ee)
        encrypted_password = password_rsa.encrypt(password)
        print(f"✓ Password encrypted: {encrypted_password[:60]}...")
        
        # Step 5: Prepare and encrypt login request
        print("\nStep 5: Preparing login request...")
        
        # Use the method:"do" structure from the original JavaScript
        login_data = {
            "method": "do",
            "login": {
                "password": encrypted_password
            }
        }
        
        print(f"  Login data structure: {json.dumps(login_data, indent=2)}")
        
        # Encrypt entire request with auth RSA+AES
        encrypted_request = self.encryptor.encrypt_login(login_data)
        print(f"✓ Login request encrypted")
        print(f"  Sign length: {len(encrypted_request['sign'])}")
        print(f"  Data length: {len(encrypted_request['data'])}")
        
        # Step 6: Send login request
        print("\nStep 6: Sending login request...")
        
        # Send to /login?form=login with encrypted sign+data
        import urllib.parse
        form_data = f"sign={encrypted_request['sign']}&data={urllib.parse.quote(encrypted_request['data'])}"
        
        result = self._make_request("/login?form=login", 
                                   data=form_data,
                                   method="POST",
                                   is_form_data=True)
        
        # Check if response is encrypted
        if result and isinstance(result.get("data"), str) and result.get("data"):
            encrypted_response = result.get("data")
            print(f"\n  Response is encrypted, decrypting...")
            try:
                decrypted = self.encryptor.aes.decrypt(encrypted_response)
                print(f"  Decrypted response: {decrypted}")
                result = json.loads(decrypted)
            except Exception as e:
                print(f"  Failed to decrypt response: {e}")
        
        if result and result.get("success"):
            # Extract token
            data = result.get("data", {})
            self.token = data.get("stok") if isinstance(data, dict) else None
            print(f"\n✓ Login successful! Token: {self.token}")
            return True
        else:
            error_code = result.get("errorCode", "unknown") if result else "no response"
            print(f"\n✗ Login failed with error: {error_code}")
            if result:
                print(f"  Full response: {json.dumps(result, indent=2)}")
            return False
    
    def make_authenticated_request(self, endpoint, data=None):
        """Make request with authentication"""
        if not self.token:
            raise Exception("Not logged in")
        
        # Encrypt data if encryptor is available
        if self.encryptor and data:
            encrypted_data = self.encryptor.encrypt(data, with_aes_key=False)
            return self._make_request(endpoint, encrypted_data)
        else:
            return self._make_request(endpoint, data)


def main():
    """Main execution"""
    print("=" * 60)
    print("TPLink Router API - Complete Authentication")
    print("=" * 60)
    
    # Configuration
    ROUTER_IP = "192.168.0.1"
    PASSWORD = "admin"  # Change this!
    
    # Create API client
    api = TPLinkRouterAPI(ROUTER_IP)
    
    # Attempt login
    if api.login(PASSWORD):
        print("\n" + "=" * 60)
        print("SUCCESS - You are now logged in!")
        print("=" * 60)
        print(f"\nYou can now make authenticated requests using token: {api.token}")
    else:
        print("\n" + "=" * 60)
        print("FAILED - Could not log in")
        print("=" * 60)
        print("\nTroubleshooting:")
        print("1. Check router IP address")
        print("2. Verify password")
        print("3. Ensure router web interface is accessible")


if __name__ == "__main__":
    main()
