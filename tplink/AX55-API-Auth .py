#!/usr/bin/env python3
"""
TPLink Router API - FINAL ATTEMPT

Based on JavaScript analysis:
- NO password hashing! 
- Just RSA encrypt the raw password
- JSON structure: {password, operation: "login", confirm: true}
"""

import requests
import base64
import json
import secrets
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP


class AESEncryptor:
    """AES-128-CBC encryption"""
    def __init__(self):
        self.key = self._generate_random_digits(16)
        self.iv = self._generate_random_digits(16)
    
    def _generate_random_digits(self, length):
        return ''.join(str(secrets.randbelow(10)) for _ in range(length))
    
    def get_formatted_key(self):
        return f"k={self.key}&i={self.iv}"
    
    def encrypt(self, plaintext):
        cipher = AES.new(self.key.encode(), AES.MODE_CBC, self.iv.encode())
        padded = pad(plaintext.encode(), AES.block_size)
        encrypted = cipher.encrypt(padded)
        return base64.b64encode(encrypted).decode()
    
    def decrypt(self, ciphertext):
        cipher = AES.new(self.key.encode(), AES.MODE_CBC, self.iv.encode())
        decrypted = cipher.decrypt(base64.b64decode(ciphertext))
        return unpad(decrypted, AES.block_size).decode()


class RSAEncryptor:
    """RSA encryption"""
    def __init__(self, n_hex, e_hex):
        self.n = int(n_hex, 16)
        self.e = int(e_hex, 16)
        self.key_size = (self.n.bit_length() + 7) // 8
    
    def encrypt(self, plaintext):
        key = RSA.construct((self.n, self.e))
        cipher = PKCS1_OAEP.new(key)
        encrypted = cipher.encrypt(plaintext.encode())
        hex_result = encrypted.hex()
        expected_length = self.key_size * 2
        if len(hex_result) < expected_length:
            hex_result = hex_result.zfill(expected_length)
        return hex_result.upper()


class TPLinkEncryptor:
    """Main encryptor"""
    SIGNATURE_OFFSET = 53
    
    def __init__(self):
        self.aes = AESEncryptor()
        self.auth_rsa = None
        self.hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        self.sequence = 0
    
    def init(self, auth_nn, auth_ee, sequence):
        self.sequence = sequence
        self.auth_rsa = RSAEncryptor(auth_nn, auth_ee)
    
    def _generate_signature(self, length):
        sig_data = f"{self.aes.get_formatted_key()}&h={self.hash}&s={length}"
        result = ""
        offset = 0
        
        while offset < len(sig_data):
            chunk = sig_data[offset:offset + self.SIGNATURE_OFFSET]
            encrypted_chunk = self.auth_rsa.encrypt(chunk)
            result += encrypted_chunk
            offset += self.SIGNATURE_OFFSET
        
        return result
    
    def encrypt_login(self, data):
        if not self.sequence:
            return {}
        
        json_data = json.dumps(data, separators=(',', ':'))
        encrypted_data = self.aes.encrypt(json_data)
        seq_value = self.sequence + len(encrypted_data)
        signature = self._generate_signature(seq_value)
        
        return {"sign": signature, "data": encrypted_data}


class TPLinkRouterAPI:
    """TPLink Router API Client"""
    
    def __init__(self, router_ip="192.168.0.1"):
        self.base_url = f"http://{router_ip}"
        self.session = requests.Session()
        self.token = None
        self.encryptor = None
        
    def _make_request(self, endpoint, data=None, method="POST", is_form_data=False):
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
                    headers["Content-Type"] = "application/x-www-form-urlencoded"
                    response = self.session.post(url, data=data, headers=headers)
                else:
                    headers["Content-Type"] = "application/json"
                    response = self.session.post(url, json=data, headers=headers)
            
            result = response.json()
            return result
        except Exception as e:
            print(f"✗ Request error: {e}")
            if 'response' in locals():
                print(f"Response text: {response.text}")
            return None
    
    def get_keys(self):
        result = self._make_request("/login?form=keys", 
                                    data="operation=read",
                                    method="POST",
                                    is_form_data=True)
        
        if result and result.get("success"):
            password_data = result.get("data", {}).get("password", [])
            if isinstance(password_data, list) and len(password_data) >= 2:
                return password_data[0], password_data[1]
        return None, None
    
    def get_auth(self):
        result = self._make_request("/login?form=auth", 
                                    data="operation=read",
                                    method="POST",
                                    is_form_data=True)
        
        if result and result.get("success"):
            data = result.get("data", {})
            auth_key = data.get("key", [])
            sequence = data.get("seq", 0)
            
            if auth_key and len(auth_key) >= 2:
                return auth_key[0], auth_key[1], sequence
        return None, None, None
    
    def login(self, password):
        """Complete login - NO HASHING VERSION"""
        print("\n" + "="*60)
        print("TPLink AX55 Login - NO HASH VERSION")
        print("="*60)
        print("Change: RSA encrypt raw password (no hashing!)")
        print("="*60 + "\n")
        
        # Get keys
        print("Step 1: Getting RSA keys...")
        password_nn, password_ee = self.get_keys()
        if not password_nn or not password_ee:
            print("✗ Failed to get RSA keys")
            return False
        print("✓ Got RSA keys")
        
        # Get auth
        print("\nStep 2: Getting auth parameters...")
        auth_nn, auth_ee, sequence = self.get_auth()
        if not auth_nn or not auth_ee or sequence is None:
            print("✗ Failed to get auth parameters")
            return False
        print(f"✓ Got auth params (seq={sequence})")
        
        # Initialize encryptor
        print("\nStep 3: Initializing encryptor...")
        self.encryptor = TPLinkEncryptor()
        self.encryptor.init(auth_nn, auth_ee, sequence)
        print("✓ Encryptor ready")
        
        # RSA encrypt raw password directly (NO HASHING!)
        print("\nStep 4: RSA encrypting password (no hash)...")
        password_rsa = RSAEncryptor(password_nn, password_ee)
        encrypted_password = password_rsa.encrypt(password)
        print(f"✓ Password encrypted: {encrypted_password[:40]}...")
        
        # Prepare login request
        print("\nStep 5: Preparing login request...")
        login_data = {
            "password": encrypted_password,
            "operation": "login",
            "confirm": True
        }
        print(f"✓ Login data: {json.dumps(login_data, separators=(',', ':'))[:100]}...")
        
        # Encrypt login request
        print("\nStep 6: Encrypting login request...")
        encrypted_request = self.encryptor.encrypt_login(login_data)
        print(f"✓ Request encrypted (data length: {len(encrypted_request['data'])})")
        
        # Send login
        print("\nStep 7: Sending login request...")
        import urllib.parse
        form_data = f"sign={encrypted_request['sign']}&data={urllib.parse.quote(encrypted_request['data'])}"
        
        result = self._make_request("/login?form=login", 
                                   data=form_data,
                                   method="POST",
                                   is_form_data=True)
        
        # Decrypt response
        if result and isinstance(result.get("data"), str):
            try:
                decrypted = self.encryptor.aes.decrypt(result.get("data"))
                print(f"✓ Response decrypted: {decrypted}")
                result = json.loads(decrypted)
            except Exception as e:
                print(f"✗ Decryption failed: {e}")
        
        # Check success
        if result and result.get("success"):
            self.token = result.get("data", {}).get("stok") if isinstance(result.get("data"), dict) else None
            print("\n" + "="*60)
            print("✓✓✓ LOGIN SUCCESSFUL! ✓✓✓")
            print("="*60)
            print(f"Token: {self.token}\n")
            return True
        else:
            error = result.get("errorcode", "unknown") if result else "no response"
            print("\n" + "="*60)
            print(f"✗ Login failed: {error}")
            print("="*60)
            if result:
                print(f"Full response: {json.dumps(result, indent=2)}")
            return False


def main():
    print("="*60)
    print("TPLink AX55 Authentication - NO HASH VERSION")
    print("="*60)
    print("Testing: RSA encrypt raw password (no SHA256 hash)")
    print("="*60 + "\n")
    
    # Configuration - USE YOUR ACTUAL PASSWORD!
    ROUTER_IP = "192.168.0.1"
    PASSWORD = "your_actual_password_here"  # CHANGE THIS!
    
    api = TPLinkRouterAPI(ROUTER_IP)
    
    if api.login(PASSWORD):
        print("✓ Ready for authenticated requests!")
        print(f"  Token: {api.token}")
    else:
        print("\nPlease verify:")
        print("- IP address is correct")
        print("- Password is correct")
        print("- Router web interface is accessible")


if __name__ == "__main__":
    main()
