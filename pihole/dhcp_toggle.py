#!/usr/bin/env python3
"""Turn the LAN DHCP server on/off on a TP-Link Archer AX55 (v1.0,
firmware 1.5.12) via the router's own JSON API. Pure HTTP -- no browser,
no Playwright.

Background -- this firmware's crypto differs from every published
TP-Link router library in two ways, both reverse-engineered from the
router's own minified frontend JS (fetched straight off the router,
see `update-store-*.js`'s `RSA`/`Encryptor` classes):

  1. LOGIN request signature: each 53-byte chunk of the sign string is
     RSA-OAEP encrypted (not PKCS1v1.5) -- this firmware has the
     "RSA_PKCS1_OAEP" feature on. The password field itself is still
     plain PKCS1v1.5, unchanged from older routers.

  2. Every request AFTER login: the signed hash is replaced with
     SHA256(this request's own AES-encrypted ciphertext), and each
     53-byte chunk of the sign string is HMAC-SHA256'd (not RSA
     encrypted) using the session's `k=<aeskey>&i=<aesiv>` string as
     the HMAC key.

Both were found by pulling apart the router's own JS (login route ->
`index-*.js`'s `LocalLogin` component -> `update-store-*.js`'s
`RSA`/`Encryptor`/`EncryptManager` classes) and testing each hypothesis
directly against the live router.

Usage:
    python dhcp_toggle.py status
    python dhcp_toggle.py on
    python dhcp_toggle.py off

Credentials are read from environment variables (never hardcode them):
    ROUTER_HOST       default: http://192.168.0.1
    ROUTER_PASSWORD   required
    ROUTER_DHCP_POOL_START / ROUTER_DHCP_POOL_END
                      default: 192.168.0.100 / 192.168.0.199
                      (only used if enabling DHCP while the pool is unset)

Requires: pip install requests pycryptodome
"""

import argparse
import hashlib
import hmac
import json
import os
import re
import sys

import requests
from Crypto.Cipher import PKCS1_OAEP, PKCS1_v1_5
from Crypto.PublicKey.RSA import construct
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
from binascii import b2a_hex

HOST = os.getenv("ROUTER_HOST", "http://192.168.0.1")
PASSWORD = os.getenv("ROUTER_PASSWORD")
DEFAULT_POOL_START = os.getenv("ROUTER_DHCP_POOL_START", "192.168.0.100")
DEFAULT_POOL_END = os.getenv("ROUTER_DHCP_POOL_END", "192.168.0.199")

SIGNATURE_CHUNK = 53
HEADERS = {
    "Referer": f"{HOST}/webpages/index.html",
    "Origin": HOST,
    "Content-Type": "application/x-www-form-urlencoded",
}


def log(msg: str) -> None:
    print(msg, flush=True)


# --------------------------------------------------------------------------
# Crypto primitives
# --------------------------------------------------------------------------

def _rsa_encrypt(data: str, nn: str, ee: str, oaep: bool) -> str:
    key = construct((int(nn, 16), int(ee, 16)))
    cipher = PKCS1_OAEP.new(key) if oaep else PKCS1_v1_5.new(key)
    return b2a_hex(cipher.encrypt(data.encode())).decode()


def _rsa_sign_chunks(s: str, nn: str, ee: str) -> str:
    """Login-time signature: RSA-OAEP encrypt each 53-byte chunk."""
    sign = ""
    pos = 0
    while pos < len(s):
        sign += _rsa_encrypt(s[pos:pos + SIGNATURE_CHUNK], nn, ee, oaep=True)
        pos += SIGNATURE_CHUNK
    return sign


def _hmac_sign_chunks(s: str, aes_key_str: str) -> str:
    """Post-login signature: HMAC-SHA256 each 53-byte chunk, keyed by the
    session's 'k=<aeskey>&i=<aesiv>' string."""
    sign = ""
    pos = 0
    while pos < len(s):
        chunk = s[pos:pos + SIGNATURE_CHUNK]
        sign += hmac.new(aes_key_str.encode(), chunk.encode(), hashlib.sha256).hexdigest()
        pos += SIGNATURE_CHUNK
    return sign


class Session:
    """Holds the per-session AES key/iv and RSA signing key, and
    implements the router's request/response encryption envelope."""

    def __init__(self, host: str):
        self.host = host
        self._aes_key = b2a_hex(get_random_bytes(8))  # 16 hex chars
        self._aes_iv = b2a_hex(get_random_bytes(8))
        self.nn = ""  # signature RSA key (from /login?form=auth)
        self.ee = ""
        self.seq = 0
        self.stok = ""
        self.sysauth = ""

    def _aes_cipher(self):
        return AES.new(self._aes_key, AES.MODE_CBC, self._aes_iv)

    def aes_encrypt(self, raw: str) -> str:
        pad_len = AES.block_size - len(raw) % AES.block_size
        padded = raw + chr(pad_len) * pad_len
        import base64
        return base64.b64encode(self._aes_cipher().encrypt(padded.encode())).decode()

    def aes_decrypt(self, enc: str) -> str:
        import base64
        decrypted = self._aes_cipher().decrypt(base64.b64decode(enc))
        return decrypted[: -decrypted[-1]].decode()

    def aes_key_string(self) -> str:
        return f"k={self._aes_key.decode()}&i={self._aes_iv.decode()}"

    def _get(self, path: str) -> dict:
        resp = requests.post(
            f"{self.host}/cgi-bin/luci/;stok=/{path}",
            params={"operation": "read"},
            timeout=15,
        )
        resp.raise_for_status()
        return resp.json()

    def fetch_password_key(self) -> tuple[str, str]:
        data = self._get("login?form=keys")["data"]["password"]
        return data[0], data[1]

    def fetch_signing_key_and_seq(self) -> None:
        data = self._get("login?form=auth")["data"]
        self.seq = data["seq"]
        self.nn, self.ee = data["key"][0], data["key"][1]

    def login(self, password: str) -> None:
        pwd_nn, pwd_ee = self.fetch_password_key()
        self.fetch_signing_key_and_seq()

        crypted_pwd = _rsa_encrypt(password, pwd_nn, pwd_ee, oaep=False)
        body = f"operation=login&password={crypted_pwd}&confirm=true"
        enc_body = self.aes_encrypt(body)

        password_hash = hashlib.sha256(("admin" + password).encode()).hexdigest()
        sign_str = f"{self.aes_key_string()}&h={password_hash}&s={self.seq + len(enc_body)}"
        sign = _rsa_sign_chunks(sign_str, self.nn, self.ee)

        resp = requests.post(
            f"{self.host}/cgi-bin/luci/;stok=/login?form=login",
            data={"sign": sign, "data": enc_body},
            headers=HEADERS,
            timeout=15,
        )
        if resp.status_code != 200:
            raise RuntimeError(f"Login failed: HTTP {resp.status_code}")

        payload = json.loads(self.aes_decrypt(resp.json()["data"]))
        if not payload.get("success"):
            raise RuntimeError(f"Login rejected: {payload}")

        self.stok = payload["data"]["stok"]
        m = re.search("sysauth=(.*?);", resp.headers.get("set-cookie", ""))
        if not m:
            raise RuntimeError("Login succeeded but no sysauth cookie was returned")
        self.sysauth = m.group(1)

    def call(self, path: str, body: str) -> dict:
        """Make an authenticated post-login request. `path` is the
        endpoint after the stok segment, e.g. 'admin/dhcps?form=setting'."""
        enc_body = self.aes_encrypt(body)
        req_hash = hashlib.sha256(enc_body.encode()).hexdigest()
        sign_str = f"h={req_hash}&s={self.seq + len(enc_body)}"
        sign = _hmac_sign_chunks(sign_str, self.aes_key_string())

        resp = requests.post(
            f"{self.host}/cgi-bin/luci/;stok={self.stok}/{path}",
            data={"sign": sign, "data": enc_body},
            headers=HEADERS,
            cookies={"sysauth": self.sysauth},
            timeout=15,
        )
        if resp.status_code != 200:
            raise RuntimeError(f"{path} -> HTTP {resp.status_code}")

        payload = json.loads(self.aes_decrypt(resp.json()["data"]))
        if not payload.get("success"):
            raise RuntimeError(f"{path} -> API error: {payload}")
        return payload.get("data", {})

    def logout(self) -> None:
        try:
            self.call("admin/system?form=logout", "operation=write")
        except Exception as e:
            log(f"[warn] logout may not have completed cleanly: {e}")


# --------------------------------------------------------------------------
# DHCP operations
# --------------------------------------------------------------------------

def read_dhcp_setting(session: Session) -> dict:
    return session.call("admin/dhcps?form=setting", "operation=read")


def write_dhcp_setting(session: Session, enable: bool, current: dict) -> dict:
    pool_start = current.get("ipaddr_start") or DEFAULT_POOL_START
    pool_end = current.get("ipaddr_end") or DEFAULT_POOL_END
    lease = current.get("leasetime") or "120"
    gateway = current.get("gateway") or ""
    pri_dns = current.get("pri_dns") or ""
    snd_dns = current.get("snd_dns") or ""

    body = (
        f"operation=write&enable={'on' if enable else 'off'}"
        f"&ipaddr_start={pool_start}&ipaddr_end={pool_end}"
        f"&leasetime={lease}&gateway={gateway}&pri_dns={pri_dns}&snd_dns={snd_dns}"
    )
    return session.call("admin/dhcps?form=setting", body)


def main() -> None:
    parser = argparse.ArgumentParser(description="Turn DHCP on/off on a TP-Link Archer AX55 router")
    parser.add_argument("action", choices=["status", "on", "off"])
    args = parser.parse_args()

    if not PASSWORD:
        sys.exit("ROUTER_PASSWORD env var is not set")

    session = Session(HOST)
    try:
        session.login(PASSWORD)

        current = read_dhcp_setting(session)
        currently_enabled = current.get("enable") == "on"

        if args.action == "status":
            log(f"DHCP server enabled: {currently_enabled}")
            if currently_enabled:
                log(f"  pool: {current['ipaddr_start']} - {current['ipaddr_end']}")
            return

        want_enabled = args.action == "on"
        if currently_enabled == want_enabled:
            log(f"[dhcp] already {'enabled' if want_enabled else 'disabled'}, nothing to do")
            return

        write_dhcp_setting(session, want_enabled, current)

        # verify with an independent re-read, not just the write's own echo
        confirmed = read_dhcp_setting(session)
        confirmed_enabled = confirmed.get("enable") == "on"
        if confirmed_enabled != want_enabled:
            raise RuntimeError(
                f"Write reported success but re-read disagrees "
                f"(wanted enabled={want_enabled}, got enabled={confirmed_enabled})"
            )
        log(f"[dhcp] confirmed {'enabled' if want_enabled else 'disabled'} (persisted)")
    finally:
        if session.stok:
            session.logout()


if __name__ == "__main__":
    main()
