#!/usr/bin/env python3

import os
import sys
import time
import hashlib
import base64
import oci
from datetime import datetime


def _resolve_cert_path(configured_path: str) -> str:
    """Return configured_path if it exists, otherwise auto-discover from /etc/letsencrypt/live/."""
    if os.path.isdir(configured_path):
        return configured_path
    live_dir = '/etc/letsencrypt/live'
    if os.path.isdir(live_dir):
        for entry in sorted(os.listdir(live_dir)):
            candidate = os.path.join(live_dir, entry)
            if os.path.isfile(os.path.join(candidate, 'fullchain.pem')):
                print(f"[INFO] Configured path '{configured_path}' not found; using auto-discovered '{candidate}'", flush=True)
                return candidate
    return configured_path  # Fall back so the original error surfaces clearly


# Configuration
CERT_PATH = _resolve_cert_path(os.getenv('CERT_PATH', '/etc/letsencrypt/live/npm-2'))
OCI_CERT_ID = os.getenv('OCI_CERT_ID')
CHECK_INTERVAL = int(os.getenv('CHECK_INTERVAL', '3600'))

# OCI credentials
oci_key_base64 = os.getenv('OCI_KEY_CONTENT_BASE64')
if oci_key_base64:
    oci_key_decoded = base64.b64decode(oci_key_base64).decode('utf-8')
else:
    oci_key_decoded = os.getenv('OCI_KEY_CONTENT')

config = {
    "user": os.getenv('OCI_USER'),
    "fingerprint": os.getenv('OCI_FINGERPRINT'),
    "tenancy": os.getenv('OCI_TENANCY'),
    "region": os.getenv('OCI_REGION', 'uk-london-1'),
    "key_content": oci_key_decoded,
}


def log(message):
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    print(f"[{timestamp}] {message}", flush=True)


def read_cert_files():
    """Read cert files and return (fullchain, chain, privkey) or raise."""
    fullchain_path = os.path.join(CERT_PATH, 'fullchain.pem')
    chain_path = os.path.join(CERT_PATH, 'chain.pem')
    privkey_path = os.path.join(CERT_PATH, 'privkey.pem')

    with open(fullchain_path, 'r') as f:
        fullchain = f.read()
    with open(chain_path, 'r') as f:
        chain = f.read()
    with open(privkey_path, 'r') as f:
        privkey = f.read()

    return fullchain, chain, privkey


def get_cert_hash():
    """Return SHA256 hash of fullchain.pem + privkey.pem content."""
    fullchain, _, privkey = read_cert_files()
    h = hashlib.sha256()
    h.update(fullchain.encode())
    h.update(privkey.encode())
    return h.hexdigest()


def upload_certificate(client):
    """Upload current cert files as a new version in OCI."""
    fullchain, chain, privkey = read_cert_files()

    update_details = oci.certificates_management.models.UpdateCertificateDetails(
        certificate_config=oci.certificates_management.models.UpdateCertificateByImportingConfigDetails(
            config_type="IMPORTED",
            certificate_pem=fullchain,
            cert_chain_pem=chain,
            private_key_pem=privkey,
        )
    )

    client.update_certificate(OCI_CERT_ID, update_details)
    log("Certificate updated successfully in OCI.")


def main():
    log("=== OCI Certificate Updater Starting ===")
    log(f"Cert path: {CERT_PATH}")
    log(f"OCI Cert ID: {OCI_CERT_ID}")
    log(f"Check interval: {CHECK_INTERVAL}s")
    log(f"Region: {config['region']}")

    if not OCI_CERT_ID:
        log("ERROR: OCI_CERT_ID not set!")
        sys.exit(1)

    if not all([config['user'], config['fingerprint'], config['tenancy'], config['key_content']]):
        log("ERROR: OCI credentials not properly configured!")
        sys.exit(1)

    try:
        client = oci.certificates_management.CertificatesManagementClient(config)
        log("OCI client initialised successfully.")
    except Exception as e:
        log(f"ERROR: Failed to initialise OCI client: {e}")
        sys.exit(1)

    # Get baseline hash
    try:
        current_hash = get_cert_hash()
        log(f"Baseline cert hash: {current_hash[:12]}...")
        # Upload on first run to ensure OCI is in sync
        log("Uploading cert on startup to ensure OCI is in sync...")
        upload_certificate(client)
    except Exception as e:
        log(f"ERROR: Failed on startup: {e}")
        sys.exit(1)

    while True:
        try:
            time.sleep(CHECK_INTERVAL)
            new_hash = get_cert_hash()
            if new_hash != current_hash:
                log(f"Cert change detected (hash: {new_hash[:12]}...). Uploading to OCI...")
                upload_certificate(client)
                current_hash = new_hash
            else:
                log("Cert unchanged, skipping upload.")
        except KeyboardInterrupt:
            log("Shutting down...")
            break
        except Exception as e:
            log(f"ERROR: {e}")
            time.sleep(60)


if __name__ == "__main__":
    main()
