#!/usr/bin/env python3

import os
import sys
import time
import hashlib
import base64
import oci
from datetime import datetime
from cryptography import x509
from cryptography.hazmat.backends import default_backend


# Configuration
OCI_CERT_ID = os.getenv('OCI_CERT_ID')
CHECK_INTERVAL = int(os.getenv('CHECK_INTERVAL', '3600'))
CERT_PATH_OVERRIDE = os.getenv('CERT_PATH')  # optional explicit override

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


def get_pem_names(fullchain_path: str) -> set:
    """Return all CN + SAN DNS names from the first cert in a PEM file."""
    with open(fullchain_path, 'rb') as f:
        pem_data = f.read()
    cert = x509.load_pem_x509_certificate(pem_data, default_backend())
    names = set()
    cn_attrs = cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
    if cn_attrs:
        names.add(cn_attrs[0].value)
    try:
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        names.update(san.value.get_values_for_type(x509.DNSName))
    except x509.ExtensionNotFound:
        pass
    return names


def find_cert_path(client) -> str:
    """Find the letsencrypt cert dir whose CN/SAN matches the OCI certificate."""
    if CERT_PATH_OVERRIDE:
        log(f"Using explicit CERT_PATH: {CERT_PATH_OVERRIDE}")
        return CERT_PATH_OVERRIDE

    log("No CERT_PATH set — discovering cert path by matching domain against OCI cert...")

    oci_cert = client.get_certificate(OCI_CERT_ID).data
    domain = oci_cert.subject.common_name
    if not domain:
        log("ERROR: OCI cert has no common name — set CERT_PATH explicitly.")
        sys.exit(1)
    log(f"OCI cert domain: {domain}")

    live_dir = '/etc/letsencrypt/live'
    if not os.path.isdir(live_dir):
        log(f"ERROR: {live_dir} does not exist — is the letsencrypt volume mounted?")
        sys.exit(1)

    for entry in sorted(os.listdir(live_dir)):
        candidate = os.path.join(live_dir, entry)
        fullchain = os.path.join(candidate, 'fullchain.pem')
        if not os.path.isfile(fullchain):
            continue
        try:
            names = get_pem_names(fullchain)
            # Also check wildcard match (e.g. *.example.com covers sub.example.com)
            parts = domain.split('.')
            wildcard = f'*.{".".join(parts[1:])}' if len(parts) > 2 else None
            if domain in names or (wildcard and wildcard in names):
                log(f"Matched cert dir: {candidate} (names: {', '.join(sorted(names))})")
                return candidate
        except Exception as e:
            log(f"WARN: Could not parse {fullchain}: {e}")

    log(f"ERROR: No cert in {live_dir} matches domain '{domain}'. Set CERT_PATH explicitly.")
    sys.exit(1)


def read_cert_files(cert_path: str):
    """Read cert files and return (fullchain, chain, privkey) or raise."""
    fullchain_path = os.path.join(cert_path, 'fullchain.pem')
    chain_path = os.path.join(cert_path, 'chain.pem')
    privkey_path = os.path.join(cert_path, 'privkey.pem')

    with open(fullchain_path, 'r') as f:
        fullchain = f.read()
    with open(chain_path, 'r') as f:
        chain = f.read()
    with open(privkey_path, 'r') as f:
        privkey = f.read()

    return fullchain, chain, privkey


def get_cert_hash(cert_path: str) -> str:
    """Return SHA256 hash of fullchain.pem + privkey.pem content."""
    fullchain, _, privkey = read_cert_files(cert_path)
    h = hashlib.sha256()
    h.update(fullchain.encode())
    h.update(privkey.encode())
    return h.hexdigest()


def upload_certificate(client, cert_path: str):
    """Upload current cert files as a new version in OCI."""
    fullchain, chain, privkey = read_cert_files(cert_path)

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

    cert_path = find_cert_path(client)
    log(f"Cert path: {cert_path}")

    # Get baseline hash
    try:
        current_hash = get_cert_hash(cert_path)
        log(f"Baseline cert hash: {current_hash[:12]}...")
        # Upload on first run to ensure OCI is in sync
        log("Uploading cert on startup to ensure OCI is in sync...")
        upload_certificate(client, cert_path)
    except Exception as e:
        log(f"ERROR: Failed on startup: {e}")
        sys.exit(1)

    while True:
        try:
            time.sleep(CHECK_INTERVAL)
            new_hash = get_cert_hash(cert_path)
            if new_hash != current_hash:
                log(f"Cert change detected (hash: {new_hash[:12]}...). Uploading to OCI...")
                upload_certificate(client, cert_path)
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
