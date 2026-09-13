#!/usr/bin/env python3

import os
import sys
import time
import hashlib
import base64
import argparse
import oci
from datetime import datetime, timedelta
from cryptography import x509
from cryptography.hazmat.backends import default_backend


# Configuration
OCI_CERT_ID = os.getenv('OCI_CERT_ID')
CHECK_INTERVAL = int(os.getenv('CHECK_INTERVAL', '3600'))
CERT_PATH_OVERRIDE = os.getenv('CERT_PATH')  # optional explicit override
KEEP_VERSIONS = int(os.getenv('KEEP_VERSIONS', '5'))  # previous versions kept, in addition to CURRENT

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


def parse_args():
    parser = argparse.ArgumentParser(description="Upload renewed certs to OCI and prune old versions.")
    parser.add_argument('--prune-only', action='store_true',
                         help="Only prune old certificate versions and exit; do not upload.")
    parser.add_argument('--dry-run', action='store_true',
                         help="Log what would happen without making changes in OCI.")
    parser.add_argument('--keep-versions', type=int, default=KEEP_VERSIONS,
                         help="Previous versions to keep in addition to CURRENT (default: %(default)s).")
    return parser.parse_args()


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
    """Return SHA256 hash of fullchain.pem content (cert+key are renewed together by certbot,
    so cert content alone is enough to detect a renewal, and it's directly comparable to
    get_current_oci_hash())."""
    fullchain, _, _ = read_cert_files(cert_path)
    h = hashlib.sha256()
    h.update(fullchain.encode())
    return h.hexdigest()


def get_current_oci_hash(certs_client) -> str | None:
    """SHA256 of the fullchain PEM currently CURRENT in OCI, or None if it can't be determined."""
    try:
        bundle = certs_client.get_certificate_bundle(certificate_id=OCI_CERT_ID).data
        h = hashlib.sha256()
        h.update(bundle.certificate_pem.encode())
        return h.hexdigest()
    except Exception as e:
        log(f"WARN: Could not fetch current OCI cert bundle for comparison: {e}")
        return None


def upload_certificate(client, cert_path: str, dry_run: bool = False):
    """Upload current cert files as a new version in OCI."""
    fullchain, chain, privkey = read_cert_files(cert_path)

    if dry_run:
        log("DRY RUN: would upload new certificate version to OCI.")
        return

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


def prune_old_versions(client, keep: int = KEEP_VERSIONS, dry_run: bool = False):
    """Schedule deletion of certificate versions beyond CURRENT + the `keep` most recent previous ones.

    Never touches the CURRENT version or a version already pending deletion. A version's actual
    removal is deferred by OCI to a future time_of_deletion — this only starts that clock.
    """
    try:
        versions = oci.pagination.list_call_get_all_results(
            client.list_certificate_versions,
            OCI_CERT_ID,
            sort_by="VERSION_NUMBER",
            sort_order="DESC",
        ).data
    except Exception as e:
        log(f"ERROR: Failed to list certificate versions: {e}")
        return

    def is_current(v):
        return "CURRENT" in (v.stages or [])

    def already_scheduled(v):
        return getattr(v, 'time_of_deletion', None) is not None

    eligible = [v for v in versions if not is_current(v) and not already_scheduled(v)]
    to_keep, to_remove = eligible[:keep], eligible[keep:]

    log(f"Certificate versions: {len(versions)} total, {len(eligible)} eligible for pruning, "
        f"keeping {len(to_keep)}, pruning {len(to_remove)}")

    for v in to_remove:
        if dry_run:
            log(f"  - DRY RUN: would schedule deletion of version {v.version_number} "
                f"(created {v.time_created})")
            continue
        try:
            client.schedule_certificate_version_deletion(
                OCI_CERT_ID,
                v.version_number,
                oci.certificates_management.models.ScheduleCertificateVersionDeletionDetails(
                    time_of_deletion=datetime.utcnow() + timedelta(days=1),  # OCI-enforced minimum window
                ),
            )
            log(f"  - Scheduled deletion of version {v.version_number} (created {v.time_created})")
        except Exception as e:
            log(f"WARN: Failed to schedule deletion for version {v.version_number}: {e}")
            # keep going — one bad version must not block pruning the rest


def main():
    args = parse_args()

    log("=== OCI Certificate Updater Starting ===")
    log(f"OCI Cert ID: {OCI_CERT_ID}")
    log(f"Check interval: {CHECK_INTERVAL}s")
    log(f"Keep versions (previous, excl. CURRENT): {args.keep_versions}")
    log(f"Region: {config['region']}")
    if args.dry_run:
        log("DRY RUN — no changes will be made in OCI.")

    if not OCI_CERT_ID:
        log("ERROR: OCI_CERT_ID not set!")
        sys.exit(1)

    if not all([config['user'], config['fingerprint'], config['tenancy'], config['key_content']]):
        log("ERROR: OCI credentials not properly configured!")
        sys.exit(1)

    try:
        client = oci.certificates_management.CertificatesManagementClient(config)
        certs_client = oci.certificates.CertificatesClient(config)
        log("OCI clients initialised successfully.")
    except Exception as e:
        log(f"ERROR: Failed to initialise OCI client: {e}")
        sys.exit(1)

    if args.prune_only:
        log("--prune-only: pruning old certificate versions and exiting (no upload attempted).")
        prune_old_versions(client, keep=args.keep_versions, dry_run=args.dry_run)
        return

    cert_path = find_cert_path(client)
    log(f"Cert path: {cert_path}")

    try:
        current_hash = get_cert_hash(cert_path)
        log(f"Local cert hash: {current_hash[:12]}...")
        oci_hash = get_current_oci_hash(certs_client)
        if oci_hash is None or oci_hash != current_hash:
            log("Local cert differs from (or unknown vs) OCI CURRENT version — uploading...")
            upload_certificate(client, cert_path, dry_run=args.dry_run)
            prune_old_versions(client, keep=args.keep_versions, dry_run=args.dry_run)
        else:
            log("Local cert matches OCI CURRENT version — skipping startup upload.")
    except Exception as e:
        log(f"ERROR: Failed on startup: {e}")
        sys.exit(1)

    while True:
        try:
            time.sleep(CHECK_INTERVAL)
            new_hash = get_cert_hash(cert_path)
            if new_hash != current_hash:
                log(f"Cert change detected (hash: {new_hash[:12]}...). Uploading to OCI...")
                upload_certificate(client, cert_path, dry_run=args.dry_run)
                prune_old_versions(client, keep=args.keep_versions, dry_run=args.dry_run)
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
