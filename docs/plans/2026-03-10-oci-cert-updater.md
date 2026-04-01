# OCI Certificate Updater Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Build a Dockerised Python service that detects cert renewals by Nginx Proxy Manager and uploads new certificate versions to OCI Certificates Service.

**Architecture:** Continuous polling loop using SHA256 hash comparison to detect cert file changes, then calls `CertificatesManagementClient.update_certificate()` with `UpdateCertificateByImportingConfigDetails`. Shares the `nginx_letsencrypt` named Docker volume (read-only) with NPM.

**Tech Stack:** Python 3.11, `oci` SDK, Docker, GitHub Actions, Portainer GitOps over WireGuard VPN.

**Design doc:** `docs/plans/2026-03-10-oci-cert-updater-design.md`

---

## Task 1: Update nginx-compose.yml to use a named volume

**Files:**
- Modify: `nginx-compose.yml`

**Context:** Currently NPM uses a bind mount `./letsencrypt:/etc/letsencrypt`. Changing to a named volume allows the cert updater to mount the same volume cleanly without hardcoded host paths. Side effect: existing certs in the bind mount are abandoned; NPM will re-issue the cert automatically on next startup.

**Step 1: Edit nginx-compose.yml**

In `nginx-compose.yml`, change the volumes block from:

```yaml
    volumes:
      - nginx_data:/data
      - ./letsencrypt:/etc/letsencrypt
```

to:

```yaml
    volumes:
      - nginx_data:/data
      - nginx_letsencrypt:/etc/letsencrypt
```

Then add `nginx_letsencrypt` to the top-level `volumes:` block:

```yaml
volumes:
  nginx_data:
    name: nginx_data
  nginx_letsencrypt:
    name: nginx_letsencrypt
```

**Step 2: Commit**

```bash
git add nginx-compose.yml
git commit -m "feat: change letsencrypt bind mount to named volume for sharing"
```

---

## Task 2: Create the Python cert updater script

**Files:**
- Create: `oci-cert-updater/update_certificate.py`

**Context:** The OCI Certificates Management SDK method for updating an **imported** certificate is `update_certificate()` with `UpdateCertificateByImportingConfigDetails`. This creates a new version of the certificate in OCI while keeping the same OCID — the Load Balancer reference remains valid.

NPM stores cert files at `CERT_PATH/fullchain.pem`, `CERT_PATH/privkey.pem`, and `CERT_PATH/chain.pem`.

**Step 1: Create `oci-cert-updater/update_certificate.py`**

```python
#!/usr/bin/env python3

import os
import time
import hashlib
import base64
import oci
from datetime import datetime


# Configuration
CERT_PATH = os.getenv('CERT_PATH', '/etc/letsencrypt/live/npm-2')
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
        return

    if not all([config['user'], config['fingerprint'], config['tenancy'], config['key_content']]):
        log("ERROR: OCI credentials not properly configured!")
        return

    try:
        client = oci.certificates_management.CertificatesManagementClient(config)
        log("OCI client initialised successfully.")
    except Exception as e:
        log(f"ERROR: Failed to initialise OCI client: {e}")
        return

    # Get baseline hash
    try:
        current_hash = get_cert_hash()
        log(f"Baseline cert hash: {current_hash[:12]}...")
        # Upload on first run to ensure OCI is in sync
        log("Uploading cert on startup to ensure OCI is in sync...")
        upload_certificate(client)
    except Exception as e:
        log(f"ERROR: Failed on startup: {e}")
        return

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
```

**Step 2: Commit**

```bash
git add oci-cert-updater/update_certificate.py
git commit -m "feat: add OCI cert updater Python script"
```

---

## Task 3: Create the Dockerfile

**Files:**
- Create: `oci-cert-updater/Dockerfile`

**Context:** Same pattern as `dynamic-ip-updater/Dockerfile`. Uses `oci` SDK (lighter than `oci-cli`).

**Step 1: Create `oci-cert-updater/Dockerfile`**

```dockerfile
FROM python:3.11-slim

LABEL maintainer="LJF Cloud"
LABEL description="Uploads renewed NPM certificates to OCI Certificates Service"

RUN pip install --no-cache-dir oci

WORKDIR /app

COPY update_certificate.py /app/

RUN chmod +x /app/update_certificate.py

CMD ["python", "-u", "/app/update_certificate.py"]
```

**Step 2: Commit**

```bash
git add oci-cert-updater/Dockerfile
git commit -m "feat: add OCI cert updater Dockerfile"
```

---

## Task 4: Create the Docker Compose file

**Files:**
- Create: `oci-cert-updater/oci-cert-updater-compose.yml`

**Context:** Mounts `nginx_letsencrypt` as `external: true` (owned and created by the nginx stack). All sensitive values come from env vars injected by Portainer.

**Step 1: Create `oci-cert-updater/oci-cert-updater-compose.yml`**

```yaml
version: '3.8'

services:
  oci-cert-updater:
    image: ghcr.io/liamj-f/oci-cert-updater:latest
    container_name: oci-cert-updater
    restart: unless-stopped
    environment:
      - CERT_PATH=${CERT_PATH:-/etc/letsencrypt/live/npm-2}
      - OCI_CERT_ID=${OCI_CERT_ID}
      - CHECK_INTERVAL=${CHECK_INTERVAL:-3600}
      - OCI_USER=${OCI_USER}
      - OCI_FINGERPRINT=${OCI_FINGERPRINT}
      - OCI_TENANCY=${OCI_TENANCY}
      - OCI_REGION=uk-london-1
      - OCI_KEY_CONTENT_BASE64=${OCI_KEY_CONTENT_BASE64}
    volumes:
      - nginx_letsencrypt:/etc/letsencrypt:ro
    logging:
      driver: "json-file"
      options:
        max-size: "10m"
        max-file: "3"

volumes:
  nginx_letsencrypt:
    name: nginx_letsencrypt
    external: true
```

**Step 2: Commit**

```bash
git add oci-cert-updater/oci-cert-updater-compose.yml
git commit -m "feat: add OCI cert updater compose file"
```

---

## Task 5: Create the GitHub Actions workflow

**Files:**
- Create: `.github/workflows/oci-cert-updater-deploy.yml`

**Context:** Mirrors `OCI-dynamic-ip-updater-deploy.yml` exactly. Job 1 builds and pushes the image to GHCR. Job 2 connects over WireGuard VPN to Portainer on `rpi4-server` and creates/updates the stack on `ljfcloud-server`.

**GitHub vars/secrets needed (check these exist, create if missing):**
- `vars.OCI_CERT_ID` — OCID of the OCI certificate
- Reuse existing: `secrets.NETWORKUPDATERSA_API_KEY`, `vars.OCID_NETWORK_UPDATER_SA_USER`, `vars.OCID_NETWORK_UPDATER_SA_FINGERPRINT`, `vars.OCID_TENANT`

**Step 1: Create `.github/workflows/oci-cert-updater-deploy.yml`**

```yaml
name: Redeploy OCI Cert Updater via Portainer GitOps

on:
  workflow_call:
    inputs:
      host_machine:
        required: true
        type: string
      domain:
        required: true
        type: string
  workflow_dispatch:
    inputs:
      host_machine:
        required: true
        type: string
      domain:
        required: true
        type: string
  push:
    branches:
      - main
      - '**'
    paths:
      - '.github/workflows/oci-cert-updater-deploy.yml'
      - 'oci-cert-updater/**'

jobs:
  build-image-and-push:
    name: Build and push image to ghcr.io
    runs-on: ubuntu-latest
    permissions:
      contents: read
      packages: write
    steps:
      - name: Checkout
        uses: actions/checkout@v4

      - name: Log in to GitHub Container Registry
        uses: docker/login-action@v3
        with:
          registry: ghcr.io
          username: ${{ github.actor }}
          password: ${{ secrets.GITHUB_TOKEN }}

      - name: Extract metadata
        id: meta
        uses: docker/metadata-action@v5
        with:
          images: ghcr.io/liamj-f/oci-cert-updater
          tags: |
            type=sha,prefix=sha-
            type=raw,value=latest

      - name: Build and push
        uses: docker/build-push-action@v6
        with:
          context: ./oci-cert-updater
          push: true
          tags: ${{ steps.meta.outputs.tags }}
          labels: ${{ steps.meta.outputs.labels }}

  deploy:
    needs: build-image-and-push
    runs-on: ubuntu-latest
    env:
      host_machine: ${{ inputs.host_machine || 'ljfcloud-server' }}
    steps:
      - name: Checkout repo
        uses: actions/checkout@v4

      - name: Install WireGuard
        run: |
          sudo apt-get install -y wireguard || (sudo apt-get update && sudo apt-get install -y wireguard)

      - name: Write WireGuard config
        run: |
          echo "${{ secrets.WG_CONFIG }}" > wg0.conf

      - name: Bring up VPN
        run: |
          sudo wg-quick up ./wg0.conf
          sudo wg show

      - name: Override system DNS resolver
        run: |
          sudo rm /etc/resolv.conf
          echo "nameserver 1.1.1.1" | sudo tee /etc/resolv.conf

      - name: Authenticate to Portainer
        id: auth
        run: |
          RESPONSE=$(curl -X POST "http://${{ vars.RPI4_IP }}:83/api/auth" \
            -H "Content-Type: application/json" \
            -d '{
                 "Username":"${{ vars.APP_USER }}",
                 "Password":"${{ secrets.APP_PASSWORD }}"
                 }')
          TOKEN=$(echo "$RESPONSE" | jq -r '.jwt')
          echo "token=$TOKEN" >> $GITHUB_OUTPUT

      - name: Get Portainer EndpointId
        id: endpoint
        run: |
          RESPONSE=$(curl -s -X GET "http://${{ vars.RPI4_IP }}:83/api/endpoints" \
            -H "Authorization: Bearer ${{ steps.auth.outputs.token }}")
          ENDPOINT_ID=$(echo "$RESPONSE" | jq -r --arg host_machine "$host_machine" '.[] | select(.Name==$host_machine) | .Id')
          echo "endpoint_id=$ENDPOINT_ID" >> $GITHUB_OUTPUT

      - name: Get Stack ID (if exists)
        id: get_stack_id
        run: |
          STACKS=$(curl --fail -s -X GET "http://${{ vars.RPI4_IP }}:83/api/stacks" \
          -H "Authorization: Bearer ${{ steps.auth.outputs.token }}" || echo "[]")

          STACK_ID=$(echo "$STACKS" | jq -r '.[] | select(.Name=="oci-cert-updater" and .EndpointId==${{ steps.endpoint.outputs.endpoint_id }}) | .Id')

          if [ -z "$STACK_ID" ] || [ "$STACK_ID" = "null" ]; then
            echo "Stack not found for this endpoint."
            echo "stack_id=0" >> $GITHUB_OUTPUT
          else
            echo "Stack found with ID: $STACK_ID"
            echo "stack_id=$STACK_ID" >> $GITHUB_OUTPUT
          fi

      - name: Generate UUID
        if: ${{ steps.get_stack_id.outputs.stack_id == '0' }}
        id: uuid
        run: |
          echo "uuid=$(uuidgen)" >> $GITHUB_OUTPUT

      - name: Create Stack from GitHub
        if: ${{ steps.get_stack_id.outputs.stack_id == '0' }}
        run: |
          OCI_KEY_BASE64=$(echo "${{ secrets.NETWORKUPDATERSA_API_KEY }}" | base64 -w 0)

          RESPONSE=$(curl -v -s -S -X POST "http://${{ vars.RPI4_IP }}:83/api/stacks/create/standalone/repository?endpointId=${{ steps.endpoint.outputs.endpoint_id }}" \
          -H "Authorization: Bearer ${{ steps.auth.outputs.token }}" \
          -H "Content-Type: application/json" \
          -d '{
               "Name": "oci-cert-updater",
               "RepositoryURL": "https://github.com/liamj-f/homelab-setup",
               "RepositoryReferenceName": "${{ github.ref }}",
               "ComposeFile": "oci-cert-updater/oci-cert-updater-compose.yml",
               "RepositoryAuthentication": false,
               "AutoUpdate": {
                              "forcePullImage": true,
                              "forceUpdate": true,
                              "Webhook": "${{ steps.uuid.outputs.uuid }}"
                             },
               "Env": [
                       {"name":"OCI_USER",        "value":"${{ vars.OCID_NETWORK_UPDATER_SA_USER }}"},
                       {"name":"OCI_FINGERPRINT",  "value":"${{ vars.OCID_NETWORK_UPDATER_SA_FINGERPRINT }}"},
                       {"name":"OCI_TENANCY",      "value":"${{ vars.OCID_TENANT }}"},
                       {"name":"OCI_CERT_ID",      "value":"${{ vars.OCI_CERT_ID }}"},
                       {"name":"OCI_KEY_CONTENT_BASE64", "value":"'"$OCI_KEY_BASE64"'"}
               ],
               "Prune": true,
               "StackFileVersion": "3"
              }')

          echo "API Response: $RESPONSE"

      - name: Update Stack
        if: ${{ steps.get_stack_id.outputs.stack_id != '0' }}
        run: |
          OCI_KEY_BASE64=$(echo "${{ secrets.NETWORKUPDATERSA_API_KEY }}" | base64 -w 0)

          curl -s -X PUT "http://${{ vars.RPI4_IP }}:83/api/stacks/${{ steps.get_stack_id.outputs.stack_id }}/git/redeploy?endpointId=${{ steps.endpoint.outputs.endpoint_id }}" \
          -H "Authorization: Bearer ${{ steps.auth.outputs.token }}" \
          -H "Content-Type: application/json" \
          -d '{
               "PullImage": true,
               "RepositoryReferenceName": "${{ github.ref }}",
               "repositoryAuthentication": false,
               "Env": [
                       {"name":"OCI_USER",        "value":"${{ vars.OCID_NETWORK_UPDATER_SA_USER }}"},
                       {"name":"OCI_FINGERPRINT",  "value":"${{ vars.OCID_NETWORK_UPDATER_SA_FINGERPRINT }}"},
                       {"name":"OCI_TENANCY",      "value":"${{ vars.OCID_TENANT }}"},
                       {"name":"OCI_CERT_ID",      "value":"${{ vars.OCI_CERT_ID }}"},
                       {"name":"OCI_KEY_CONTENT_BASE64", "value":"'"$OCI_KEY_BASE64"'"}
               ],
               "Prune": true
              }'

      - name: Bring down VPN
        run: |
          sudo wg-quick down ./wg0.conf
          sudo wg show
```

**Step 2: Commit**

```bash
git add .github/workflows/oci-cert-updater-deploy.yml
git commit -m "feat: add OCI cert updater GitHub Actions workflow"
```

---

## Task 6: Pre-flight checklist before pushing

Before pushing to main, verify:

1. **GitHub vars/secrets** — ensure `vars.OCI_CERT_ID` exists in the repo settings (Settings → Secrets and variables → Actions → Variables). Value is the OCID of the OCI certificate, e.g. `ocid1.certificate.oc1.uk-london-1.xxxxx`.

2. **nginx stack re-deployed** — after merging, the nginx stack must be redeployed so NPM starts using the `nginx_letsencrypt` named volume. The cert will be re-issued automatically. The `oci-cert-updater` stack will not start successfully until this volume exists.

3. **Deploy order** — nginx stack must be deployed first (creates the `nginx_letsencrypt` volume), then the cert updater stack.

4. **Verify cert path** — once NPM has re-issued the cert, SSH into `ljfcloud-server` and confirm the path:
   ```bash
   sudo docker exec nginx-proxy-manager nginx -T | grep ssl_certificate
   ```
   If the cert is no longer `npm-2` (e.g. it becomes `npm-3`), update `CERT_PATH` in the Portainer stack env vars.

---

## Summary of files created/modified

| Action | File |
|---|---|
| Modified | `nginx-compose.yml` |
| Created | `oci-cert-updater/update_certificate.py` |
| Created | `oci-cert-updater/Dockerfile` |
| Created | `oci-cert-updater/oci-cert-updater-compose.yml` |
| Created | `.github/workflows/oci-cert-updater-deploy.yml` |
