# OCI Certificate Updater — Design

**Date:** 2026-03-10

## Overview

A Dockerised Python service that watches for certificate renewals by Nginx Proxy Manager (NPM) and uploads the updated certificate to OCI Certificates Service as a new version. The OCI certificate is a standalone imported certificate referenced by an OCI Load Balancer.

## Context

- NPM runs on `ljfcloud-server` and manages a Let's Encrypt certificate for `james-fagg.uk` (with wildcard SAN subdomains), stored as `npm-2` in the letsencrypt volume.
- The OCI Certificates Service holds an imported certificate (identified by `OCI_CERT_ID`) that must be kept in sync with the NPM-managed cert.
- The existing `dynamic-ip-updater` service establishes the pattern: Python script + Dockerfile + compose + GitHub workflow deploying via Portainer over WireGuard VPN.

## Architecture

Single container running a continuous polling loop:

```
[NPM container] --writes certs--> [nginx_letsencrypt named volume]
[cert-updater container] --reads certs (read-only)--> [nginx_letsencrypt named volume]
                         --calls API--> [OCI Certificates Service]
                                              |
                                        [OCI Load Balancer]
```

## nginx-compose.yml Change

Replace the existing bind mount with a named volume so both containers can share it cleanly:

```yaml
# Before
- ./letsencrypt:/etc/letsencrypt

# After
- nginx_letsencrypt:/etc/letsencrypt
```

Add `nginx_letsencrypt` to the `volumes:` block. NPM will re-issue the cert on next deploy.

**Side effect:** Existing certs in the host bind mount path (`/data/compose/39/letsencrypt`) are abandoned. NPM will re-issue the cert automatically.

## New Files

```
oci-cert-updater/
  Dockerfile
  update_certificate.py
  oci-cert-updater-compose.yml
.github/workflows/
  oci-cert-updater-deploy.yml
```

## Python Script (`update_certificate.py`)

**Approach:** SHA256 hash polling (same pattern as `update_security_list.py`).

**Logic:**
1. On startup, hash `fullchain.pem` + `privkey.pem` from `CERT_PATH` and store as baseline.
2. Loop every `CHECK_INTERVAL` seconds.
3. Re-hash the files; if hash differs from stored hash, call `CertificatesManagementClient.create_certificate_version()` with the new PEM content.
4. Update stored hash and log the result.

**OCI API:** `oci.certificates_management.CertificatesManagementClient.create_certificate_version()`

## Environment Variables

| Variable | Default | Description |
|---|---|---|
| `CERT_PATH` | `/etc/letsencrypt/live/npm-2` | Path to the cert directory inside the container |
| `OCI_CERT_ID` | required | OCID of the certificate in OCI Certificates Service |
| `CHECK_INTERVAL` | `3600` | Polling interval in seconds |
| `OCI_USER` | required | OCI user OCID |
| `OCI_FINGERPRINT` | required | OCI API key fingerprint |
| `OCI_TENANCY` | required | OCI tenancy OCID |
| `OCI_REGION` | `uk-london-1` | OCI region |
| `OCI_KEY_CONTENT_BASE64` | required | Base64-encoded OCI private key |

## Compose (`oci-cert-updater-compose.yml`)

- Image: `ghcr.io/liamj-f/oci-cert-updater:latest`
- Volume: `nginx_letsencrypt:/etc/letsencrypt:ro` (external, owned by nginx stack)
- Same logging config as `dynamic-ip-updater` (json-file, 10m/3 files)

## Dockerfile

- Base: `python:3.11-slim`
- Install: `oci` SDK (`pip install oci`)
- Copy and run `update_certificate.py`
- Same pattern as `dynamic-ip-updater/Dockerfile`

## GitHub Workflow (`oci-cert-updater-deploy.yml`)

Same structure as `OCI-dynamic-ip-updater-deploy.yml`:

- **Triggers:** push to `oci-cert-updater/**` or the workflow file itself; `workflow_dispatch`; `workflow_call`
- **Job 1 — build-image-and-push:** checkout → login to GHCR → extract metadata → build and push to `ghcr.io/liamj-f/oci-cert-updater`
- **Job 2 — deploy:** WireGuard VPN up → auth to Portainer → get/create stack on `ljfcloud-server` → WireGuard VPN down
- Stack name: `oci-cert-updater`
- Compose file: `oci-cert-updater/oci-cert-updater-compose.yml`
- Env vars passed: all OCI credentials + `OCI_CERT_ID` (from GitHub vars/secrets)

## GitHub Secrets/Vars Required

New entries needed (reuse existing OCI secrets where possible):
- `vars.OCI_CERT_ID` — OCID of the OCI certificate
- Existing: `NETWORKUPDATERSA_API_KEY`, `vars.OCID_NETWORK_UPDATER_SA_USER`, `vars.OCID_NETWORK_UPDATER_SA_FINGERPRINT`, `vars.OCID_TENANT`
