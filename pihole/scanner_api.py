#!/usr/bin/env python3
"""
Pi-hole dynamic hostname sync using Pi-hole /api/auth session auth (no API_TOKEN required).

Features:
- Ping sweep of LAN_SUBNET
- Reverse DNS, mDNS (avahi-resolve-address), NetBIOS (nbtscan) name resolution
- Auth via /api/auth (session cookie + csrf) or API token fallback
- Add localdns entries and prune stale ones (except PI_HOST_IP)
- DRY_RUN mode for testing
- Subprocess timeouts to avoid hangs
"""

import os
import time
import socket
import requests
import subprocess
import json
import traceback
from ipaddress import ip_network
from datetime import datetime, timedelta

# ---------------------------
# Configuration (env vars)
# ---------------------------
PIHOLE_HOST = os.getenv("PIHOLE_HOST", "pihole.local")
PIHOLE_PORT = os.getenv("PIHOLE_PORT", "80")
PI_PASSWORD = os.getenv("PI_PASSWORD")           # admin password (for /api/auth)
PIHOLE_TOKEN = os.getenv("PIHOLE_TOKEN")         # optional fallback token
LAN_SUBNET = os.getenv("LAN_SUBNET", "192.168.0.0/24")
PI_HOST_IP = os.getenv("PI_HOST_IP")             # Do not prune records pointing to this IP
SCAN_INTERVAL = int(os.getenv("SCAN_INTERVAL", "300"))
DRY_RUN = os.getenv("DRY_RUN", "0") == "1"
PING_TIMEOUT = float(os.getenv("PING_TIMEOUT", "1.0"))   # seconds for per-ping
MDNS_TIMEOUT = int(os.getenv("MDNS_TIMEOUT", "2"))      # seconds for avahi-resolve-address
NBTSCAN_TIMEOUT = int(os.getenv("NBTSCAN_TIMEOUT", "25"))# seconds for nbtscan whole-subnet call

# Construct URLs
BASE = f"http://{PIHOLE_HOST}:{PIHOLE_PORT}"
API_URL = f"{BASE}/api"
AUTH_URL = f"{BASE}/api/auth"

# ---------------------------
# Utilities
# ---------------------------
def log(msg):
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"[{ts}] {msg}", flush=True)

def run_subprocess(cmd, timeout=None):
    """Run subprocess.run with a timeout and return stdout (str) or None on failure."""
    try:
        out = subprocess.check_output(cmd, stderr=subprocess.DEVNULL, timeout=timeout).decode().strip()
        return out
    except subprocess.TimeoutExpired:
        log(f"[!] subprocess timeout: {' '.join(cmd)}")
    except subprocess.CalledProcessError:
        # Command returned non-zero; just return None
        pass
    except FileNotFoundError:
        log(f"[!] command not found: {cmd[0]}")
    return None

# ---------------------------
# Network discovery methods
# ---------------------------
def ping_host(ip):
    """Ping host once. Returns True if reachable."""
    try:
        res = subprocess.run(
            ["ping", "-c", "1", "-W", str(int(PING_TIMEOUT)), ip],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=PING_TIMEOUT + 1
        )
        return res.returncode == 0
    except Exception:
        return False

def scan_network(subnet):
    """Scan subnet sequentially with ping; returns list of alive IPs (strings)."""
    net = ip_network(subnet)
    alive = []
    log(f"[i] Performing ping sweep of {subnet}")
    for ip in net.hosts():
        ipstr = str(ip)
        # skip network/broadcast automatically by ip_network.hosts()
        if ping_host(ipstr):
            alive.append(ipstr)
    log(f"[i] Ping sweep found {len(alive)} alive hosts")
    return alive

def resolve_reverse(ip):
    """Reverse DNS (PTR)."""
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return None

def resolve_mdns(ip):
    """Use avahi-resolve-address (returns 'name' on success)."""
    out = run_subprocess(["avahi-resolve-address", ip], timeout=MDNS_TIMEOUT)
    if out and " " in out:
        parts = out.split(None, 1)
        if len(parts) == 2:
            return parts[1]
    return None

def resolve_netbios_from_nbtscan_output(nbtscan_out):
    """Parse nbtscan output for ip -> name mapping. nbtscan prints lines like:
       192.168.0.124:LIAM-LATITUDE35:<server>:...
    """
    mapping = {}
    if not nbtscan_out:
        return mapping
    for line in nbtscan_out.splitlines():
        line = line.strip()
        if not line or line.startswith("Trying") or ":" not in line:
            continue
        # Some lines are "192.168.0.255   Sendto failed: Permission denied" - handle gracefully
        if "Sendto failed" in line:
            continue
        parts = line.split(":")
        if len(parts) >= 2:
            ip = parts[0].strip()
            name = parts[1].strip()
            if ip and name:
                mapping[ip] = name
    return mapping

def run_nbtscan(subnet):
    """Run nbtscan for the whole subnet once (faster than per-IP nbtscan)."""
    log(f"[i] Running nbtscan for {subnet} (timeout {NBTSCAN_TIMEOUT}s)")
    out = run_subprocess(["nbtscan", "-s:", subnet], timeout=NBTSCAN_TIMEOUT)
    return resolve_netbios_from_nbtscan_output(out)

# ---------------------------
# Pi-hole API helpers
# ---------------------------
class PiHoleAPI:
    def __init__(self):
        self.session = requests.Session()
        self.csrf = None
        self.token = PIHOLE_TOKEN
        if not self.token:
            if not PI_PASSWORD:
                log("[!] Need PI_PASSWORD or PIHOLE_TOKEN. Exiting.")
                raise SystemExit(1)
            self._auth_with_password()
        else:
            log("[i] Using PIHOLE_TOKEN auth")

    def _auth_with_password(self):
        """Authenticate using POST /api/auth to receive session cookie and csrf token."""
        try:
            r = self.session.post(AUTH_URL, json={"password": PI_PASSWORD}, timeout=10)
            r.raise_for_status()
            j = r.json()
            self.csrf = j.get("session", {}).get("csrf")
            # session cookie stored automatically in requests.Session
            log(f"[i] Authenticated to Pi-hole via /api/auth. CSRF present: {bool(self.csrf)}")
        except Exception as e:
            log(f"[!] Failed to authenticate to Pi-hole via {AUTH_URL}: {e}")
            raise

    def _auth_params(self):
        if self.token:
            return {"auth": self.token}
        return {}

    def _auth_headers(self, extra=None):
        headers = {}
        if self.csrf:
            headers["X-CSRF-Token"] = self.csrf
        if extra:
            headers.update(extra)
        return headers

    def list_localdns(self):
        params = {"list": "localdns"}
        params.update(self._auth_params())
        try:
            r = self.session.get(API_URL, params=params, timeout=10)
            r.raise_for_status()
            return r.json().get("data", [])
        except Exception as e:
            log(f"[!] list_localdns failed: {getattr(e, 'response', repr(e))}")
            # Try to show response content if available
            try:
                if hasattr(e, "response") and e.response is not None:
                    log(f"[!] Response: {e.response.status_code} {e.response.text[:200]}")
            except Exception:
                pass
            return []

    def add_localdns(self, ip, domain):
        params = {"list": "localdns", "add": "A", "domain": domain, "ip": ip}
        params.update(self._auth_params())
        if DRY_RUN:
            log(f"[DRY RUN] Would add {domain} -> {ip}")
            return True
        try:
            r = self.session.get(API_URL, params=params, headers=self._auth_headers(), timeout=10)
            r.raise_for_status()
            log(f"[+] Added {domain} -> {ip}")
            return True
        except Exception as e:
            log(f"[!] add_localdns failed for {domain}: {getattr(e, 'response', repr(e))}")
            return False

    def delete_localdns_by_id(self, rid):
        params = {"list": "localdns", "delete": rid}
        params.update(self._auth_params())
        if DRY_RUN:
            log(f"[DRY RUN] Would delete record id {rid}")
            return True
        try:
            r = self.session.get(API_URL, params=params, headers=self._auth_headers(), timeout=10)
            r.raise_for_status()
            log(f"[-] Deleted record id {rid}")
            return True
        except Exception as e:
            log(f"[!] delete_localdns failed for id {rid}: {getattr(e, 'response', repr(e))}")
            return False

# ---------------------------
# Main scan + sync
# ---------------------------
def run_scan():
    api = run_scan.api  # store api object on function attribute to persist session across runs
    # 1) Discover alive IPs via ping sweep
    active_ips = set(scan_network(LAN_SUBNET))

    # 2) NetBIOS scan once (nbtscan covers whole subnet) to speed lookups
    nbtscan_map = run_nbtscan(LAN_SUBNET)

    # 3) Try to resolve hostnames for each active IP using multiple methods
    found = {}  # ip -> hostname
    for ip in active_ips:
        name = None
        # Reverse DNS
        name = resolve_reverse(ip)
        if name:
            found[ip] = name.rstrip(".")
            continue
        # NetBIOS (from aggregated nbtscan)
        nbname = nbtscan_map.get(ip)
        if nbname:
            found[ip] = nbname.rstrip(".")
            continue
        # mDNS
        mdname = resolve_mdns(ip)
        if mdname:
            found[ip] = mdname.rstrip(".")
            continue
        # If none found, skip (we won't create a record with no hostname)
    log(f"[i] Resolved {len(found)} hostnames out of {len(active_ips)} alive hosts")

    # 4) Fetch existing Pi-hole localdns records
    existing = api.list_localdns()   # list of dicts {id, domain, ip}
    existing_map = {e["domain"]: e for e in existing}

    # 5) Add or replace records
    for ip, hostname in found.items():
        # Ensure hostname is a single label or fqdn — leave as provided
        domain = hostname
        if domain in existing_map:
            if existing_map[domain]["ip"] == ip:
                # up-to-date
                continue
            else:
                # domain exists but IP changed: delete old then add new
                rid = existing_map[domain]["id"]
                log(f"[!] {domain} exists with different IP {existing_map[domain]['ip']} -> replacing with {ip}")
                api.delete_localdns_by_id(rid)
                time.sleep(0.3)
                api.add_localdns(ip, domain)
        else:
            api.add_localdns(ip, domain)

    # 6) Prune stale records (remove records whose IP not in active_ips and not PI_HOST_IP)
    # existing is the list of dicts from earlier — refresh it for safe deletes
    existing_after = api.list_localdns()
    for rec in existing_after:
        rid = rec.get("id")
        domain = rec.get("domain")
        ip = rec.get("ip")
        if not rid or not domain or not ip:
            continue
        if ip == PI_HOST_IP:
            continue
        if ip not in active_ips:
            api.delete_localdns_by_id(rid)

# attach api object to run_scan to preserve session across invocations
def init_api_once():
    if getattr(run_scan, "api", None) is None:
        run_scan.api = PiHoleAPI()
init_api_once()

# ---------------------------
# Main loop (robust)
# ---------------------------
if __name__ == "__main__":
    log("[*] Starting Pi-hole hostname scanner (session auth mode)")
    # Basic validation
    if not PIHOLE_HOST or not PI_HOST_IP:
        log("[!] PIHOLE_HOST and PI_HOST_IP must be set. Exiting.")
        raise SystemExit(1)

    while True:
        start_time = datetime.now()
        try:
            log(f"[+] Beginning new scan at {start_time.strftime('%Y-%m-%d %H:%M:%S')}")
            run_scan()
            log("[✓] Scan completed successfully.")
        except Exception as e:
            log(f"[!] Exception during run_scan: {e}")
            traceback.print_exc()
        finally:
            next_scan = datetime.now() + timedelta(seconds=int(SCAN_INTERVAL))
            log(f"[~] Sleeping {SCAN_INTERVAL}s... next scan at {next_scan.strftime('%H:%M:%S')}")
            time.sleep(int(SCAN_INTERVAL))
