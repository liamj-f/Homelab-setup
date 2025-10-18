#!/usr/bin/env python3
"""
Aggressive Pi-hole hostname sync scanner.

- Parallel host discovery: ARP, parallel ICMP, parallel TCP (multiple ports)
- Name resolution: reverse DNS, nbtscan (NetBIOS), mDNS
- Updates Pi-hole via PUT /admin/api/config/hosts/<hostname>
- Prunes stale hosts via GET /admin/api/config/hosts and DELETE /admin/api/config/hosts/<hostname>
- Authenticates with POST /api/auth (session + csrf)
- DRY_RUN supported
- Logs request URLs and responses for debugging
"""

import os
import time
import socket
import requests
import subprocess
import traceback
from concurrent.futures import ThreadPoolExecutor, as_completed
from ipaddress import ip_network
from datetime import datetime, timedelta

# ---------------------------
# Config via ENV
# ---------------------------
PIHOLE_HOST = os.getenv("PIHOLE_HOST", "pihole.local")
PIHOLE_PORT = os.getenv("PIHOLE_PORT", "80")
PI_PASSWORD = os.getenv("PI_PASSWORD")          # required for session auth
LAN_SUBNET = os.getenv("LAN_SUBNET", "192.168.0.0/24")
PI_HOST_IP = os.getenv("PI_HOST_IP")            # keep this IP (don't prune)
SCAN_INTERVAL = int(os.getenv("SCAN_INTERVAL", "300"))
DRY_RUN = os.getenv("DRY_RUN", "0") == "1"
# parallelism and timeouts
MAX_WORKERS = int(os.getenv("MAX_WORKERS", "150"))
PING_TIMEOUT = float(os.getenv("PING_TIMEOUT", "0.6"))
TCP_TIMEOUT = float(os.getenv("TCP_TIMEOUT", "0.35"))
NBTSCAN_TIMEOUT = int(os.getenv("NBTSCAN_TIMEOUT", "15"))
MDNS_TIMEOUT = int(os.getenv("MDNS_TIMEOUT", "1"))

# TCP ports to probe (common ports that indicate a live host)
TCP_PORTS = [80, 443, 22, 53, 8080]

BASE = f"http://{PIHOLE_HOST}:{PIHOLE_PORT}"
AUTH_URL = f"{BASE}/api/auth"
CONFIG_HOSTS_URL = f"{BASE}/api/config/hosts"   # GET/PUT/DELETE endpoints

# ---------------------------
# Logging helper
# ---------------------------
def log(msg):
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"[{ts}] {msg}", flush=True)

# ---------------------------
# Safe subprocess runner
# ---------------------------
def run_subprocess(cmd, timeout=None):
    try:
        out = subprocess.check_output(cmd, stderr=subprocess.DEVNULL, timeout=timeout).decode().strip()
        return out
    except subprocess.TimeoutExpired:
        log(f"[!] subprocess timeout: {' '.join(cmd)}")
    except subprocess.CalledProcessError:
        pass
    except FileNotFoundError:
        log(f"[!] command not found: {cmd[0]}")
    return None

# ---------------------------
# Discovery methods
# ---------------------------
def read_arp_table():
    """Attempt to read ARP table via 'ip neigh' or /proc/net/arp"""
    # Try ip neigh
    out = run_subprocess(["ip", "neigh"], timeout=2)
    ips = set()
    if out:
        for line in out.splitlines():
            parts = line.split()
            if len(parts) >= 1:
                ip = parts[0]
                if ip and ip != "": 
                    # only include reachable / incomplete? include all entries
                    ips.add(ip)
    else:
        # fallback to /proc/net/arp
        try:
            with open("/proc/net/arp", "r") as f:
                next(f)  # skip header
                for l in f:
                    cols = l.split()
                    if len(cols) >= 1:
                        ips.add(cols[0])
        except Exception:
            pass
    log(f"[i] ARP table contributed {len(ips)} IPs")
    return ips

def ping_one(ip):
    """Ping once, quick timeout. Returns True if alive."""
    try:
        res = subprocess.run(["ping", "-c", "1", "-W", str(int(PING_TIMEOUT)), ip],
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                              timeout=PING_TIMEOUT+0.5)
        return res.returncode == 0
    except Exception:
        return False

def tcp_probe(ip, port):
    """Try TCP connect; quick timeout."""
    try:
        with socket.create_connection((ip, port), timeout=TCP_TIMEOUT) as s:
            return True
    except Exception:
        return False

def parallel_scan_hosts(subnet):
    """
    Aggressively detect live hosts:
    - seed with ARP entries
    - parallel TCP probes across ports
    - parallel ICMP pings to remaining addresses
    Returns a set of alive IPs.
    """
    network = ip_network(subnet)
    all_hosts = [str(ip) for ip in network.hosts()]
    alive = set()

    # 1) Add from ARP (fast)
    arp_ips = read_arp_table()
    for ip in arp_ips:
        if ip in all_hosts:
            alive.add(ip)

    # 2) Parallel TCP probes (fast and finds hosts ignoring ICMP)
    log(f"[i] Starting parallel TCP probes ({len(all_hosts)} targets, ports {TCP_PORTS})")
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as ex:
        futures = {}
        for ip in all_hosts:
            # skip if already discovered by ARP
            if ip in alive:
                continue
            # schedule a single aggregated future that probes multiple ports (returns True on first success)
            futures[ex.submit(tcp_probe_any, ip)] = ip
        for fut in as_completed(futures):
            ip = futures[fut]
            try:
                ok = fut.result()
                if ok:
                    alive.add(ip)
            except Exception:
                pass
    log(f"[i] After TCP probes: {len(alive)} alive (including ARP)")

    # 3) For remaining unknowns, parallel ICMP ping (cheaper than serial)
    remaining = [ip for ip in all_hosts if ip not in alive]
    if remaining:
        log(f"[i] Starting parallel ICMP on {len(remaining)} addresses")
        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as ex:
            futures = {ex.submit(ping_one, ip): ip for ip in remaining}
            for fut in as_completed(futures):
                ip = futures[fut]
                try:
                    if fut.result():
                        alive.add(ip)
                except Exception:
                    pass
    log(f"[i] Total alive: {len(alive)}")
    return alive

def tcp_probe_any(ip):
    """Try the list of common ports for a single IP (returns True early)."""
    for p in TCP_PORTS:
        if tcp_probe(ip, p):
            return True
    return False

# ---------------------------
# Name resolution
# ---------------------------
def resolve_reverse(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return None

def resolve_mdns(ip):
    out = run_subprocess(["avahi-resolve-address", ip], timeout=MDNS_TIMEOUT)
    if out and " " in out:
        return out.split(None, 1)[1]
    return None

def run_nbtscan_map(subnet):
    out = run_subprocess(["nbtscan", "-s:", subnet], timeout=NBTSCAN_TIMEOUT)
    mapping = {}
    if not out:
        return mapping
    for line in out.splitlines():
        if "Sendto failed" in line or ":" not in line:
            continue
        parts = line.split(":")
        if len(parts) >= 2:
            ip = parts[0].strip()
            name = parts[1].strip()
            if ip and name:
                mapping[ip] = name
    return mapping

# ---------------------------
# Pi-hole API helpers (PUT/DELETE & list)
# ---------------------------
class PiHoleAPI:
    def __init__(self):
        self.session = requests.Session()
        self.csrf = None
        self._auth()

    def _auth(self):
        if not PI_PASSWORD:
            log("[!] PI_PASSWORD must be set for session auth")
            raise SystemExit(1)
        try:
            r = self.session.post(AUTH_URL, json={"password": PI_PASSWORD}, timeout=10)
            r.raise_for_status()
            j = r.json()
            self.csrf = j.get("session", {}).get("csrf")
            log(f"[i] Authenticated to Pi-hole via /api/auth. CSRF present: {bool(self.csrf)}")
        except Exception as e:
            log(f"[!] Auth failed: {e}")
            raise

    def _headers(self):
        h = {}
        if self.csrf:
            h["X-CSRF-Token"] = self.csrf
        return h

    def put_host(self, hostname, ip):
        url = f"{CONFIG_HOSTS_URL}/{hostname}"
        data = {"ip": ip}
        log(f"[DEBUG] PUT URL: {url} Body: {data}")
        if DRY_RUN:
            log(f"[DRY RUN] Would PUT {hostname} -> {ip}")
            return False
        try:
            r = self.session.put(url, json=data, headers=self._headers(), timeout=10)
            log(f"[DEBUG] PUT resp: {r.status_code} {r.text[:400]}")
            r.raise_for_status()
            log(f"[+] PUT {hostname} -> {ip}")
            return True
        except Exception as e:
            log(f"[!] PUT failed for {hostname}: {e}")
            try:
                if hasattr(e, "response") and e.response is not None:
                    log(f"[DEBUG] Response: {e.response.status_code} {e.response.text[:400]}")
            except Exception:
                pass
            return False

    def delete_host(self, hostname):
        url = f"{CONFIG_HOSTS_URL}/{hostname}"
        log(f"[DEBUG] DELETE URL: {url}")
        if DRY_RUN:
            log(f"[DRY RUN] Would DELETE {hostname}")
            return False
        try:
            r = self.session.delete(url, headers=self._headers(), timeout=10)
            log(f"[DEBUG] DELETE resp: {r.status_code} {r.text[:400]}")
            r.raise_for_status()
            log(f"[-] DELETE {hostname}")
            return True
        except Exception as e:
            log(f"[!] DELETE failed for {hostname}: {e}")
            try:
                if hasattr(e, "response") and e.response is not None:
                    log(f"[DEBUG] Response: {e.response.status_code} {e.response.text[:400]}")
            except Exception:
                pass
            return False

    def list_hosts(self):
        """Try GET /admin/api/config/hosts — may return JSON list of hosts (depends on Pi-hole)."""
        try:
            url = CONFIG_HOSTS_URL
            log(f"[DEBUG] GET URL: {url}")
            r = self.session.get(url, headers=self._headers(), timeout=10)
            log(f"[DEBUG] GET resp: {r.status_code} {r.text[:400]}")
            if r.ok:
                return r.json().get("data", []) if isinstance(r.json(), dict) and "data" in r.json() else r.json()
        except Exception as e:
            log(f"[!] list_hosts failed: {e}")
        return []

# ---------------------------
# High-level scan & sync
# ---------------------------
def sync_to_pihole(api, active_ips):
    # Resolve hostnames
    nbmap = run_nbtscan_map(LAN_SUBNET)
    resolved = {}   # ip -> fqdn/hostname
    # do resolution in parallel for speed
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as ex:
        futures = {}
        for ip in active_ips:
            futures[ex.submit(resolve_name_for_ip, ip, nbmap)] = ip
        for fut in as_completed(futures):
            ip = futures[fut]
            try:
                name = fut.result()
                if name:
                    resolved[ip] = name.rstrip(".")
            except Exception:
                pass

    log(f"[i] Resolved {len(resolved)} hostnames out of {len(active_ips)} alive hosts")

    # Fetch existing hosts for pruning
    existing = api.list_hosts()
    # Normalize existing into domain -> ip map if possible
    existing_map = {}
    if isinstance(existing, list):
        for item in existing:
            # item may be dict with fields or simple mapping; try different shapes
            if isinstance(item, dict):
                # typical entry may be { "hostname": "...", "ip": "1.2.3.4" } or {"domain":..., "ip":...}
                domain = item.get("hostname") or item.get("domain") or item.get("name")
                ip = item.get("ip")
                if domain and ip:
                    existing_map[domain] = ip
            elif isinstance(item, str) and ":" in item:
                # sometimes returns "domain:ip"
                try:
                    d, ip = item.split(":", 1)
                    existing_map[d] = ip
                except Exception:
                    pass

    # Upsert resolved hostnames
    for ip, hostname in resolved.items():
        # optionally normalize hostname (e.g., ensure .local or .lan) — leaving as discovered
        api.put_host(hostname, ip)

    # Prune stale hosts: delete hosts whose IP not in active_ips and not PI_HOST_IP
    # Only prune if we successfully fetched existing_map
    if existing_map:
        for domain, ip in list(existing_map.items()):
            if ip == PI_HOST_IP:
                continue
            if ip not in active_ips:
                # delete
                api.delete_host(domain)
    else:
        log("[i] Existing hosts listing unavailable; skipping prune phase")

def resolve_name_for_ip(ip, nbmap):
    """Try reverse, netbios, mdns (in that order)"""
    name = resolve_reverse(ip)
    if name:
        return name
    nb = nbmap.get(ip)
    if nb:
        return nb
    md = resolve_mdns(ip)
    if md:
        return md
    return None

# ---------------------------
# Main loop
# ---------------------------
if __name__ == "__main__":
    log("[*] Starting aggressive Pi-hole hostname scanner")
    if not PIHOLE_HOST or not PI_HOST_IP:
        log("[!] PIHOLE_HOST and PI_HOST_IP must be set. Exiting.")
        raise SystemExit(1)

    try:
        api = PiHoleAPI()
    except Exception as e:
        log(f"[!] Failed to init PiHole API: {e}")
        raise

    while True:
        start = datetime.now()
        try:
            log(f"[+] Beginning scan at {start.strftime('%Y-%m-%d %H:%M:%S')}")
            active = parallel_scan_hosts(LAN_SUBNET)
            sync_to_pihole(api, active)
            log("[✓] Scan & sync completed.")
        except Exception as e:
            log(f"[!] Exception during scan: {e}")
            traceback.print_exc()
        finally:
            nxt = datetime.now() + timedelta(seconds=SCAN_INTERVAL)
            log(f"[~] Sleeping {SCAN_INTERVAL}s... next scan at {nxt.strftime('%H:%M:%S')}")
            time.sleep(SCAN_INTERVAL)
