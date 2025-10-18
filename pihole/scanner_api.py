#!/usr/bin/env python3
"""
Aggressive network scanner + Pi-hole hostname sync.

Discovery:
 - ARP table (/proc/net/arp)
 - parallel TCP probes (common ports)
 - parallel ICMP ping fallback
 - nbtscan (NetBIOS)
 - avahi-browse (mDNS)
 - TCP banner sniff (HTTP Server header, SSH banner)
 - OUI vendor fallback (from MAC)

Pi-hole sync:
 - Session auth: POST {API_BASE}/auth -> returns session.sid and session.csrf
 - For each discovered ip/hostname: PUT {API_BASE}/config/dns/hosts/{ip} {hostname}
 - Optional prune: GET {API_BASE}/config -> config.dns.hosts -> delete entries not current

Configuration via environment variables:
 - LAN_SUBNET (default 192.168.0.0/24)
 - PIHOLE_HOST (required)
 - PIHOLE_PORT (default 82)
 - PI_PASSWORD (required for session auth)
 - PI_HOST_IP (do not prune)
 - SCAN_INTERVAL (seconds, default 300)
 - DRY_RUN (1 = true)
 - MAX_WORKERS, PING_TIMEOUT, TCP_TIMEOUT, NBTSCAN_TIMEOUT, MDNS_TIMEOUT
"""

import os
import time
import socket
import requests
import subprocess
import traceback
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from ipaddress import ip_network
from datetime import datetime, timedelta

# -----------------------
# Config (env)
# -----------------------
LAN_SUBNET = os.getenv("LAN_SUBNET", "192.168.0.0/24")
PIHOLE_HOST = os.getenv("PIHOLE_HOST")  # required
PIHOLE_PORT = os.getenv("PIHOLE_PORT", "82")
PI_PASSWORD = os.getenv("PI_PASSWORD")  # required for /api/auth
PI_HOST_IP = os.getenv("PI_HOST_IP", PIHOLE_HOST)
SCAN_INTERVAL = int(os.getenv("SCAN_INTERVAL", "300"))
DRY_RUN = os.getenv("DRY_RUN", "0") == "1"

MAX_WORKERS = int(os.getenv("MAX_WORKERS", "120"))
PING_TIMEOUT = float(os.getenv("PING_TIMEOUT", "0.6"))
TCP_TIMEOUT = float(os.getenv("TCP_TIMEOUT", "0.35"))
NBTSCAN_TIMEOUT = int(os.getenv("NBTSCAN_TIMEOUT", "15"))
MDNS_TIMEOUT = int(os.getenv("MDNS_TIMEOUT", "3"))

TCP_PORTS = [80, 443, 22, 53, 8080]  # ports to probe for TCP banner

API_BASE = f"http://{PIHOLE_HOST}:{PIHOLE_PORT}/api"

# -----------------------
# Helpers
# -----------------------
def now():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def log(msg):
    print(f"[{now()}] {msg}", flush=True)

def run_subproc(cmd, timeout=None):
    try:
        out = subprocess.check_output(cmd, stderr=subprocess.DEVNULL, timeout=timeout).decode(errors="ignore").strip()
        return out
    except subprocess.TimeoutExpired:
        log(f"[!] subprocess timeout: {' '.join(cmd)}")
    except subprocess.CalledProcessError:
        # non-zero exit
        pass
    except FileNotFoundError:
        log(f"[!] command not found: {cmd[0]}")
    return None

# -----------------------
# Discovery
# -----------------------
def read_arp_table():
    """
    Read /proc/net/arp for IP -> MAC entries.
    Returns dict[ip] = mac
    """
    arp = {}
    try:
        with open("/proc/net/arp") as f:
            next(f)  # skip header
            for line in f:
                cols = line.split()
                if len(cols) >= 4:
                    ip = cols[0]
                    mac = cols[3]
                    if mac and mac != "00:00:00:00:00:00":
                        arp[ip] = mac.lower()
    except Exception as e:
        log(f"[!] read_arp_table failed: {e}")
    log(f"[i] ARP table: {len(arp)} entries")
    return arp

def tcp_probe(ip, port, timeout=TCP_TIMEOUT):
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return True
    except Exception:
        return False

def tcp_banner(ip, ports=TCP_PORTS, timeout=TCP_TIMEOUT):
    """
    Try to fetch a banner: SSH banner or HTTP Server header.
    Return short hint or None.
    """
    for port in ports:
        try:
            s = socket.create_connection((ip, port), timeout=timeout)
        except Exception:
            continue
        try:
            if port == 22:
                # SSH banner
                s.settimeout(1.0)
                try:
                    banner = s.recv(256).decode(errors="ignore").strip()
                    s.close()
                    if banner:
                        # return something like "SSH-2.0-OpenSSH_8.4"
                        return banner.splitlines()[0]
                except Exception:
                    s.close()
                    continue
            else:
                # HTTP head
                try:
                    s.sendall(b"HEAD / HTTP/1.0\r\nHost: localhost\r\n\r\n")
                    data = s.recv(2048).decode(errors="ignore")
                    s.close()
                    m = re.search(r"Server:\s*(.+)", data, re.IGNORECASE)
                    if m:
                        return m.group(1).strip().replace("\n", " ").replace("\r", " ")
                except Exception:
                    try:
                        s.close()
                    except Exception:
                        pass
                    continue
        except Exception:
            try:
                s.close()
            except Exception:
                pass
    return None

def parallel_tcp_and_icmp(subnet):
    """
    Aggressive parallel discovery:
      - seed from ARP table
      - parallel TCP probes across ports
      - parallel ICMP for remaining addresses
    Returns set of alive IPs and dict of discovery reasons
    """
    network = ip_network(subnet)
    all_hosts = [str(ip) for ip in network.hosts()]
    alive = set()
    reasons = {}  # ip -> list of reasons

    # 1) seed with ARP
    arp = read_arp_table()
    for ip in arp.keys():
        if ip in all_hosts:
            alive.add(ip)
            reasons.setdefault(ip, []).append("arp")

    # 2) parallel TCP probes (try multiple ports per ip)
    log(f"[i] Starting parallel TCP probes over {len(all_hosts)} addresses")
    def probe_ip(ip):
        # return True if any port open
        for p in TCP_PORTS:
            if tcp_probe(ip, p):
                return p
        return None

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as ex:
        futures = {ex.submit(probe_ip, ip): ip for ip in all_hosts if ip not in alive}
        for fut in as_completed(futures):
            ip = futures[fut]
            try:
                p = fut.result()
                if p:
                    alive.add(ip)
                    reasons.setdefault(ip, []).append(f"tcp:{p}")
            except Exception:
                pass

    # 3) ICMP for remaining
    remaining = [ip for ip in all_hosts if ip not in alive]
    if remaining:
        log(f"[i] Starting parallel ICMP for {len(remaining)} addresses")
        def ping_one(ip):
            try:
                res = subprocess.run(["ping", "-c", "1", "-W", str(int(PING_TIMEOUT)), ip],
                                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                     timeout=PING_TIMEOUT + 0.5)
                return res.returncode == 0
            except Exception:
                return False
        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as ex:
            futures = {ex.submit(ping_one, ip): ip for ip in remaining}
            for fut in as_completed(futures):
                ip = futures[fut]
                try:
                    ok = fut.result()
                    if ok:
                        alive.add(ip)
                        reasons.setdefault(ip, []).append("icmp")
                except Exception:
                    pass

    log(f"[i] Discovery: {len(alive)} alive hosts found")
    return alive, reasons, arp

def run_nbtscan(subnet):
    out = run_subproc(["nbtscan", "-s:", subnet], timeout=NBTSCAN_TIMEOUT)
    mapping = {}
    if out:
        for line in out.splitlines():
            if "Sendto failed" in line or ":" not in line:
                continue
            parts = line.split(":")
            if len(parts) >= 2:
                ip = parts[0].strip()
                name = parts[1].strip()
                if ip and name:
                    mapping[ip] = name
    log(f"[i] nbtscan: {len(mapping)} names")
    return mapping

def run_avahi(subnet=None):
    """
    Use avahi-browse to list mDNS services. Parse IPv4 lines.
    Returns mapping ip -> name.
    """
    out = run_subproc(["avahi-browse", "-alrpt"], timeout=MDNS_TIMEOUT)
    mapping = {}
    if not out:
        return mapping
    # lines like: "+    eth0 IPv4 My-Device _workstation._tcp local"
    # or: "+    eth0 IPv4 192.168.0.10 My-Device _workstation._tcp local"
    for line in out.splitlines():
        line = line.strip()
        # Some avahi output forms: "+   eth0 IPv4 hostname.local 192.168.0.10 ..."
        # We'll capture common patterns: IPv4 <ip> <name> or IPv4 <name> <ip>
        m_ip_first = re.match(r"^\+ .* IPv4 (\d+\.\d+\.\d+\.\d+) (\S+)", line)
        m_name_first = re.match(r"^\+ .* IPv4 (\S+) (\d+\.\d+\.\d+\.\d+)", line)
        if m_ip_first:
            ip = m_ip_first.group(1)
            name = m_ip_first.group(2)
            mapping[ip] = name
        elif m_name_first:
            name = m_name_first.group(1)
            ip = m_name_first.group(2)
            mapping[ip] = name
    log(f"[i] mDNS: {len(mapping)} names")
    return mapping

# -----------------------
# OUI vendor fallback
# -----------------------
def mac_to_vendor(mac):
    # simple vendor hint from OUI (first 3 bytes). Local small map for common vendors
    if not mac:
        return None
    oui = mac.upper().replace(":", "")[:6]
    # minimal built-in map (common consumer vendors). Expand as needed.
    vendors = {
        "B827EB": "RaspberryPi",
        "EC1A4B": "Samsung",
        "F4F5C4": "Apple",
        "D0D3D6": "Sony",
        "001A11": "TP-Link",
        "0013EF": "Amazon",
    }
    return vendors.get(oui, "unknown")

# -----------------------
# Name resolution orchestration
# -----------------------
def resolve_names(alive, arp_map, nbmap, mdmap):
    """
    For each ip in alive set, choose a hostname using precedence:
    mDNS > NetBIOS > TCP banner > OUI vendor fallback > IP fallback
    """
    resolved = {}
    # do banner fetch in parallel
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as ex:
        futures = {ex.submit(tcp_banner, ip): ip for ip in alive}
        banners = {}
        for fut in as_completed(futures):
            ip = futures[fut]
            try:
                banners[ip] = fut.result()
            except Exception:
                banners[ip] = None

    for ip in sorted(alive, key=lambda x: tuple(map(int, x.split(".")))):
        name = None
        if ip in mdmap:
            name = mdmap[ip]
        elif ip in nbmap:
            name = nbmap[ip]
        elif banners.get(ip):
            # sanitize banner to short label
            b = banners[ip]
            # shorten http server names like "Apache/2.4.54 (Raspbian)"
            b = re.sub(r"[^\w\.-]", "_", b)[:48]
            name = b
        elif ip in arp_map:
            vendor = mac_to_vendor(arp_map[ip])
            name = f"{vendor}-{ip.split('.')[-1]}" if vendor else f"unknown-{ip.split('.')[-1]}"
        else:
            name = ip  # fallback to IP

        # normalize some names: remove trailing dots
        name = name.rstrip(".")
        resolved[ip] = name

    log(f"[i] Resolved names for {len(resolved)} hosts")
    return resolved

# -----------------------
# Pi-hole API (session auth + put/delete)
# -----------------------
class PiHoleAPI:
    def __init__(self):
        self.session = requests.Session()
        self.sid = None
        self.csrf = None
        self.auth()

    def auth(self):
        if not PI_PASSWORD:
            log("[!] PI_PASSWORD is required for session auth")
            raise SystemExit(1)
        url = f"{API_BASE}/auth"
        try:
            r = self.session.post(url, json={"password": PI_PASSWORD}, timeout=10)
            r.raise_for_status()
            j = r.json()
            self.sid = j.get("session", {}).get("sid")
            self.csrf = j.get("session", {}).get("csrf")
            log(f"[i] Authenticated to Pi-hole via /api/auth. CSRF present: {bool(self.csrf)} SID present: {bool(self.sid)}")
        except Exception as e:
            log(f"[!] Pi-hole auth failed: {e}")
            raise

    def headers(self):
        h = {}
        # X-FTL-SID or Authorization
        if self.sid:
            h["X-FTL-SID"] = self.sid
            h["Authorization"] = f"Bearer {self.sid}"
        if self.csrf:
            h["X-CSRF-Token"] = self.csrf
        return h

    def put_host(self, ip, hostname):
        # value must be "IP hostname" but encoded in path; spaces need to be URL-encoded
        value = f"{ip} {hostname}"
        # encode value for URL path
        from urllib.parse import quote
        q = quote(value, safe='')
        url = f"{API_BASE}/config/dns/hosts/{q}"
        log(f"[DEBUG] PUT URL: {url}")
        if DRY_RUN:
            log(f"[DRY RUN] PUT {value}")
            return True
        try:
            r = self.session.put(url, headers=self.headers(), timeout=10)
            log(f"[DEBUG] PUT resp: {r.status_code} {r.text[:300]}")
            if r.status_code in (200, 204):
                return True
            else:
                log(f"[!] PUT failed {value}: {r.status_code} {r.text[:300]}")
                return False
        except Exception as e:
            log(f"[!] PUT exception for {value}: {e}")
            return False

    def delete_host(self, ip, hostname):
        value = f"{ip} {hostname}"
        from urllib.parse import quote
        q = quote(value, safe='')
        url = f"{API_BASE}/config/dns/hosts/{q}"
        log(f"[DEBUG] DELETE URL: {url}")
        if DRY_RUN:
            log(f"[DRY RUN] DELETE {value}")
            return True
        try:
            r = self.session.delete(url, headers=self.headers(), timeout=10)
            log(f"[DEBUG] DELETE resp: {r.status_code} {r.text[:300]}")
            return r.status_code in (200, 204)
        except Exception as e:
            log(f"[!] DELETE exception for {value}: {e}")
            return False

    def list_hosts_array(self):
        """Return list of host strings like 'IP hostname' or empty list."""
        try:
            url = f"{API_BASE}/config"
            log(f"[DEBUG] GET URL: {url}")
            r = self.session.get(url, headers=self.headers(), timeout=10)
            log(f"[DEBUG] GET resp: {r.status_code} {r.text[:400]}")
            r.raise_for_status()
            j = r.json()
            # try to extract config.dns.hosts
            hosts = []
            if isinstance(j, dict):
                hosts = j.get("config", {}).get("dns", {}).get("hosts", []) or []
                # sometimes returned as None
                if hosts is None:
                    hosts = []
            return hosts
        except Exception as e:
            log(f"[!] list_hosts_array failed: {e}")
            return []

# -----------------------
# Sync logic
# -----------------------
def sync_scan(api: PiHoleAPI):
    alive, reasons, arp_map = parallel_tcp_and_icmp(LAN_SUBNET)
    nbmap = run_nbtscan(LAN_SUBNET)
    mdmap = run_avahi(LAN_SUBNET)
    resolved = resolve_names(alive, arp_map, nbmap, mdmap)

    # Log discovery details
    log(f"[i] Discovery summary: {len(alive)} alive. Resolved {len([v for v in resolved.values() if v])} names.")
    # print each resolved
    for ip, name in sorted(resolved.items()):
        r = ", ".join(reasons.get(ip, []))
        mac = arp_map.get(ip, "")
        log(f"[DEBUG] {ip} -> {name} (reasons: {r} mac: {mac})")

    # Upsert each resolved host into Pi-hole
    added = 0
    for ip, hostname in resolved.items():
        ok = api.put_host(ip, hostname)
        if ok:
            added += 1

    log(f"[i] PUT attempts complete. {added} successful (DRY_RUN={DRY_RUN})")

    # Prune stale entries: fetch existing host list and delete any entries whose IP not in alive
    existing = api.list_hosts_array()
    if existing:
        # normalize to domain->ip mapping
        existing_map = {}
        for entry in existing:
            # entry is expected "IP hostname"
            parts = entry.split()
            if len(parts) >= 2:
                ip = parts[0].strip()
                host = " ".join(parts[1:]).strip()
                existing_map[f"{ip} {host}"] = (ip, host)
        # Delete entries not in current alive set and not PI_HOST_IP
        removed = 0
        for key, (ip, host) in existing_map.items():
            if ip == PI_HOST_IP:
                continue
            if ip not in alive:
                ok = api.delete_host(ip, host)
                if ok:
                    removed += 1
        log(f"[i] Prune: removed {removed} stale hosts (DRY_RUN={DRY_RUN})")
    else:
        log("[i] Prune: could not fetch existing hosts; skipping prune.")

# -----------------------
# Main loop
# -----------------------
def main_loop():
    if not PIHOLE_HOST or not PI_PASSWORD:
        log("[!] PIHOLE_HOST and PI_PASSWORD must be set in environment")
        raise SystemExit(1)

    while True:
        try:
            log("[*] Starting scan cycle")
            api = PiHoleAPI()
            sync_scan(api)
            log(f"[✓] Scan complete. Sleeping {SCAN_INTERVAL}s\n")
        except Exception as e:
            log(f"[!] Exception in main loop: {e}")
            traceback.print_exc()
        time.sleep(SCAN_INTERVAL)

if __name__ == "__main__":
    main_loop()
