#!/usr/bin/env python3
"""
Pi-hole dynamic hostname sync using Pi-hole /api/auth session auth (no API_TOKEN required).

Env vars:
- PIHOLE_HOST      e.g. 192.168.0.2
- PIHOLE_PORT      e.g. 82 (optional, default 80)
- PI_PASSWORD      (admin password) OR PIHOLE_TOKEN (optional)
- LAN_SUBNET       e.g. 192.168.0.0/24
- PI_HOST_IP       IP of the Pi-hole host to preserve (do not prune)
- SCAN_INTERVAL    seconds (default 300)
- DRY_RUN          "1" to not perform adds/deletes (default 0)
"""
import os, time, socket, requests, subprocess, json
from ipaddress import ip_network

PIHOLE_HOST = os.getenv("PIHOLE_HOST", "pihole.local")
PIHOLE_PORT = os.getenv("PIHOLE_PORT", "80")
PI_PASSWORD = os.getenv("PI_PASSWORD")
PIHOLE_TOKEN = os.getenv("PIHOLE_TOKEN")   # optional fallback
LAN_SUBNET = os.getenv("LAN_SUBNET", "192.168.0.0/24")
PI_HOST_IP = os.getenv("PI_HOST_IP")       # required for pruning rule
SCAN_INTERVAL = int(os.getenv("SCAN_INTERVAL", "300"))
DRY_RUN = os.getenv("DRY_RUN", "0") == "1"

BASE = f"http://{PIHOLE_HOST}:{PIHOLE_PORT}"
API_URL = f"{BASE}/api"
AUTH_URL = f"{BASE}/api/auth"             # per your snippet

# Utilities: network scan
def scan_network(subnet):
    alive = []
    for ip in ip_network(subnet).hosts():
        ipstr = str(ip)
        if ipstr.endswith(".0") or ipstr.endswith(".255"):
            continue
        # quick ping
        res = subprocess.call(["ping", "-c", "1", "-W", "1", ipstr],
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if res == 0:
            alive.append(ipstr)
    return alive

# Resolution methods
def resolve_reverse(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return None

def resolve_mdns(ip):
    try:
        out = subprocess.check_output(["avahi-resolve-address", ip], stderr=subprocess.DEVNULL).decode().strip()
        if out and " " in out:
            return out.split(" ", 1)[1]
    except Exception:
        pass
    return None

def resolve_netbios(ip):
    try:
        out = subprocess.check_output(["nbtscan", "-s:", ip], stderr=subprocess.DEVNULL).decode()
        for line in out.splitlines():
            if ip in line:
                parts = line.split()
                if len(parts) > 1:
                    return parts[1]
    except Exception:
        pass
    return None

# Pi-hole API helpers using either token or session auth
class PiHoleAPI:
    def __init__(self):
        self.session = requests.Session()
        self.csrf = None
        self.token = PIHOLE_TOKEN

        if not self.token:
            if not PI_PASSWORD:
                raise SystemExit("Need PI_PASSWORD or PIHOLE_TOKEN in env")
            self._auth_with_password()

    def _auth_with_password(self):
        """POST /api/auth with password to obtain session cookie + csrf"""
        try:
            r = self.session.post(AUTH_URL, json={"password": PI_PASSWORD}, timeout=10)
            r.raise_for_status()
            j = r.json()
            # expected path: j["session"]["csrf"] and j["session"]["sid"]
            self.csrf = None
            try:
                self.csrf = j.get("session", {}).get("csrf")
            except Exception:
                self.csrf = None
            print("[*] Authenticated to Pi-hole API (session auth). CSRF:", bool(self.csrf))
        except Exception as e:
            raise SystemExit(f"Failed to auth to Pi-hole via {AUTH_URL}: {e}")

    def _auth_params(self):
        if self.token:
            return {"auth": self.token}
        return {}

    def _auth_headers(self, extra=None):
        headers = {}
        if self.csrf:
            # Common header name; include to be safe
            headers["X-CSRF-Token"] = self.csrf
        if extra:
            headers.update(extra)
        return headers

    def list_localdns(self):
        params = {"list": "localdns"}
        params.update(self._auth_params())
        r = self.session.get(API_URL, params=params, timeout=10)
        if not r.ok:
            print("[!] list_localdns failed:", r.status_code, r.text[:200])
            return []
        return r.json().get("data", [])

    def add_localdns(self, ip, domain):
        params = {"list": "localdns", "add": "A", "domain": domain, "ip": ip}
        params.update(self._auth_params())
        if DRY_RUN:
            print(f"[DRY RUN] Would add {domain} -> {ip}")
            return True
        r = self.session.get(API_URL, params=params, headers=self._auth_headers(), timeout=10)
        if r.ok:
            print(f"[+] Added {domain} -> {ip}")
            return True
        else:
            print("[!] add_localdns failed:", r.status_code, r.text[:200])
            return False

    def delete_localdns_by_id(self, rid):
        params = {"list": "localdns", "delete": rid}
        params.update(self._auth_params())
        if DRY_RUN:
            print(f"[DRY RUN] Would delete record id {rid}")
            return True
        r = self.session.get(API_URL, params=params, headers=self._auth_headers(), timeout=10)
        if r.ok:
            print(f"[-] Deleted record id {rid}")
            return True
        else:
            print("[!] delete_localdns failed:", r.status_code, r.text[:200])
            return False

# Main loop
def main():
    api = PiHoleAPI()
    print(f"Starting scan {LAN_SUBNET}, prune except {PI_HOST_IP}, DRY_RUN={DRY_RUN}")
    while True:
        active_ips = set(scan_network(LAN_SUBNET))
        existing = api.list_localdns()   # list of dicts (id, domain, ip)
        existing_map = {e["domain"]: e for e in existing}

        found_map = {}   # ip -> hostname
        for ip in active_ips:
            name = resolve_reverse(ip) or resolve_mdns(ip) or resolve_netbios(ip)
            if name:
                name = name.rstrip(".")
                found_map[ip] = name

        # Add new records (domain not present or present but different ip)
        for ip, hostname in found_map.items():
            if hostname in existing_map:
                if existing_map[hostname]["ip"] == ip:
                    continue
                else:
                    # domain exists with different IP. Delete old and add new.
                    rid = existing_map[hostname]["id"]
                    print(f"[!] {hostname} exists with different IP {existing_map[hostname]['ip']} -> replacing with {ip}")
                    if not DRY_RUN:
                        api.delete_localdns_by_id(rid)
                        time.sleep(0.3)
                        api.add_localdns(ip, hostname)
            else:
                api.add_localdns(ip, hostname)

        # Prune stale records: if record ip not in active_ips and not equal to PI_HOST_IP -> delete
        for rec in existing:
            rid = rec["id"]
            domain = rec["domain"]
            ip = rec["ip"]
            if ip == PI_HOST_IP:
                continue
            if ip not in active_ips:
                api.delete_localdns_by_id(rid)

        print(f"Scan complete. Sleeping {SCAN_INTERVAL}s")
        time.sleep(SCAN_INTERVAL)

if __name__ == "__main__":
    main()
