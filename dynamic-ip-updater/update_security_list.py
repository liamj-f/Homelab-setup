#!/usr/bin/env python3

import os
import time
import socket
import ipaddress
import base64
import oci
from datetime import datetime

# LIST_ITEMS format: "host1:port, host2:port_start-port_end, ip:port, ..."
# Examples:
#   "14monarch.tplinkdns.com:22"
#   "14monarch.tplinkdns.com:22, 14monarch.tplinkdns.com:9001, 14monarch.tplinkdns.com:80-90, 82.71.195.5:80"
LIST_ITEMS_STR = os.getenv('LIST_ITEMS', '')
SECURITY_LIST_ID = os.getenv('SECURITY_LIST_ID')
NSG_ID = os.getenv('NSG_ID')
WAF_ALLOWLIST_ID = os.getenv('WAF_ALLOWLIST_ID')
CHECK_INTERVAL = int(os.getenv('CHECK_INTERVAL', '300'))  # Default: 5 minutes

# OCI Configuration
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
    "key_content": oci_key_decoded
}


def log(message):
    """Print timestamped log message"""
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    print(f"[{timestamp}] {message}", flush=True)


def is_ip_address(host):
    """Return True if host is a literal IP address rather than a hostname"""
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def parse_list_items(list_items_str):
    """
    Parse LIST_ITEMS string into a list of (host, min_port, max_port) tuples.

    Accepts entries like:
        hostname:22
        hostname:80-90
        1.2.3.4:443
    """
    items = []
    for raw in list_items_str.split(','):
        entry = raw.strip()
        if not entry:
            continue
        try:
            last_colon = entry.rfind(':')
            if last_colon == -1:
                log(f"WARNING: Skipping malformed item (no port): '{entry}'")
                continue
            host = entry[:last_colon].strip()
            port_spec = entry[last_colon + 1:].strip()
            if '-' in port_spec:
                lo, hi = port_spec.split('-', 1)
                min_port, max_port = int(lo), int(hi)
            else:
                min_port = max_port = int(port_spec)
            items.append((host, min_port, max_port))
        except (ValueError, IndexError) as exc:
            log(f"WARNING: Skipping malformed item '{entry}': {exc}")
    return items


def resolve_host(host):
    """
    Return the IP address for host.
    If host is already an IP, return it unchanged.
    If DNS resolution fails, return None.
    """
    if is_ip_address(host):
        return host
    try:
        ip = socket.gethostbyname(host)
        return ip
    except socket.gaierror as exc:
        log(f"ERROR: Failed to resolve {host}: {exc}")
        return None


def rule_description(host, min_port, max_port):
    """Canonical description used to identify rules belonging to a host/port pair"""
    if min_port == max_port:
        return f"{host}:{min_port}"
    return f"{host}:{min_port}-{max_port}"


# ---------------------------------------------------------------------------
# Security List
# ---------------------------------------------------------------------------

def update_security_list(vcn_client, parsed_items, changed_hosts, new_host_ip_map):
    """
    Remove old VCN security list ingress rules for changed hosts and add
    fresh rules reflecting their new IPs.
    """
    if not SECURITY_LIST_ID:
        return True
    try:
        response = vcn_client.get_security_list(SECURITY_LIST_ID)
        current_rules = list(response.data.ingress_security_rules)

        # Drop rules whose description contains any changed host name
        kept_rules = []
        removed = 0
        for rule in current_rules:
            desc = getattr(rule, 'description', '') or ''
            if any(host in desc for host in changed_hosts):
                removed += 1
            else:
                kept_rules.append(rule)

        if removed:
            log(f"Security list: removed {removed} old rule(s) for changed hosts")

        # Build new rules for every (host, port) entry whose host changed
        new_rules = []
        for host, min_port, max_port in parsed_items:
            if host not in changed_hosts:
                continue
            new_ip = new_host_ip_map[host]
            if new_ip is None:
                continue
            new_rules.append(
                oci.core.models.IngressSecurityRule(
                    protocol="6",  # TCP
                    source=f"{new_ip}/32",
                    tcp_options=oci.core.models.TcpOptions(
                        destination_port_range=oci.core.models.PortRange(
                            min=min_port,
                            max=max_port
                        )
                    ),
                    description=rule_description(host, min_port, max_port)
                )
            )
            log(f"  + Security list: {rule_description(host, min_port, max_port)} -> {new_ip}")

        vcn_client.update_security_list(
            SECURITY_LIST_ID,
            oci.core.models.UpdateSecurityListDetails(
                ingress_security_rules=kept_rules + new_rules
            )
        )
        log("✓ Security list updated successfully")
        return True

    except Exception as exc:
        log(f"ERROR: Failed to update security list: {exc}")
        return False


# ---------------------------------------------------------------------------
# NSG
# ---------------------------------------------------------------------------

def update_nsg(vcn_client, parsed_items, changed_hosts, new_host_ip_map):
    """
    Remove old NSG ingress rules for changed hosts and add fresh per-port rules.
    """
    if not NSG_ID:
        return True
    try:
        response = vcn_client.list_network_security_group_security_rules(NSG_ID)
        current_rules = response.data

        # Collect IDs of rules belonging to changed hosts
        old_ids = [
            rule.id for rule in current_rules
            if any(host in (getattr(rule, 'description', '') or '') for host in changed_hosts)
        ]
        if old_ids:
            vcn_client.remove_network_security_group_security_rules(
                NSG_ID,
                oci.core.models.RemoveNetworkSecurityGroupSecurityRulesDetails(
                    security_rule_ids=old_ids
                )
            )
            log(f"NSG: removed {len(old_ids)} old rule(s) for changed hosts")

        # Build new per-port rules for changed hosts
        new_rules = []
        for host, min_port, max_port in parsed_items:
            if host not in changed_hosts:
                continue
            new_ip = new_host_ip_map[host]
            if new_ip is None:
                continue
            new_rules.append(
                oci.core.models.AddSecurityRuleDetails(
                    direction="INGRESS",
                    protocol="6",  # TCP
                    source=f"{new_ip}/32",
                    source_type="CIDR_BLOCK",
                    tcp_options=oci.core.models.TcpOptions(
                        destination_port_range=oci.core.models.PortRange(
                            min=min_port,
                            max=max_port
                        )
                    ),
                    description=rule_description(host, min_port, max_port)
                )
            )
            log(f"  + NSG: {rule_description(host, min_port, max_port)} -> {new_ip}")

        if new_rules:
            vcn_client.add_network_security_group_security_rules(
                NSG_ID,
                oci.core.models.AddNetworkSecurityGroupSecurityRulesDetails(
                    security_rules=new_rules
                )
            )
        log("✓ NSG updated successfully")
        return True

    except Exception as exc:
        log(f"ERROR: Failed to update NSG: {exc}")
        return False


# ---------------------------------------------------------------------------
# WAF Network Address List
# ---------------------------------------------------------------------------

def update_waf_allowlist(waf_client, old_host_ip_map, new_host_ip_map):
    """
    Synchronise the WAF Network Address List so it contains exactly the
    current set of resolved IPs (plus any CIDRs we did not add ourselves).

    Strategy:
      - IPs that were in old_host_ip_map but are no longer in new_host_ip_map
        are removed.
      - IPs that are in new_host_ip_map but not yet in the WAF list are added.
      - Manually-added CIDRs (not in either map) are left untouched.
    """
    if not WAF_ALLOWLIST_ID:
        return True
    try:
        response = waf_client.get_network_address_list(WAF_ALLOWLIST_ID)
        addresses = list(response.data.addresses) if response.data.addresses else []

        # CIDRs previously managed by this script that are no longer needed
        old_ips = {ip for ip in old_host_ip_map.values() if ip}
        new_ips = {ip for ip in new_host_ip_map.values() if ip}
        ips_to_remove = old_ips - new_ips

        for ip in ips_to_remove:
            cidr = f"{ip}/32"
            if cidr in addresses:
                addresses.remove(cidr)
                log(f"  - WAF: removed {cidr}")

        for ip in new_ips:
            cidr = f"{ip}/32"
            if cidr not in addresses:
                addresses.append(cidr)
                log(f"  + WAF: added {cidr}")

        waf_client.update_network_address_list(
            WAF_ALLOWLIST_ID,
            oci.waf.models.UpdateNetworkAddressListAddressesDetails(
                addresses=addresses
            )
        )
        log("✓ WAF allowlist updated successfully")
        return True

    except Exception as exc:
        log(f"ERROR: Failed to update WAF allowlist: {exc}")
        return False


# ---------------------------------------------------------------------------
# Main loop
# ---------------------------------------------------------------------------

def main():
    log("=== IP Security List Updater Starting ===")

    parsed_items = parse_list_items(LIST_ITEMS_STR)
    if not parsed_items:
        log(
            "ERROR: LIST_ITEMS not set or could not be parsed. "
            "Expected format: 'host:port, host:port_start-port_end, ip:port'"
        )
        return

    # Unique hosts preserving first-seen order
    unique_hosts = list(dict.fromkeys(h for h, _, _ in parsed_items))

    log(f"LIST_ITEMS: {LIST_ITEMS_STR}")
    log(f"Unique hosts/IPs ({len(unique_hosts)}): {', '.join(unique_hosts)}")
    log(f"Security List ID: {SECURITY_LIST_ID or '(not configured)'}")
    log(f"NSG ID:           {NSG_ID or '(not configured)'}")
    log(f"WAF Allowlist ID: {WAF_ALLOWLIST_ID or '(not configured)'}")
    log(f"Check Interval:   {CHECK_INTERVAL} seconds")
    log(f"Region:           {config['region']}")

    if not any([SECURITY_LIST_ID, NSG_ID, WAF_ALLOWLIST_ID]):
        log("ERROR: At least one of SECURITY_LIST_ID, NSG_ID, or WAF_ALLOWLIST_ID must be set.")
        return

    if not all([config['user'], config['fingerprint'], config['tenancy'], config['key_content']]):
        log("ERROR: OCI credentials not properly configured!")
        return

    try:
        vcn_client = oci.core.VirtualNetworkClient(config)
        waf_client = oci.waf.WafClient(config)
        log("✓ OCI clients initialised successfully")
    except Exception as exc:
        log(f"ERROR: Failed to initialise OCI clients: {exc}")
        return

    # Per-host state: None means "not yet resolved / not yet pushed to OCI"
    host_ip_map = {host: None for host in unique_hosts}

    while True:
        try:
            # Resolve every host (static IPs pass through unchanged)
            newly_resolved = {host: resolve_host(host) for host in unique_hosts}

            # Hosts whose IP has changed (including first-time resolution)
            changed_hosts = [
                host for host in unique_hosts
                if newly_resolved[host] is not None
                and newly_resolved[host] != host_ip_map[host]
            ]

            if changed_hosts:
                for host in changed_hosts:
                    log(f"IP change: {host}  {host_ip_map[host]} -> {newly_resolved[host]}")

                update_security_list(vcn_client, parsed_items, changed_hosts, newly_resolved)
                update_nsg(vcn_client, parsed_items, changed_hosts, newly_resolved)
                # Pass the full old and new maps so WAF can manage the complete IP set
                update_waf_allowlist(waf_client, host_ip_map, newly_resolved)

                # Persist new IPs (only for hosts that resolved successfully)
                for host in changed_hosts:
                    host_ip_map[host] = newly_resolved[host]

            else:
                status = ', '.join(
                    f"{h}={newly_resolved[h] or 'unresolved'}" for h in unique_hosts
                )
                log(f"No IP changes ({status})")

            time.sleep(CHECK_INTERVAL)

        except KeyboardInterrupt:
            log("Shutting down...")
            break
        except Exception as exc:
            log(f"ERROR: Unexpected error: {exc}")
            time.sleep(60)


if __name__ == "__main__":
    main()
