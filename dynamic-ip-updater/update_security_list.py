#!/usr/bin/env python3

import os
import time
import socket
import json
import base64
import oci
from datetime import datetime

# Configuration from environment variables
TARGET_HOSTNAME = os.getenv('TARGET_HOSTNAME', '14monarch.tplinkdns.com')
SECURITY_LIST_ID = os.getenv('SECURITY_LIST_ID')
NSG_ID = os.getenv('NSG_ID')
WAF_ALLOWLIST_ID = os.getenv('WAF_ALLOWLIST_ID')
CHECK_INTERVAL = int(os.getenv('CHECK_INTERVAL', '300'))  # Default: 5 minutes
PORTS = [22]  # SSH

# OCI Configuration
oci_key_base64 = os.getenv('OCI_KEY_CONTENT_BASE64')
if oci_key_base64:
    oci_key_decoded = base64.b64decode(oci_key_base64).decode('utf-8')
else:
    oci_key_decoded = os.getenv('OCI_KEY_CONTENT')  # Fallback

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

def get_port_description(port):
    """Get description for a port"""
    if port == 22:
        return f"{TARGET_HOSTNAME} - SSH access"
    elif port == 9001:
        return f"{TARGET_HOSTNAME} - Port 9001"
    else:
        return f"{TARGET_HOSTNAME} - Port {port}"

def resolve_ip(TARGET_HOSTNAME):
    """Resolve TARGET_HOSTNAME to IP address"""
    try:
        ip = socket.gethostbyname(TARGET_HOSTNAME)
        log(f"Resolved {TARGET_HOSTNAME} to {ip}")
        return ip
    except socket.gaierror as e:
        log(f"ERROR: Failed to resolve {TARGET_HOSTNAME}: {e}")
        return None

def get_current_rules(virtual_network_client):
    """Get current security list rules"""
    try:
        response = virtual_network_client.get_security_list(SECURITY_LIST_ID)
        return response.data.ingress_security_rules
    except Exception as e:
        log(f"ERROR: Failed to get security list: {e}")
        return None

def update_security_list(virtual_network_client, new_ip):
    """Update security list with new IP for all configured ports"""
    try:
        # Get current rules
        current_rules = get_current_rules(virtual_network_client)
        if current_rules is None:
            return False

        # Filter out old rules for this TARGET_HOSTNAME (all ports)
        description_prefix = TARGET_HOSTNAME
        filtered_rules = [
            rule for rule in current_rules 
            if not (hasattr(rule, 'description') and rule.description and description_prefix in rule.description)
        ]

        removed_count = len(current_rules) - len(filtered_rules)
        if removed_count > 0:
            log(f"Removed {removed_count} old rule(s) for {TARGET_HOSTNAME}")

        # Create new rules for each port
        new_rules = []
        for port in PORTS:
            new_rule = oci.core.models.IngressSecurityRule(
                protocol="6",  # TCP
                source=f"{new_ip}/32",
                tcp_options=oci.core.models.TcpOptions(
                    destination_port_range=oci.core.models.PortRange(
                        min=port,
                        max=port
                    )
                ),
                description=get_port_description(port)
            )
            new_rules.append(new_rule)

        # Combine filtered rules with new rules
        updated_rules = filtered_rules + new_rules

        # Update security list
        update_details = oci.core.models.UpdateSecurityListDetails(
            ingress_security_rules=updated_rules
        )

        virtual_network_client.update_security_list(
            SECURITY_LIST_ID,
            update_details
        )

        log(f"✓ Security list updated successfully with IP: {new_ip}")
        for port in PORTS:
            log(f"  - Port {port} rule added")
        return True

    except Exception as e:
        log(f"ERROR: Failed to update security list: {e}")
        return False

def update_nsg(virtual_network_client, new_ip):
    """Update NSG rules with new source CIDR for all configured ports"""
    if not NSG_ID:
        return True  # Skip silently if not configured

    try:
        # List current NSG rules
        response = virtual_network_client.list_network_security_group_security_rules(NSG_ID)
        current_rules = response.data

        # Find and remove old rules for this TARGET_HOSTNAME
        old_rule_ids = [
            rule.id for rule in current_rules
            if hasattr(rule, 'description') and rule.description and TARGET_HOSTNAME in rule.description
        ]

        if old_rule_ids:
            virtual_network_client.remove_network_security_group_security_rules(
                NSG_ID,
                oci.core.models.RemoveNetworkSecurityGroupSecurityRulesDetails(
                    security_rule_ids=old_rule_ids
                )
            )
            log(f"Removed {len(old_rule_ids)} old NSG rule(s) for {TARGET_HOSTNAME}")

        # Add a single rule allowing all protocols/ports
        virtual_network_client.add_network_security_group_security_rules(
            NSG_ID,
            oci.core.models.AddNetworkSecurityGroupSecurityRulesDetails(
                security_rules=[
                    oci.core.models.AddSecurityRuleDetails(
                        direction="INGRESS",
                        protocol="all",
                        source=f"{new_ip}/32",
                        source_type="CIDR_BLOCK",
                        description=f"{TARGET_HOSTNAME} - all protocols"
                    )
                ]
            )
        )

        log(f"✓ NSG updated successfully with IP: {new_ip} (all protocols)")
        return True

    except Exception as e:
        log(f"ERROR: Failed to update NSG: {e}")
        return False


def update_waf_allowlist(waf_client, old_ip, new_ip):
    """Update WAF Network Address List with new IP, replacing the old one"""
    if not WAF_ALLOWLIST_ID:
        return True  # Skip silently if not configured

    try:
        # Get current address list
        response = waf_client.get_network_address_list(WAF_ALLOWLIST_ID)
        current_addresses = list(response.data.addresses) if response.data.addresses else []

        # Remove old IP entry if present
        if old_ip:
            old_cidr = f"{old_ip}/32"
            current_addresses = [a for a in current_addresses if a != old_cidr]
            log(f"Removed old WAF allowlist entry: {old_cidr}")

        # Add new IP if not already present
        new_cidr = f"{new_ip}/32"
        if new_cidr not in current_addresses:
            current_addresses.append(new_cidr)

        waf_client.update_network_address_list(
            WAF_ALLOWLIST_ID,
            oci.waf.models.UpdateNetworkAddressListAddressesDetails(
                addresses=current_addresses
            )
        )

        log(f"✓ WAF allowlist updated successfully with IP: {new_ip}")
        return True

    except Exception as e:
        log(f"ERROR: Failed to update WAF allowlist: {e}")
        return False


def main():
    """Main loop"""
    log("=== IP Security List Updater Starting ===")
    log(f"TARGET_HOSTNAME: {TARGET_HOSTNAME}")
    log(f"Ports: {', '.join(map(str, PORTS))}")
    log(f"Security List ID: {SECURITY_LIST_ID}")
    log(f"NSG ID: {NSG_ID or '(not configured)'}")
    log(f"WAF Allowlist ID: {WAF_ALLOWLIST_ID or '(not configured)'}")
    log(f"Check Interval: {CHECK_INTERVAL} seconds")
    log(f"Region: {config['region']}")

    # Validate configuration
    if not SECURITY_LIST_ID:
        log("ERROR: SECURITY_LIST_ID not set!")
        return

    if not all([config['user'], config['fingerprint'], config['tenancy'], config['key_content']]):
        log("ERROR: OCI credentials not properly configured!")
        return

    # Initialize OCI clients
    try:
        virtual_network_client = oci.core.VirtualNetworkClient(config)
        waf_client = oci.waf.WafClient(config)
        log("✓ OCI clients initialized successfully")
    except Exception as e:
        log(f"ERROR: Failed to initialize OCI clients: {e}")
        return

    current_ip = None

    while True:
        try:
            # Resolve current IP
            new_ip = resolve_ip(TARGET_HOSTNAME)

            if new_ip is None:
                log(f"Skipping update due to DNS resolution failure")
            elif new_ip != current_ip:
                log(f"IP change detected: {current_ip} -> {new_ip}")
                sl_ok = update_security_list(virtual_network_client, new_ip)
                nsg_ok = update_nsg(virtual_network_client, new_ip)
                waf_ok = update_waf_allowlist(waf_client, current_ip, new_ip)
                if sl_ok and nsg_ok and waf_ok:
                    current_ip = new_ip
            else:
                log(f"IP unchanged: {current_ip}")

            # Wait before next check
            time.sleep(CHECK_INTERVAL)

        except KeyboardInterrupt:
            log("Shutting down...")
            break
        except Exception as e:
            log(f"ERROR: Unexpected error: {e}")
            time.sleep(60)  # Wait a minute before retrying

if __name__ == "__main__":
    main()