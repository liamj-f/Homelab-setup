#!/usr/bin/env python3

import os
import time
import socket
import json
import oci
from datetime import datetime

# Configuration from environment variables
HOSTNAME = os.getenv('HOSTNAME', '14monarch.tplinkdns.com')
SECURITY_LIST_ID = os.getenv('SECURITY_LIST_ID')
CHECK_INTERVAL = int(os.getenv('CHECK_INTERVAL', '300'))  # Default: 5 minutes
PORT = int(os.getenv('PORT', '9001'))

# OCI Configuration
config = {
    "user": os.getenv('OCI_USER'),
    "fingerprint": os.getenv('OCI_FINGERPRINT'),
    "tenancy": os.getenv('OCI_TENANCY'),
    "region": os.getenv('OCI_REGION', 'uk-london-1'),
    "key_content": os.getenv('OCI_KEY_CONTENT')
}

def log(message):
    """Print timestamped log message"""
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    print(f"[{timestamp}] {message}", flush=True)

def resolve_ip(hostname):
    """Resolve hostname to IP address"""
    try:
        ip = socket.gethostbyname(hostname)
        log(f"Resolved {hostname} to {ip}")
        return ip
    except socket.gaierror as e:
        log(f"ERROR: Failed to resolve {hostname}: {e}")
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
    """Update security list with new IP"""
    try:
        # Get current rules
        current_rules = get_current_rules(virtual_network_client)
        if current_rules is None:
            return False
        
        # Filter out old rules for this hostname
        description_marker = f"{HOSTNAME} - Port {PORT}"
        filtered_rules = [
            rule for rule in current_rules 
            if not (hasattr(rule, 'description') and description_marker in rule.description)
        ]
        
        log(f"Removed {len(current_rules) - len(filtered_rules)} old rule(s) for {HOSTNAME}")
        
        # Create new rule
        new_rule = oci.core.models.IngressSecurityRule(
            protocol="6",  # TCP
            source=f"{new_ip}/32",
            tcp_options=oci.core.models.TcpOptions(
                destination_port_range=oci.core.models.PortRange(
                    min=PORT,
                    max=PORT
                )
            ),
            description=description_marker
        )
        
        # Combine filtered rules with new rule
        updated_rules = filtered_rules + [new_rule]
        
        # Update security list
        update_details = oci.core.models.UpdateSecurityListDetails(
            ingress_security_rules=updated_rules
        )
        
        virtual_network_client.update_security_list(
            SECURITY_LIST_ID,
            update_details
        )
        
        log(f"✓ Security list updated successfully with IP: {new_ip}")
        return True
        
    except Exception as e:
        log(f"ERROR: Failed to update security list: {e}")
        return False

def main():
    """Main loop"""
    log("=== IP Security List Updater Starting ===")
    log(f"Hostname: {HOSTNAME}")
    log(f"Port: {PORT}")
    log(f"Security List ID: {SECURITY_LIST_ID}")
    log(f"Check Interval: {CHECK_INTERVAL} seconds")
    log(f"Region: {config['region']}")
    
    # Validate configuration
    if not SECURITY_LIST_ID:
        log("ERROR: SECURITY_LIST_ID not set!")
        return
    
    if not all([config['user'], config['fingerprint'], config['tenancy'], config['key_content']]):
        log("ERROR: OCI credentials not properly configured!")
        return
    
    # Initialize OCI client
    try:
        virtual_network_client = oci.core.VirtualNetworkClient(config)
        log("✓ OCI client initialized successfully")
    except Exception as e:
        log(f"ERROR: Failed to initialize OCI client: {e}")
        return
    
    current_ip = None
    
    while True:
        try:
            # Resolve current IP
            new_ip = resolve_ip(HOSTNAME)
            
            if new_ip is None:
                log(f"Skipping update due to DNS resolution failure")
            elif new_ip != current_ip:
                log(f"IP change detected: {current_ip} -> {new_ip}")
                if update_security_list(virtual_network_client, new_ip):
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
