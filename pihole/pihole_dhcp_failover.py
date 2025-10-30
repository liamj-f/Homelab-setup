#!/usr/bin/env python3
"""
Pi-hole DHCP Failover Monitor
Checks Pi 4 DHCP status and fails over to Pi Zero W if needed
Runs continuously, checking every 5 minutes
"""

import requests
import sys
import time
import os
from datetime import datetime

# Configuration from environment variables
PI4_HOST = os.getenv('RPI4_IP')
PI0_HOST = os.getenv('RPI0_IP')
PI4_PASSWORD = os.getenv('PIHOLE_WEBPASSWORD', '')
PI0_PASSWORD = os.getenv('PIHOLE_WEBPASSWORD', '')
CHECK_INTERVAL = int(os.getenv('CHECK_INTERVAL_SECONDS', '300'))  # Default 5 minutes

# Construct URLs
PI4_URL = f"http://{PI4_HOST}:82" if PI4_HOST else None
PI0_URL = f"http://{PI0_HOST}:82" if PI0_HOST else None

def log(message):
    """Print timestamped log message"""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"[{timestamp}] {message}")

def auth_pihole(base_url, password):
    """Authenticate to Pi-hole and return session tokens"""
    try:
        response = requests.post(
            f"{base_url}/api/auth",
            json={"password": password},
            timeout=10
        )
        response.raise_for_status()
        data = response.json()
        
        if "session" in data:
            return {
                "sid": data["session"]["sid"],
                "csrf": data["session"]["csrf"]
            }
        else:
            log(f"ERROR: Authentication failed for {base_url}")
            return None
    except requests.exceptions.RequestException as e:
        log(f"ERROR: Could not connect to {base_url}: {e}")
        return None

def get_dhcp_status(base_url, session):
    """Check if DHCP is enabled on a Pi-hole"""
    try:
        response = requests.get(
            f"{base_url}/api/config",
            headers={
                "X-FTL-SID": session["sid"],
                "X-FTL-CSRF": session["csrf"]
            },
            timeout=10
        )
        response.raise_for_status()
        data = response.json()
        
        if "config" in data and "dhcp" in data["config"]:
            return data["config"]["dhcp"].get("active", False)
        return False
    except requests.exceptions.RequestException as e:
        log(f"ERROR: Could not get DHCP status from {base_url}: {e}")
        return None

def set_dhcp_status(base_url, session, enabled):
    """Enable or disable DHCP on a Pi-hole"""
    try:
        response = requests.patch(
            f"{base_url}/api/config",
            headers={
                "X-FTL-SID": session["sid"],
                "X-FTL-CSRF": session["csrf"],
                "Content-Type": "application/json"
            },
            json={
                "config": {
                    "dhcp": {
                        "active": enabled
                    }
                }
            },
            timeout=10
        )
        response.raise_for_status()
        data = response.json()
        
        if "error" in data:
            log(f"ERROR: Failed to set DHCP on {base_url}: {data['error']}")
            return False
        return True
    except requests.exceptions.RequestException as e:
        log(f"ERROR: Could not set DHCP status on {base_url}: {e}")
        return False

def main():
    log("Starting Pi-hole DHCP failover monitor...")
    
    # Authenticate to Pi 4
    log("Authenticating to Pi 4...")
    pi4_session = auth_pihole(PI4_URL, PIHOLE_PASSWORD)
    if not pi4_session:
        log("CRITICAL: Cannot authenticate to Pi 4!")
        sys.exit(1)
    
    # Check Pi 4 DHCP status
    log("Checking Pi 4 DHCP status...")
    pi4_dhcp = get_dhcp_status(PI4_URL, pi4_session)
    
    if pi4_dhcp is None:
        log("CRITICAL: Cannot get Pi 4 DHCP status!")
        sys.exit(1)
    
    if pi4_dhcp:
        log("✓ Pi 4 DHCP running OK")
        
        # Ensure Pi Zero W DHCP is off
        log("Authenticating to Pi Zero W...")
        pi0_session = auth_pihole(PI0_URL, PIHOLE_PASSWORD)
        if pi0_session:
            log("Checking Pi Zero W DHCP status...")
            pi0_dhcp = get_dhcp_status(PI0_URL, pi0_session)
            
            if pi0_dhcp:
                log("⚠ Pi Zero W DHCP is enabled - disabling it...")
                if set_dhcp_status(PI0_URL, pi0_session, False):
                    log("✓ Pi Zero W DHCP disabled successfully")
                else:
                    log("ERROR: Failed to disable Pi Zero W DHCP")
            else:
                log("✓ Pi Zero W DHCP is off (as expected)")
        else:
            log("WARNING: Cannot authenticate to Pi Zero W")
        
        return 0
    
    else:
        log("⚠ Pi 4 DHCP is NOT running - initiating failover...")
        
        # Authenticate to Pi Zero W
        log("Authenticating to Pi Zero W...")
        pi0_session = auth_pihole(PI0_URL, PIHOLE_PASSWORD)
        if not pi0_session:
            log("CRITICAL: Cannot authenticate to Pi Zero W!")
            log("✗ No Pi-holes have DHCP enabled!")
            sys.exit(1)
        
        # Enable DHCP on Pi Zero W
        log("Enabling DHCP on Pi Zero W...")
        if set_dhcp_status(PI0_URL, pi0_session, True):
            log("✓ Failed over to Pi Zero W")
            return 0
        else:
            log("CRITICAL: Failed to enable DHCP on Pi Zero W!")
            log("✗ No Pi-holes have DHCP enabled!")
            sys.exit(1)

if __name__ == "__main__":
    try:
        exit_code = main()
        sys.exit(exit_code)
    except KeyboardInterrupt:
        log("Interrupted by user")
        sys.exit(130)
    except Exception as e:
        log(f"CRITICAL: Unexpected error: {e}")
        sys.exit(1)
