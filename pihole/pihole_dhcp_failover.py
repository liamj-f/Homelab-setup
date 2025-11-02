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
# Support both direct IPs and full URLs for flexibility
Primary_IP = os.getenv('PRIMARY_IP')
Secondary_IP = os.getenv('SECONDARY_IP')
Primary_Password = os.getenv('PRIMARY_PASSWORD')
Secondary_Password = os.getenv('SECONDARY_PASSWORD')
CHECK_INTERVAL = os.getenv('CHECK_INTERVAL', '300')

Primary_Host = f"http://{Primary_IP}:82"
Secondary_Host = f"http://{Secondary_IP}:82"


def log(message):
    """Print timestamped log message"""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"[{timestamp}] {message}")

def auth_pihole(base_url, password):
    if not password:
        log(f"ERROR: No password provided for {base_url}")
        return None
    
    try:
        #log(f"Logging into {base_url}.")
        response = requests.post(
            f"{base_url}/api/auth",
            json={"password": password},
            timeout=10
        )
        response.raise_for_status()
        data = response.json()
        
        if "session" in data:
            #log(f"Logged into {base_url}.")
            return {
                "base_url":base_url,
                "sid": data["session"]["sid"],
                "csrf": data["session"]["csrf"],
            }
        else:
            log(f"ERROR: Authentication failed for {base_url}")
            return None
    except requests.exceptions.RequestException as e:
        log(f"ERROR: Could not connect to {base_url}: {e}")
        return False
    
def deauth_pihole(session):
    if not session:
        log("DEBUG: No session to logout from")
        return
    
    try:
        #log(f"Logging out from {session['base_url']}...")
        response = requests.delete(
            f"{session['base_url']}/api/auth",
            headers={
                "X-FTL-SID": session["sid"],
                "X-FTL-CSRF": session["csrf"]
            },
            timeout=10
        )
        response.raise_for_status()
        #log(f"Logged out from {session['base_url']}")
        return True
    except requests.exceptions.RequestException as e:
        log(f"WARNING: Could not logout from {session['base_url']}: {e}")
        return False

def get_dhcp_status(session):
    try:
        response = requests.get(
            f"{session['base_url']}/api/config",
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
        log(f"ERROR: Could not get DHCP status from {session['base_url']}: {e}")
        return None

def set_dhcp_status(session, active):
    ## Active is boolean true or false
    try:
        response = requests.patch(
            f"{session['base_url']}/api/config",
            headers={
                "X-FTL-SID": session["sid"],
                "X-FTL-CSRF": session["csrf"],
                "Content-Type": "application/json"
            },
            json={
                "config": {
                    "dhcp": {
                        "active": active
                    }
                }
            },
            timeout=10
        )
        response.raise_for_status()
        data = response.json()
        
        if "error" in data:
            log(f"ERROR: Failed to set DHCP on {session['base_url']}: {data['error']}")
            return False
        return True
    except requests.exceptions.RequestException as e:
        log(f"ERROR: Could not set DHCP status on {session['base_url']}: {e}")
        return False

def Check_and_Set_DHCP(host, password, active):
    ## active is a boolean passed into set_dhcp_Status(), determining failover or failback
    session = auth_pihole(host,password)
    if session == False:
        log(f"Unable to reach {host}.")
        return False
    try:
        dhcp_status = get_dhcp_status(session)

        if dhcp_status == None:
            log(f"Unable to see if DHCP running on {session['base_url']}")
            if set_dhcp_status(session, active) == False:
                log(f"Tried making DHCP active:{active} on {session['base_url']} unsuccessfully.")
                return False
            else:
                log(f"Made DHCP active:{active} on {session['base_url']} successfully.")
                return True
        elif dhcp_status == active:
            log(f"DHCP already active:{active} on {session['base_url']}.")
            return True
        elif dhcp_status != active:
            if set_dhcp_status(session, active) == False:
                log(f"Tried making DHCP active:{active} on {session['base_url']} unsuccessfully.")
                return False
            else:
                log(f"Made DHCP active:{active} on {session['base_url']} successfully.")
                return True
    finally:
        deauth_pihole(session)
 
def updater():
    primary_check_and_set = Check_and_Set_DHCP(Primary_Host,Primary_Password, True)
    if primary_check_and_set == False: #Primary
        secondary_check_and_set = Check_and_Set_DHCP(Secondary_Host,Secondary_Password, True)
        if secondary_check_and_set == False: #Secondary
            log(f"Unable to Enable Primary DHCP or Secondary DHCP")
            return 0
        elif secondary_check_and_set == True:
            log(f"Unable to Enable Primary DHCP, Secondary DHCP enabled.") 
            return 1
    elif primary_check_and_set == True:
        secondary_check_and_set = Check_and_Set_DHCP(Secondary_Host,Secondary_Password, False)
        if secondary_check_and_set == True:
            log("Primary DHCP Enabled, Secondary DHCP Disabled.")
            return 1
        elif secondary_check_and_set == False:
            log("Primary DHCP Enabled, Unable to confirm status of secondary.")                          
            return 1

def main():
    """Initialize and start monitoring loop"""
    log("Starting Pi-hole DHCP failover monitor...")
    
    # Validate configuration
    if not Primary_Host or not Secondary_Host:
        log("CRITICAL: Pi-hole IP addresses must be set!")
        log("Set either Primary_IP or Secondary_IP environment variables")
        log(f"Current values: Primary_Host={Primary_Host}, Secondary_Host={Secondary_Host}")
        sys.exit(1)
    
    if not Primary_Host or not Secondary_Password:
        log("WARNING: Passwords not set. Using empty passwords.")
    
    log(f"Configuration:")
    log(f"  Primary: {Primary_Host}")
    log(f"  Secondary: {Secondary_Host}")
    log(f"  Check interval: {CHECK_INTERVAL} seconds")
    
    # Main monitoring loop
    while True:
        try:
            exit_code = updater()
            if exit_code != 0:
                log(f"Check completed with exit code {exit_code}")
        except Exception as e:
            log(f"ERROR during check: {e}")
        
        log(f"Waiting {CHECK_INTERVAL} seconds until next check...")
        time.sleep(int(CHECK_INTERVAL))
    
if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        log("Interrupted by user - shutting down")
        sys.exit(0)
