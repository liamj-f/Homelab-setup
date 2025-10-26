#!/usr/bin/env python3
"""
Pi-hole DHCP Failover Monitor
Monitors Pi4 Pi-hole health and enables DHCP on Pi0 if Pi4 fails
"""

import os
import time
import requests
import logging

# Configuration from environment variables
PI4_HOST = os.getenv('PI4_HOST', 'http://pihole.14monarch.local')
PI0_HOST = os.getenv('PI0_HOST', 'http://pihole0.14monarch.local')
PI4_PASSWORD = os.getenv('PI4_PASSWORD', '')
PI0_PASSWORD = os.getenv('PI0_PASSWORD', '')

# Monitoring settings
CHECK_INTERVAL = int(os.getenv('CHECK_INTERVAL', '30'))  # seconds

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)


class PiHoleSession:
    """Manages authentication and session for a Pi-hole instance"""
    def __init__(self, host, password):
        self.host = host
        self.password = password
        self.session = requests.Session()
        self.sid = None
        self.csrf_token = None
        self.last_auth = 0
        self.auth_ttl = 300  # Re-authenticate every 5 minutes
    
    def authenticate(self, retries=3):
        """Authenticate with Pi-hole and get session ID and CSRF token (with retries)"""
        for attempt in range(retries):
            try:
                response = self.session.post(
                    f"{self.host}/api/auth",
                    json={"password": self.password},
                    timeout=5
                )
                
                if response.status_code == 200:
                    data = response.json()
                    self.sid = data.get('session', {}).get('sid')
                    self.csrf_token = data.get('session', {}).get('csrf')
                    self.last_auth = time.time()
                    
                    if self.sid and self.csrf_token:
                        return True
                        
            except requests.exceptions.RequestException:
                if attempt < retries - 1:
                    time.sleep(1)  # Wait 1 second between retries
                    continue
                    
        return False
    
    def ensure_authenticated(self):
        """Ensure we have a valid session, re-authenticate if needed"""
        if not self.sid or not self.csrf_token or (time.time() - self.last_auth) > self.auth_ttl:
            return self.authenticate()
        return True
    
    def get_headers(self):
        """Get headers with authentication tokens"""
        return {
            "X-FTL-SID": self.sid,
            "X-FTL-CSRF": self.csrf_token,
            "Content-Type": "application/json"
        }


class PiHoleMonitor:
    def __init__(self):
        self.current_dhcp = None  # Will be set on startup: "pi4", "pi0", or None
        
        # Create sessions for each Pi-hole
        self.pi4_session = PiHoleSession(PI4_HOST, PI4_PASSWORD)
        self.pi0_session = PiHoleSession(PI0_HOST, PI0_PASSWORD)
    
    def set_dhcp_status(self, session, active):
        """Enable or disable DHCP on Pi-hole"""
        try:
            if not session.ensure_authenticated():
                return False
            
            response = session.session.patch(
                f"{session.host}/api/config/dhcp",
                headers=session.get_headers(),
                json={"config": {"active": active}},
                timeout=10
            )
            
            return response.status_code == 200
                
        except requests.exceptions.RequestException:
            return False
    
    def get_dhcp_status(self, session):
        """Get current DHCP status from Pi-hole"""
        try:
            if not session.ensure_authenticated():
                return None
            
            response = session.session.get(
                f"{session.host}/api/config/dhcp",
                headers=session.get_headers(),
                timeout=5
            )
            
            if response.status_code == 200:
                config = response.json()
                return config.get('config', {}).get('dhcp', {}).get('active', False)
            
            return None
            
        except requests.exceptions.RequestException:
            return None
    
    def initialize_current_dhcp(self):
        """Detect which Pi-hole is currently serving DHCP on startup"""
        logger.info("Detecting current DHCP state...")
        
        pi4_dhcp = self.get_dhcp_status(self.pi4_session)
        if pi4_dhcp:
            self.current_dhcp = "pi4"
            logger.info("✓ Pi4 is currently serving DHCP")
            return
        
        pi0_dhcp = self.get_dhcp_status(self.pi0_session)
        if pi0_dhcp:
            self.current_dhcp = "pi0"
            logger.info("✓ Pi0 is currently serving DHCP")
            return
        
        self.current_dhcp = None
        logger.warning("⚠️  No Pi-hole is currently serving DHCP")
    
    def run(self):
        """Main monitoring loop"""
        logger.info("=" * 60)
        logger.info("Pi-hole DHCP Failover Monitor Started")
        logger.info(f"Primary:   {PI4_HOST}")
        logger.info(f"Secondary: {PI0_HOST}")
        logger.info(f"Check interval: {CHECK_INTERVAL}s")
        logger.info("=" * 60)
        
        # Initialize state
        self.initialize_current_dhcp()
        
        logger.info("=" * 60)
        logger.info("Starting monitoring loop...")
        logger.info("=" * 60)
        
        while True:
            try:
                
                # Check both Pi-holes (3 retries each via authenticate method)
                pi4_auth = self.pi4_session.authenticate(retries=3)
                pi0_auth = self.pi0_session.authenticate(retries=3)
                
                # Handle all scenarios based on current state
                if self.current_dhcp == "pi4":
                    if not pi4_auth and not pi0_auth:
                        self.current_dhcp = None
                        logger.error("⚠️  Both Pi-holes down")
                    elif not pi4_auth and pi0_auth:
                        if self.set_dhcp_status(self.pi0_session, True):
                            self.current_dhcp = "pi0"
                            logger.warning("⚠️  Pi4 down, Pi0 now serving DHCP")
                        else:
                            logger.error("✗ Failed to enable DHCP on Pi0")
                    elif pi4_auth and not pi0_auth:
                        logger.info("✓ Pi4 serving DHCP, but Pi0 down")
                    else:  # both up
                        logger.info("✓ Pi4 serving DHCP, Pi0 ready")
                
                elif self.current_dhcp == "pi0":
                    if not pi4_auth and not pi0_auth:
                        self.current_dhcp = None
                        logger.error("⚠️  Both Pi-holes down")
                    elif not pi4_auth and pi0_auth:
                        logger.info("⚠️  Pi4 still down, Pi0 still serving DHCP")
                    elif pi4_auth and not pi0_auth:
                        if self.set_dhcp_status(self.pi4_session, True):
                            self.current_dhcp = "pi4"
                            logger.info("✓ Pi4 back up, now serving DHCP (Pi0 down)")
                        else:
                            logger.error("✗ Failed to enable DHCP on Pi4")
                    else:  # both up
                        # Switch back to pi4
                        if self.set_dhcp_status(self.pi0_session, False):
                            if self.set_dhcp_status(self.pi4_session, True):
                                self.current_dhcp = "pi4"
                                logger.info("✓ Pi4 back up, switching DHCP from Pi0 to Pi4")
                            else:
                                logger.error("✗ Failed to enable DHCP on Pi4")
                                self.set_dhcp_status(self.pi0_session, True)  # Re-enable on pi0
                        else:
                            logger.error("✗ Failed to disable DHCP on Pi0")
                
                else:  # current_dhcp == None
                    if not pi4_auth and not pi0_auth:
                        logger.error("⚠️  Both Pi-holes still down")
                    elif not pi4_auth and pi0_auth:
                        if self.set_dhcp_status(self.pi0_session, True):
                            self.current_dhcp = "pi0"
                            logger.info("✓ Pi0 back up, now serving DHCP")
                        else:
                            logger.error("✗ Failed to enable DHCP on Pi0")
                    elif pi4_auth and not pi0_auth:
                        if self.set_dhcp_status(self.pi4_session, True):
                            self.current_dhcp = "pi4"
                            logger.info("✓ Pi4 back up, now serving DHCP")
                        else:
                            logger.error("✗ Failed to enable DHCP on Pi4")
                    else:  # both up
                        if self.set_dhcp_status(self.pi4_session, True):
                            self.current_dhcp = "pi4"
                            logger.info("✓ Both Pi-holes back up, Pi4 serving DHCP")
                        else:
                            logger.error("✗ Failed to enable DHCP on Pi4")
                
                time.sleep(CHECK_INTERVAL)
                
            except KeyboardInterrupt:
                logger.info("Shutting down monitor...")
                break
            except Exception as e:
                logger.error(f"Unexpected error: {e}")
                time.sleep(CHECK_INTERVAL)


if __name__ == "__main__":
    # Validate configuration
    if not PI4_PASSWORD or not PI0_PASSWORD:
        logger.error("Passwords not configured! Set PI4_PASSWORD and PI0_PASSWORD environment variables")
        exit(1)
    
    monitor = PiHoleMonitor()
    monitor.run()
