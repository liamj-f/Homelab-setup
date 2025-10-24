
#!/usr/bin/env python3
"""
Pi-hole DHCP Failover Monitor
Monitors Pi4 Pi-hole health and enables DHCP on Pi0 if Pi4 fails
"""

import os
import time
import requests
import logging
from datetime import datetime

# Configuration from environment variables
PI4_HOST = os.getenv('RPI4_IP', 'http://pihole.14monarch.local')
PI0_HOST = os.getenv('RPI0_IP', 'http://pih0le.14monarch.local')
PI4_PASSWORD = os.getenv('PI4_PASSWORD', '')
PI0_PASSWORD = os.getenv('PI0_PASSWORD', '')

# Monitoring settings
CHECK_INTERVAL = int(os.getenv('CHECK_INTERVAL', '60'))  # seconds
FAILURE_THRESHOLD = int(os.getenv('FAILURE_THRESHOLD', '3'))  # consecutive failures
RECOVERY_THRESHOLD = int(os.getenv('RECOVERY_THRESHOLD', '1'))  # consecutive successes

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
    
    def authenticate(self):
        """Authenticate with Pi-hole and get session ID and CSRF token"""
        try:
            # Login to get session
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
                    
            return False
                
        except requests.exceptions.RequestException:
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
        self.pi4_failure_count = 0
        self.pi4_recovery_count = 0
        self.dhcp_failover_active = False
        
        # Create sessions for each Pi-hole
        self.pi4_session = PiHoleSession(PI4_HOST, PI4_PASSWORD)
        self.pi0_session = PiHoleSession(PI0_HOST, PI0_PASSWORD)
    
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
                return config.get('active', False)
            elif response.status_code == 401:
                # Session expired, try to re-authenticate
                session.sid = None
                if session.ensure_authenticated():
                    return self.get_dhcp_status(session)
            
            return None
            
        except requests.exceptions.RequestException:
            return None
    
    def set_dhcp_status(self, session, active):
        """Enable or disable DHCP on Pi-hole"""
        try:
            if not session.ensure_authenticated():
                return False
            
            response = session.session.patch(
                f"{session.host}/api/config/dhcp",
                headers=session.get_headers(),
                json={"active": active},
                timeout=10
            )
            
            if response.status_code == 200:
                return True
            elif response.status_code == 401:
                # Session expired, try to re-authenticate
                session.sid = None
                if session.ensure_authenticated():
                    return self.set_dhcp_status(session, active)
                return False
            else:
                logger.error(f"Failed to set DHCP on {session.host}: HTTP {response.status_code}")
                return False
                
        except requests.exceptions.RequestException as e:
            logger.error(f"Failed to set DHCP on {session.host}: {e}")
            return False
    
    def enable_failover(self):
        """Enable DHCP on Pi0 (failover)"""
        logger.warning("⚠️  Pi4 DOWN - Activating DHCP failover on Pi0")
        
        if self.set_dhcp_status(self.pi0_session, True):
            self.dhcp_failover_active = True
            logger.info("✓ DHCP failover ACTIVE on Pi0")
            return True
        else:
            logger.error("✗ Failed to activate DHCP failover")
            return False
    
    def disable_failover(self):
        """Disable DHCP on Pi0 (restore primary)"""
        logger.info("✓ Pi4 RECOVERED - Restoring Pi4 as primary DHCP")
        
        if self.set_dhcp_status(self.pi0_session, False):
            self.dhcp_failover_active = False
            logger.info("✓ DHCP failover deactivated")
            return True
        else:
            logger.error("✗ Failed to deactivate DHCP failover")
            return False
    
    def run(self):
        """Main monitoring loop"""
        logger.info("=" * 60)
        logger.info("Pi-hole DHCP Failover Monitor Started")
        logger.info(f"Primary:   {PI4_HOST}")
        logger.info(f"Secondary: {PI0_HOST}")
        logger.info(f"Check interval: {CHECK_INTERVAL}s | Failure threshold: {FAILURE_THRESHOLD} | Recovery threshold: {RECOVERY_THRESHOLD}")
        logger.info("=" * 60)
        
        check_count = 0
        
        while True:
            try:
                check_count += 1
                
                # Check Pi4 health by getting DHCP status (None = Pi-hole down)
                pi4_dhcp_status = self.get_dhcp_status(self.pi4_session)
                pi4_healthy = pi4_dhcp_status is not None
                
                if pi4_healthy:
                    self.pi4_failure_count = 0
                    self.pi4_recovery_count += 1
                    
                    # If failover is active and Pi4 has recovered
                    if self.dhcp_failover_active and self.pi4_recovery_count >= RECOVERY_THRESHOLD:
                        self.disable_failover()
                        self.pi4_recovery_count = 0
                        
                else:
                    self.pi4_failure_count += 1
                    self.pi4_recovery_count = 0
                    
                    # If Pi4 has failed threshold times and failover not active
                    if not self.dhcp_failover_active and self.pi4_failure_count >= FAILURE_THRESHOLD:
                        self.enable_failover()
                
                # Log periodic status every 20 checks (10 minutes at 30s intervals)
                if check_count % 20 == 0:
                    status = "FAILOVER ACTIVE" if self.dhcp_failover_active else "NORMAL"
                    logger.info(f"[Check #{check_count}] Status: {status}")
                
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
