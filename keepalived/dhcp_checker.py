import os
import time
import requests
import logging

STATE_FILE = "/shared/keepalived.state"
PIHOLE_URL = os.getenv("PIHOLE_URL")
PASSWORD = os.getenv("PIHOLE_PASSWORD")

CHECK_INTERVAL = int(os.getenv("CHECK_INTERVAL", 30))  # Default: 30 seconds
MASTER_STABLE_SECONDS = 10
TOGGLE_COOLDOWN = 15

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)

last_dhcp_state = None
last_toggle_time = 0
master_since = None


def read_state():
    try:
        with open(STATE_FILE) as f:
            return f.read().strip()
    except:
        return "UNKNOWN"


def login(session):
    r = session.post(
        f"{PIHOLE_URL}/api/auth",
        json={"password": PASSWORD},
        timeout=5
    )
    r.raise_for_status()
    return r.json()["session"]["csrf"]


def logout(session):
    try:
        session.delete(f"{PIHOLE_URL}/api/auth", timeout=5)
    except:
        pass


def ftl_healthy(session):
    try:
        r = session.get(f"{PIHOLE_URL}/api/info", timeout=5)
        r.raise_for_status()
        return True
    except:
        return False


def set_dhcp(enable):
    global last_dhcp_state, last_toggle_time

    now = time.time()

    if last_dhcp_state == enable:
        return

    if now - last_toggle_time < TOGGLE_COOLDOWN:
        logging.warning("Toggle cooldown active — skipping change")
        return

    session = requests.Session()

    try:
        csrf = login(session)

        if not ftl_healthy(session):
            logging.error("FTL not healthy — aborting DHCP change")
            return

        logging.info("Enabling DHCP" if enable else "Disabling DHCP")

        r = session.patch(
            f"{PIHOLE_URL}/api/config/dhcp",
            json={"active": enable},
            headers={"X-CSRF-Token": csrf},
            timeout=5
        )
        r.raise_for_status()

        last_dhcp_state = enable
        last_toggle_time = now

    except Exception as e:
        logging.error(f"DHCP toggle failed: {e}")

    finally:
        logout(session)
        session.close()


while True:
    state = read_state()
    now = time.time()

    if state == "MASTER":
        if master_since is None:
            master_since = now
            logging.info("MASTER detected — starting stability timer")

        if now - master_since >= MASTER_STABLE_SECONDS:
            set_dhcp(True)
    else:
        if master_since is not None:
            logging.info("Lost MASTER state")

        master_since = None
        set_dhcp(False)

    time.sleep(CHECK_INTERVAL)