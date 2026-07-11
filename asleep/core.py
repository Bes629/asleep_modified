import logging
import shutil
import subprocess
import sys
from pathlib import Path
from queue import Queue

from asleep.config import config, additional_masscan_params
from asleep.brute import BruteThread
from asleep.snapshot import ScreenshotThread
from utils.masscan import masscan_parse


def _find_masscan():
    system = sys.platform
    for name in ['masscan', 'masscan.exe']:
        path = shutil.which(name)
        if path:
            return path
    if system == 'win32':
        return config.get('masscan_windows_path', 'masscan.exe')
    return config.get('masscan_nix_path', 'masscan')


def process_cameras():
    brute_file = config['tmp_masscan_file']
    hosts = masscan_parse(brute_file)
    ip_count = len(hosts)
    logging.info(f'Parsed {ip_count} IPs from Masscan output')

    if not hosts:
        return False
    if ip_count < config['default_brute_threads']:
        config['default_brute_threads'] = ip_count
        config['default_snap_threads'] = max(1, ip_count - 20)

    ips_list_file = config['ips_file'] % config['start_datetime']
    full_ips_list = Path(config['reports_folder']) / ips_list_file
    with open(full_ips_list, 'w') as file:
        for host in hosts:
            file.write(host[0] + ':' + host[1] + '\n')
    logging.info(f'IPs saved to {full_ips_list}')

    config['total'] = len(hosts)

    try:
        brute_queue = Queue()
        screenshot_queue = Queue()

        for _ in range(config['default_brute_threads']):
            brute_worker = BruteThread(brute_queue, screenshot_queue)
            brute_worker.daemon = True
            brute_worker.start()

        for _ in range(config['default_snap_threads']):
            screenshot_worker = ScreenshotThread(screenshot_queue)
            screenshot_worker.daemon = True
            screenshot_worker.start()

        logging.info(f'Starting to brute total {len(hosts)} devices\n')
        for host in hosts:
            brute_queue.put(host)

        brute_queue.join()
        screenshot_queue.join()
        print('\n')

    except Exception as e:
        logging.error(e)
        logging.info('Brute process interrupt!')
        logging.debug(config['working_hosts'])

    logging.info(f'Results: {len(hosts)} devices found, {len(config["working_hosts"])} bruted')
    logging.info(f'Made total {config["snapshots_counts"]} snapshots')


def masscan(filescan, threads, resume):
    logging.info(f'Starting scan with masscan on ports {", ".join(config["global_ports"])}')
    masscan_path = _find_masscan()

    if resume:
        logging.info('Continue last scan from paused.conf')
        cmd = [masscan_path, '--resume', 'paused.conf'] + additional_masscan_params().split()
    else:
        cmd = [
            masscan_path,
            '-p', ','.join(config['global_ports']),
            '-iL', filescan,
            '-oL', config['tmp_masscan_file'],
            '--rate', str(threads),
        ] + additional_masscan_params().split()
        cmd += ['--http-user-agent', 'Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:47.0) Gecko/20100101 Firefox/47.0']

    try:
        subprocess.run([masscan_path, '-V'], capture_output=True)
    except FileNotFoundError:
        logging.error('Masscan not found. Install it or set path in config.')
        sys.exit(0)
    except PermissionError:
        logging.error('Masscan requires root/admin privileges.')
        sys.exit(0)

    system = sys.platform
    if system != 'win32':
        cmd = ['sudo'] + cmd

    logging.info(f'Running: {" ".join(cmd)}')
    subprocess.run(cmd)
    if not Path(config['tmp_masscan_file']).exists():
        logging.error('Masscan output error, results file %s not found.' % config['tmp_masscan_file'])
        sys.exit(0)
