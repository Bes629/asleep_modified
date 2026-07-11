import logging
import os
import time

from pocs.base import DEFAULT_PORTS

DATA_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'data')

config = {
    'combinations': [],
    'top_logopass': {},
    'working_hosts': [],
    'random_countries': [],
    'snapshots_counts': 0,
    'custom_brute_file': False,
    'snapshots_enabled': True,
    'ch_count': 0,
    'max_ips': 0,
    'index': 0,
    'total': 0,
    'state': 0.0,
    'global_country': '',
    'global_ports': [str(p) for p in DEFAULT_PORTS],

    'tmp_masscan_file': 'res_scan.txt',
    'logins_file': os.path.join(DATA_DIR, 'logins.txt'),
    'passwords_file': os.path.join(DATA_DIR, 'passwords.txt'),
    'logopass_file': os.path.join(DATA_DIR, 'combinations.txt'),
    'results_file': 'results_%s.csv',
    'ips_file': 'ips_%s.txt',
    'xml_file': 'smart_pss_%s.xml',

    'snapshots_folder': 'tmp_snapshots',
    'reports_folder': 'reports',

    'masscan_windows_path': 'masscan.exe',
    'masscan_nix_path': 'masscan',

    'default_masscan_threads': 3000,
    'default_brute_threads': 160,
    'default_snap_threads': 140,
    'max_xml_entries': 255,

    'start_datetime': time.strftime('%Y.%m.%d-%H.%M.%S'),
}

logging.basicConfig(level=logging.INFO, format='[%(asctime)s] [%(levelname)s] %(message)s')
logging.getLogger('requests').setLevel(logging.INFO)


def update_status():
    config['index'] += 1
    config['state'] = round(10 * (config['index'] / config['total']), 2)


def additional_masscan_params():
    return '--randomize-hosts -sS'
