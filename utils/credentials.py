import logging
import random
import sys
from pathlib import Path
from shutil import rmtree

from asleep.config import config


def prepare_folders_and_files():
    if config['snapshots_enabled']:
        snapshots_folder = Path(config['snapshots_folder'])
        if snapshots_folder.exists():
            rmtree(snapshots_folder)
        snapshots_folder.mkdir()
        Path(snapshots_folder / 'trash').mkdir()

    reports_folder = Path(config['reports_folder']) / Path(config['start_datetime'])
    reports_folder.mkdir(parents=True)


def setup_credentials(use_custom_credentials):
    if use_custom_credentials:
        if not Path(config['logins_file']).exists():
            logging.error(f'Logins file {config["logins_file"]} not found!')
            sys.exit(0)
        if not Path(config['passwords_file']).exists():
            logging.error(f'Passwords file {config["passwords_file"]} not found!')
            sys.exit(0)

        logins = list(map(str.strip, open(config['logins_file']).readlines()))
        passwords = list(map(str.strip, open(config['passwords_file']).readlines()))

        config['combinations'] = [(login, password) for login in logins for password in passwords]

        logging.debug(f'Logins loaded: {", ".join(logins)}')
        logging.debug(f'Passwords loaded: {", ".join(passwords)}')
    else:
        if not Path(config['logopass_file']).exists():
            logging.error(f'Login/password combinations file {config["logopass_file"]} not found!')
            sys.exit(0)

        raw_creds = list(map(str.strip, open(config['logopass_file']).readlines()))
        for raw_cred in raw_creds:
            login_pass = raw_cred.split(':')
            if len(login_pass) == 2:
                config['combinations'].append((login_pass[0], login_pass[1]))
        random.shuffle(config['combinations'])

        logging.debug(f'Login/password combinations loaded: {", ".join(raw_creds)}')
