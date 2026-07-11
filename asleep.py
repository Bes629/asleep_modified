#!/usr/bin/env python3
import logging
import sys
from pathlib import Path

from colorama import Fore, init

from asleep.config import config
from asleep.core import masscan, process_cameras
from asleep import export
from utils.args import get_args
from utils.credentials import setup_credentials, prepare_folders_and_files
from utils.logo import get_figlet_logo


def main():
    init()
    print(Fore.RED + get_figlet_logo('asleep') + Fore.RESET)
    print(Fore.RED + 'Modified by Bes  t.me/SniiCam\n' + Fore.RESET)

    args = get_args()
    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)
    else:
        logging.getLogger().propagate = False

    setup_credentials(args.use_custom_credentials)
    prepare_folders_and_files()

    if not args.brute_only:
        masscan(args.scan_file, args.threads, args.masscan_resume)

    process_cameras()

    if not args.no_xml and len(config['working_hosts']) > 0:
        export.save_xml(config['working_hosts'])
    export.save_csv()

    if args.dead_cams:
        from utils.masscan import masscan_parse
        hosts = masscan_parse(config['tmp_masscan_file'])
        export.dead_cams(hosts)

    if Path(config['snapshots_folder']).exists():
        c_error = False
        if config['global_country']:
            try:
                Path(config['snapshots_folder']).rename(f'{config["global_country"]}_{config["start_datetime"]}')
            except Exception:
                c_error = True
        if not config['global_country'] or c_error:
            Path(config['snapshots_folder']).rename(f'Snapshots_{config["start_datetime"]}')


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print('\n')
        logging.info('Interrupted by user')
        sys.exit(0)
