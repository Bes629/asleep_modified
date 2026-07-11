import argparse
import logging
import random
import socket
import struct
import sys
import time
from pathlib import Path

from countrycode import codelist, countrycode

from asleep.config import config
from asleep.geolocation import IPDenyGeolocationToIP

VALID_COUNTRIES = [c for c in codelist['country.name.en'] if c and countrycode(c, origin='country.name.en', destination='iso2c')]
ISO2C_TO_NAME = {countrycode(c, origin='country.name.en', destination='iso2c').upper(): c for c in VALID_COUNTRIES}


def resolve_country(raw):
    raw = raw.strip()
    if raw.upper() in ISO2C_TO_NAME:
        return ISO2C_TO_NAME[raw.upper()]
    for c in VALID_COUNTRIES:
        if c.lower() == raw.lower():
            return c
    return raw


def parse_ports(raw):
    result = []
    for part in raw.split(','):
        part = part.strip()
        if '-' in part:
            a, b = part.split('-', 1)
            result.extend(range(int(a), int(b) + 1))
        else:
            result.append(int(part))
    return sorted(set(result))


def _cidr_to_ips(cidr):
    net, mask = cidr.split('/')
    mask = int(mask)
    ip_int = struct.unpack('>I', socket.inet_aton(net))[0]
    start = ip_int & (0xFFFFFFFF << (32 - mask))
    end = start | ((1 << (32 - mask)) - 1)
    return [socket.inet_ntoa(struct.pack('>I', i)) for i in range(start + 1, end)]


def _expand_ips(raw):
    result = []
    for part in raw.split(','):
        part = part.strip()
        if '/' in part:
            result.extend(_cidr_to_ips(part))
        elif '-' in part:
            pieces = part.split('-', 1)
            a, b = pieces[0].strip(), pieces[1].strip()
            a_parts = a.split('.')
            b_parts = b.split('.')
            if len(a_parts) == 4 and len(b_parts) == 4:
                a_int = struct.unpack('>I', socket.inet_aton(a))[0]
                b_int = struct.unpack('>I', socket.inet_aton(b))[0]
                for i in range(a_int, b_int + 1):
                    result.append(socket.inet_ntoa(struct.pack('>I', i)))
            else:
                result.append(part)
        else:
            result.append(part)
    return sorted(set(result))


def parse_ips(raw):
    lines = []
    for part in raw.split(','):
        part = part.strip()
        if '/' in part or '-' in part:
            lines.append(part)
        else:
            lines.append(part)
    return ','.join(lines)


def get_args():
    parser = argparse.ArgumentParser(description='Dahua Brute Scanner')
    parser.add_argument('-s', dest='scan_file',
                        help='file with IP ranges to scan')
    parser.add_argument('-i', dest='ip_input',
                        help='IP targets directly, e.g. 192.168.1.0/24,10.0.0.1-10.0.0.255')
    parser.add_argument('-p', dest='ports',
                        help='ports to scan, e.g. 80-90,8080-8090,37777 (default: all)')
    parser.add_argument('-b', dest='brute_file',
                        help='file with IPs to brute, in any format')
    parser.add_argument('-l', dest='use_custom_credentials', action='store_true', default=False,
                        help='brute combinations from logins.txt and passwords.txt instead of combinations.txt')
    parser.add_argument('-m', '--masscan', dest='brute_only', action='store_false', default=True,
                        help='run Masscan and brute the results')
    parser.add_argument('-t', dest='threads', default=str(config['default_masscan_threads']),
                        help=f'number of threads for Masscan (default: %(default)s)')
    parser.add_argument('--masscan-resume', dest='masscan_resume', action='store_true', default=False,
                        help='continue paused Masscan')
    parser.add_argument('--no-snapshots', dest='snapshots_enabled', action='store_false', default=True,
                        help="don't make snapshots")
    parser.add_argument('--no-xml', dest='no_xml', action='store_true', default=False,
                        help="don't make SMART PSS .xml files")
    parser.add_argument('--dead', dest='dead_cams', action='store_true', default=False,
                        help='write not bruted cams to dead_cams.txt file')
    parser.add_argument('--country', dest='country',
                        action='store_true', default=False, help='scan by country (name or 2-letter code, e.g. Russia or RU)')
    parser.add_argument('--random-country', dest='random_country', action='store_true', default=False,
                        help='scan by random country')
    parser.add_argument('-d', '--debug', dest='debug',
                        action='store_true', default=False, help='debug output')

    if len(sys.argv) < 2:
        parser.print_help()
        sys.exit()
    args = parser.parse_args()

    city = ''
    count = 0

    config['snapshots_enabled'] = args.snapshots_enabled

    if args.ports:
        print('It\'s better to run with "-d" flag while setting custom ports!')
        print('That\'s why this forced ;)\n')
        args.debug = True
        config['global_ports'] = [str(p) for p in parse_ports(args.ports)]

    if args.ip_input:
        args.brute_only = False
        with open(config['tmp_masscan_file'], 'w') as f:
            f.write(parse_ips(args.ip_input))
        args.scan_file = config['tmp_masscan_file']

    if args.masscan_resume:
        args.brute_only = False

    if args.random_country:
        args.brute_only = False
        count = 600000
        total_count = 0
        total_range = []

        while config['max_ips'] < count:
            country = random.choice(VALID_COUNTRIES)
            for stored_c in list(dict.fromkeys(config['random_countries'])):
                if country is stored_c:
                    continue
            locator = IPDenyGeolocationToIP(country, city)
            try:
                range_list = locator.get_random_ranges(max_ips=int(count), day_ranges=True)
            except Exception as e:
                logging.debug(e)
                continue
            total_range += range_list
            slash = ['|', '/', ' ', '-']
            print(f'Searching for a bright-day ip-ranges {random.choice(slash)}', end='\r')
            time.sleep(2)
            for cidr in range_list:
                count2 = IPDenyGeolocationToIP.get_cidr_count(cidr)
                total_count += count2
            config['max_ips'] = total_count
        else:
            logging.info('Generated %s IPs from %s' % (total_count, list(dict.fromkeys(config['random_countries']))))
            config['global_country'] = random.choice(config['random_countries'])
            file = open(config['tmp_masscan_file'], 'w')
            file.write('\n'.join(total_range))
            file.close()
            args.scan_file = config['tmp_masscan_file']

    if args.country:
        args.brute_only = False
        country = input('Enter country name or code, e.g. Russia or RU (default random): ')
        if not country:
            country = random.choice(VALID_COUNTRIES)
        else:
            country = resolve_country(country)
        print('Selected %s' % country)
        config['global_country'] = country
        city = input('Enter city name (default none): ')
        count = input('Maximum IPs (default 1000000): ') or 1000000
        locator = IPDenyGeolocationToIP(country, city)
        range_list = locator.get_random_ranges(max_ips=int(count))
        total_count = 0
        for cidr in range_list:
            count3 = IPDenyGeolocationToIP.get_cidr_count(cidr)
            total_count += count3

        logging.info('Generated %s IPs from %s' % (total_count, config['global_country']))

        file = open(config['tmp_masscan_file'], 'w')
        file.write('\n'.join(range_list))
        file.close()

        args.scan_file = config['tmp_masscan_file']

    if not args.brute_file:
        args.brute_file = config['tmp_masscan_file']
    else:
        config['custom_brute_file'] = True
        config['tmp_masscan_file'] = args.brute_file

    if not Path(args.brute_file).exists() and args.brute_only:
        logging.error('File with IPs %s not found. Specify it with -b option or run without brute-only option'
                      % config['tmp_masscan_file'])
        sys.exit(0)

    if not args.scan_file and not args.brute_only and not args.masscan_resume:
        logging.error('No target file scan list')
        parser.print_help()
        sys.exit(0)

    return args
