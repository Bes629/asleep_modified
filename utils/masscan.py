import re

from asleep.config import config


def masscan_parse(brute_file):
    with open(brute_file, 'r') as file:
        hosts = []
        q = False
        for line in file.readlines():
            new_ips = re.findall(r'[0-9]+(?:\.[0-9]+){3}', line)
            port_re = re.search(r'tcp (\d+)', line)
            if port_re:
                port = port_re.group(1)
            elif not port_re and config['custom_brute_file']:
                port = config['global_ports'][0]
            else:
                port = '37777'
            for p in port:
                for ip in new_ips:
                    if config['custom_brute_file']:
                        hosts.append([ip, p])
                    else:
                        hosts.append([ip, port])
                        q = True
                if q:
                    break
    return hosts
