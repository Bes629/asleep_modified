import logging
import os
import xml.etree.ElementTree as ElTree

from asleep.config import config


def save_xml(results):
    host_parts = []
    host_buf = []
    for host in results:
        host_buf.append(host)
        if len(host_buf) == config['max_xml_entries']:
            host_parts.append(host_buf)
            host_buf = []
    host_parts.append(host_buf)
    short_name = False
    if len(host_parts) == 1:
        short_name = True
    i = 0
    for part in host_parts:
        if len(part) == 0:
            continue
        i += 1
        root = ElTree.Element('Organization')
        dev_list = ElTree.SubElement(root, 'Department')
        dev_list.set('name', 'root')
        for host in part:
            device = ElTree.SubElement(dev_list, 'Device')
            device.set('title', '%s_%s:%s' % (host[0], host[2], host[3]))
            device.set('ip', host[0])
            device.set('port', str(host[1]))
            device.set('user', host[2])
            device.set('password', host[3])
        if short_name:
            filename = 'save.xml'
        else:
            filename = 'save_part_%d.xml' % i
        full_filename = os.path.join(config['reports_folder'], filename)
        out_xml = open(full_filename, 'w')
        out_xml.write(ElTree.tostring(root).decode('ascii'))
        out_xml.close()
        logging.info('Saved SMART PSS XML to %s' % full_filename)


def save_csv():
    path = os.path.join(os.getcwd(), config['reports_folder'], config['start_datetime'])
    os.makedirs(path, exist_ok=True)
    full_filename = os.path.join(path, config['results_file'] % config['start_datetime'])
    mic_filename = os.path.join(path, 'mic_' + config['results_file'] % config['start_datetime'])
    no_mic_filename = os.path.join(path, 'no_mic_' + config['results_file'] % config['start_datetime'])
    with open(full_filename, 'a') as results_csv, \
         open(mic_filename, 'a') as mic_csv, \
         open(no_mic_filename, 'a') as no_mic_csv:
        for host in config['working_hosts']:
            server_ip, port, login, password, dahua = host
            mic = 'YES' if dahua.has_mic else 'NO'
            string = '%s,%s,%s,%s,%d,%s,%s\n' % (server_ip, port, login, password, dahua.channels_count, dahua.model, mic)
            results_csv.write(string)
            if dahua.has_mic:
                mic_csv.write(string)
            else:
                no_mic_csv.write(string)
            logopass = '%s:%s' % (login, password)
            if logopass not in config['top_logopass']:
                config['top_logopass'][logopass] = 1
            else:
                config['top_logopass'][logopass] += 1
    logging.info(f'Saved: {full_filename}')
    logging.info(f'Saved mic cameras: {mic_filename}')
    logging.info(f'Saved no-mic cameras: {no_mic_filename}')


def dead_cams(hosts):
    res_cams = []
    raw_cams = []
    for ip in config['working_hosts']:
        res_cams.append(ip[0])
    for host in hosts:
        raw_cams.append(host[0])
    dead_c = [[x for x in raw_cams if x not in res_cams], [x for x in res_cams if x not in raw_cams]]

    with open('dead_cams.txt', 'w') as dead:
        for lst in dead_c:
            for cam in lst:
                dead.write(str(cam) + '\n')
