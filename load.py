#!/usr/bin/env python
# coding: utf-8


import json
import pandas
import datetime
import time
import re
import ipaddress
import math


def sort_by_field(sort_list, sort_field):
    sorted_list = sorted(sort_list, key=lambda k: k[sort_field])
    return sorted_list


def check_ip_format(ip_address):
    version = ipaddress.ip_address(ip_address).version
    if version == 6:
        # ipv6
        addr = ipaddress.ip_address(ip_address)
        #int_ip = int(ipaddress.IPv6Address(addr.exploded))
        return addr.exploded
    else:
        # ipv4
        #int_ip = int(ipaddress.IPv4Address(ip_address))
        return ip_address

def load_conn(f, idx, attacker_ip):
    cnt = 0
    conn = []
    anomaly_idx = []
    for line in f.readlines():
        tmp = {}
        # destination ip = attacker ip -> anomaly
        log = json.loads(line)
        if '_source' in log.keys():
            keys = [
                'ts', 'id_orig_h', 'id_orig_p', 'id_resp_h', 'id_resp_p',
                'uid', 'service', 'proto', 'duration', 'orig_bytes',
                'resp_bytes', 'orig_ip_bytes', 'resp_pkts', 'resp_ip_bytes'
            ]
            check = [
                'duration', 'orig_bytes', 'resp_bytes', 'orig_ip_bytes',
                'resp_pkts', 'resp_ip_bytes'
            ]
            for key in keys:
                if key in log['_source'].keys():
                    if key == 'ts':               
                        tmp['time'] = datetime.datetime.strptime(
                                (log['_source']['@timestamp'].replace(
                                    'T', ' '))[:-1], '%Y-%m-%d %H:%M:%S.%f')
                    elif key == 'id_orig_h':
                        ipa = check_ip_format(log['_source'][key])
                        tmp[key] = ipa
                    elif key == 'id_resp_h':
                        ipa = check_ip_format(log['_source'][key])
                        if str(ipa).strip() == attacker_ip:
                            anomaly_idx.append(idx)
                        tmp[key] = ipa
                    elif key in check:
                        # not exist -> replace it to 0
                        if log['_source'][key] == '-':
                            tmp[key] = 0
                        else:
                            tmp[key] = log['_source'][key]
                    else:
                        tmp[key] = log['_source'][key]

            # add an index to each log
            tmp['idx'] = idx
            idx += 1

        conn.append(tmp)
    conn = sort_by_field(conn,'time')
    return conn, anomaly_idx, idx

def load_system(f, idx):
    # system
    system = []
    # network
    security_5156 = []
    sysmon_3 = []
    # traceback
    sysmon = []
    microsoft_powershell = []
    powershell = []
    security_trace = []
    for line in f.readlines():
        tmp = {}
        log = json.loads(line)
        # system
        system.append(log)
        # traceback
        if log['_source']['winlog']['provider_name']=='Microsoft-Windows-Sysmon':
            sysmon.append(log['_source'])
        elif log['_source']['winlog']['provider_name']=='Microsoft-Windows-PowerShell':
            microsoft_powershell.append(log['_source'])
        elif log['_source']['winlog']['provider_name']=='PowerShell':
            powershell.append(log['_source'])
        elif 'Security' in log['_source']['winlog']['provider_name']:
            security_trace.append(log['_source'])
        # network map to security and sysmon
        if '_source' in log.keys():
            if 'event' in log['_source'].keys():
                if log['_source']['event'][
                            'provider'] == 'Microsoft-Windows-Security-Auditing':
                        # check security event code 5156
                        if log['_source']['event']['code'] == 5156:
                            tmp['time'] = datetime.datetime.strptime(
                                (log['_source']['@timestamp'].replace(
                                    'T', ' '))[:-1], '%Y-%m-%d %H:%M:%S.%f')
                            tmp['ProcessID'] = log['_source']['winlog'][
                                'event_data']['ProcessID']
                            if 'Protocol' in log['_source']['winlog'][
                                    'event_data'].keys():
                                if log['_source']['winlog']['event_data'][
                                        'Protocol'] == '6':
                                    tmp['Protocol'] = 'tcp'
                                elif log['_source']['winlog']['event_data'][
                                        'Protocol'] == '17':
                                    tmp['Protocol'] = 'udp'
                                elif (log['_source']['winlog']['event_data']
                                      ['Protocol'] == '58'
                                      or log['_source']['winlog']['event_data']
                                      ['Protocol'] == '2'):
                                    tmp['Protocol'] = 'icmp'
                                else:
                                    tmp['Protocol'] = log['_source']['winlog'][
                                        'event_data']['Protocol']
                            tmp['SourceIp']= check_ip_format(
                                log['_source']['winlog']['event_data']
                                ['SourceAddress'])
                            tmp['SourcePort'] = log['_source']['winlog'][
                                'event_data']['SourcePort']
                            tmp['DestinationIp'] = check_ip_format(
                                log['_source']['winlog']['event_data']
                                ['DestAddress'])
                            tmp['DestinationPort'] = log['_source']['winlog'][
                                'event_data']['DestPort']
                            #### message
                            tmp['message'] = log['_source']['message']
                            ####
                            tmp['idx'] = idx
                            tmp['record_id'] = log['_source']['winlog']['record_id']
                            tmp['ProcessId'] = log['_source']['winlog']['event_data']['ProcessID']
                            security_5156.append(tmp)
                elif 'provider' in log['_source']['event']:
                    if log['_source']['event'][
                            'provider'] == 'Microsoft-Windows-Sysmon':
                        # check sysmon event code 3
                        if log['_source']['event']['code'] == 3:
                            keys = [
                                'UtcTime', 'ProcessId', 'Protocol', 'SourceIp',
                                'SourcePort', 'DestinationIp',
                                'DestinationPort'
                            ]
                            message = log['_source']['message'].split('\n')
                            for msg in message:
                                content = msg.split(':', 1)
                                if content[0] == 'UtcTime':
                                    tmp['time'] = datetime.datetime.strptime(
                                        (log['_source']['@timestamp'].replace(
                                            'T',
                                            ' '))[:-1], '%Y-%m-%d %H:%M:%S.%f')
                                elif content[0] == 'SourceIp' or content[
                                        0] == 'DestinationIp':
                                    tmp[content[0]] = check_ip_format(
                                        str(content[1].strip()))
                                elif content[0] in keys:
                                    tmp[content[0]] = content[1].strip()
                            tmp['record_id'] = log['_source']['winlog']['record_id']
                            tmp['idx'] = idx
                            sysmon_3.append(tmp)
        idx += 1
    return system, sysmon_3, security_5156, sysmon, microsoft_powershell,powershell,security_trace, idx
