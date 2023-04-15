#!/usr/bin/python3
#CustomAgent.py
#Script to parse and send logs to Elasticsearch

import os
import sys
import json
import re
import argparse
import ipaddress
from pprint import pprint
from datetime import datetime
from subprocess import check_output
from pathlib import Path
import xmltodict
from elasticsearch import Elasticsearch, helpers
from evtx import PyEvtxParser

default_args = {
	"date_fmts": [
		"%m/%d/%Y %H:%M:%S %p",
		"%m/%d/%Y %H:%M %p",
		"%Y-%m-%dT%H:%M:%S.%fZ"
	]
}

def check_vars(file, ip, port, cert, type):
    print("Checking vars!")
    if not os.path.isfile(file):
        print("[ERROR] Specified event logs file path does not exists!")
        exit()
    
    if not 0 <= port <= 65535:
        print("[ERROR] Invalid port!")
        exit()
    
    if not os.path.isfile(cert):
        print("[ERROR] Specified certificate file path does not exists!")
        exit()

    conversion_type = ["evtx", "log", "apache_access_logs", "apache_error_logs"]
    if not type in conversion_type:
        print("[ERROR] Conversion type is incorrect please choose correct option!")
        exit()
        
    try:
        ipaddress.ip_address(ip)
    except Exception as e:
        print("[ERROR] IP Address is not valid!")
        exit()

def ingestion(file, type, ip, port, index, user, pwd, cert, size, timestampfile):
    index = index.lower()
    if type == "evtx":
        evtx_to_elk(file, ip, port, index, user, pwd, cert, size)
    elif type == "log":
        log_to_elk(file, ip, port, index, user, pwd, cert, size)
    elif type == "apache_access_logs":
        apache_access_to_elk(file, ip, port, index, user, pwd, cert, size, timestampfile)
    elif type == "apache_error_logs":
        apache_error_to_elk(file, ip, port, index, user, pwd, cert, size, timestampfile)
    else:
        exit()

def evtx_to_elk(file, ip, port, index, user, pwd, cert, size):
    eparser = PyEvtxParser(file)
    bulk = []
    count = 0
    for record in eparser.records():
        eventlog = {}
        eventlogdata = xmltodict.parse(record['data'])
        eventlogdata = json.loads(json.dumps(eventlogdata))
        eventlog = validate_event(eventlogdata)
        eventlog = correct_data_field_structure(eventlog)
        eventlog['file_name'] = file
        bulk.append({
            "_index": index,
            "@timestamp": eventlog['Event']['System']['TimeCreated']['@SystemTime'],
            "body": eventlog
        })
        if len(bulk) == size:
            send_logs(ip, port, user, pwd, cert, bulk)
            count += size
            bulk.clear()
    send_logs(ip, port, user, pwd, cert, bulk)
    count += len(bulk)
    print(f"{count} Windows event logs sent successfully at index: \'{index}\'!")

def log_to_elk(file, ip, port, index, user, pwd, cert, size):
    bulk = []
    count = 0
    with open(file, 'r') as log_file:
        for line in log_file:
            bulk.append({
                '_index': index,
                '_body': line
            })
            if len(bulk) == size:
                send_logs(ip, port, user, pwd, cert, bulk)
                count += size
                bulk.clear()
    send_logs(ip, port, user, pwd, cert, bulk)
    count += len(bulk)
    print(f"{count} Linux logs send successfully at index: \'{index}\'!")         

def apache_access_to_elk(file, ip, port, index, user, pwd, cert, size, timestampfile):
    bulk = []
    data = []
    count = 0
    for line in open(file, 'r'):
        data.append(json.loads(line))
    new_data = check_timestamp(data, timestampfile)
    for line in new_data:
        bulk.append({
            '_index': index,
            '@timestamp': line['timestamp'],
            '_body': line
        })
        if len(bulk) == size:
            send_logs(ip, port, user, pwd, cert, bulk)
            count += size
            bulk.clear()
    send_logs(ip, port, user, pwd, cert, bulk)
    count += len(bulk)
    print(f"{count} Apache Access logs send successfully at index: \'{index}\'!")

def apache_error_to_elk(file, ip, port, index, user, pwd, cert, size, timestampfile):
    bulk = []
    log_entries = []
    count = 0
    pattern = re.compile(r'^\[(?P<timestamp>.*?)\] \[(?P<severity>.*?)\] \[(?P<module>.*?)\] \[pid (?P<pid>.*?)\]( \[client (?P<client>.*?)\])? (?P<message>.*)$')

    with open(file, 'r') as f:
        log_data = f.readlines()
    for line in log_data:
        match = pattern.match(line)
        if match:
            log_entry = match.groupdict()
            log_entries.append(log_entry)
    data = json.dumps(log_entries)
    json_data = json.loads(data)
    new_data = check_timestamp(json_data, timestampfile)
    for line in new_data:
        bulk.append({
            '_index': index,
            '@timestamp': line['timestamp'],
            '_body': line
        })
        if len(bulk) == size:
            send_logs(ip, port, user, pwd, cert, bulk)
            count += size
            bulk.clear()
    send_logs(ip, port, user, pwd, cert, bulk)
    count += len(bulk)
    print(f"{count} Apache Error logs send successfully at index: \'{index}\'!")

def send_logs(ip, port, user, pwd, cert, bulk):
    try:
        client = Elasticsearch(
            "https://{}:{}".format(ip, port),
            ca_certs = cert,
            basic_auth = (user, pwd)
        )
        helpers.bulk(client, bulk)
    except Exception as e:
        print("[ERROR] ", e)

def check_timestamp(data, timestampfile):
    if os.path.isfile(timestampfile):
        with open(timestampfile, "r") as f:
            last_sent_timestamp = f.read().strip()
    else:
        last_sent_timestamp = None

    new_log_entries = []
    for entry in data:
        entry_timestamp = entry['timestamp']
        if last_sent_timestamp is None or entry_timestamp > last_sent_timestamp:
            new_log_entries.append(entry)

    current_timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")
    with open(timestampfile, "w") as f:
        f.write(current_timestamp)
    return new_log_entries

def validate_event(event):
    if ('EventData' in event['Event']) and not (event['Event']['EventData'] == None):
        if ('Data' in event['Event']['EventData']) and not (event['Event']['EventData']['Data'] == None):
            if not ('@Name' in event['Event']['EventData']['Data']):
                try:
                    event['Event']['EventData']['Data'][0]['@Name']
                except:
                    group_data = [{'@Name': 'param1', '#text': str(event['Event']['EventData']['Data'])}]
                    event['Event']['EventData']['Data'] = group_data
    if ('System' in event['Event']) and not (event['Event']['System'] == None):
        if ('EventID' in event['Event']['System']) and not (event['Event']['System'] == None):
            try:
                event['Event']['System']['EventID']['@Qualifiers']
            except:
                group_data = {'@Qualifiers': 'Unknown', '#text': event['Event']['System']['EventID']}
                event['Event']['System']['EventID'] = group_data
    return event

def correct_data_field_structure(event):
    data = {}
    try:
        if ('Data' in event['Event']['EventData']) and not (event['Event']['EventData']['Data'] == None):
            for field in range(0,len(event['Event']['EventData']['Data'])):
                field_name = event['Event']['EventData']['Data'][field]['@Name']
                already_done = False
                try:
                    if 'time' in field_name.lower():
                        temp = event['Event']['EventData']['Data'][field]['#text'].replace("?", "")
                        if '.' in temp and temp[-1] == 'Z' and len(temp) - temp.index('.') - 2 == 9 : temp = temp[:temp.index('.') + 7] + 'Z'
                        if is_date(temp):
                            text = get_date(temp)
                            already_done = True
                except: pass
                if not already_done:
                    try: text = event['Event']['EventData']['Data'][field]['#text']
                    except: text = '-'
                data[field_name] = text
    except:
        return event
    event['Event']['EventData']['Data'] = data	
    return event

def is_date(mstr):
        validate = False
        for fmt in default_args.get("date_fmts"):
            try:
                datetime.strptime(mstr, fmt)
                validate = True
                break
            except Exception:
                pass
        if not validate:
            print("[Warning] Exception occurred in is_date while validating date {}...".format(mstr))
        return validate


def get_date(mstr):
        valid_date = "-"
        validate = False
        for fmt in default_args.get("date_fmts"):
            try:
                valid_date = datetime.strptime(mstr, fmt)
                validate = True
                break
            except Exception:
                pass
        if not validate:
            print("[Warning] Exception occurred in is_date while validating date {}...".format(mstr))
        return valid_date


if __name__ == '__main__':
    parser = argparse.ArgumentParser('CustomAgent.py')
    parser.add_argument('file', type=str, metavar='<file_path>', help='path to event file')
    parser.add_argument('type', type=str, metavar='<file_type>', help='file type to parse and ingest, options are "evtx", "log", "apache_access_logs", "apache_error_logs"')
    parser.add_argument('--ip', type=str, default='127.0.0.1', metavar='<ip_address>', help='ip address of elasticsearch server, default is \'localhost\'')
    parser.add_argument('--port', type=int, default=9200, metavar='<port>', help='port on which elasticsearch server is running, default is \'9200\'')
    parser.add_argument('index', type=str, metavar='<elasticsearch_index>', help='name of the elasticsearch index')
    parser.add_argument('--user', type=str, default='elastic', metavar='<elasticsearch_user>', help='name of the elasticsearch user, default is \'elastic\'')
    parser.add_argument('pwd', type=str, metavar='<elasticsearch_password>', help='password of the elasticsearch user')
    parser.add_argument('cert', type=str, metavar='<elasticsearch_http_ca_cert_path>', help='path to elasticsearch http ca certificate')
    parser.add_argument('--size', type=int, default=100, metavar='<queue_size>', help='size of the queue, default is \'100\'')
    parser.add_argument('--timestampfile', type=str, default='timestampfile.txt', metavar='<timestamp_file_path>', help='path to the timestamp file, default is in cwd: timestampfile.txt')

    if len(sys.argv) < 4:
        parser.print_help()
        exit()

    vars = parser.parse_args()
    check_vars(vars.file, vars.ip, vars.port, vars.cert, vars.type)
    ingestion(vars.file, vars.type, vars.ip, vars.port, vars.index, vars.user, vars.pwd, vars.cert, vars.size, vars.timestampfile)