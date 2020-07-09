#!/usr/bin/env python3

#
# Script for adding alerts from Suricata to Mikrotik routers.
#
# In suricata.yaml add another eve-log:
#  - eve-log:
#      enabled: yes
#      filetype: regular
#      filename: alerts.json
#      types:
#        - alert
#

import ssl
import librouteros
from librouteros import connect
from librouteros.query import Key
import ujson
import pyinotify
import re
from time import sleep
from datetime import datetime as dt, timedelta as td, timezone as tz
import os

# Edit these settings:
USERNAME = "suricata"
PASSWORD = "suricata123"
ROUTER_IP = "192.168.88.1"
TIMEOUT = "1d"
PORT = 8729  # api-ssl port
FILEPATH = os.path.abspath("/var/log/suricata/alerts.json")
ROUTER_LIST_NAME = "Suricata"
WAN_IP = "n/a"  # You can add your WAN IP if you are port-mirroring, so it doesn't get mistakenly added. (don't leave empty string)
LOCAL_IP_PREFIX = "192.168."
WHITELIST_IPS = (WAN_IP, LOCAL_IP_PREFIX, "127.0.0.1")
COMMENT_TIME_FORMAT = "%-d %b %Y %H:%M:%S.%f"  # Check datetime strftime formats

# Add all alerts from alerts.json on start?
# Setting this to True will start reading alerts.json from beginning
# and will add whole file to firewall when pyinotify is triggered.
# Just for testing purposes, i.e. not good for systemd service.
ADD_ON_START = False

class EventHandler(pyinotify.ProcessEvent):
    def process_IN_MODIFY(self, event):
        try:
            add_to_tik(read_json(FILEPATH))            
        except ConnectionError:
            connect_to_tik()

        check_truncated(FILEPATH)

def check_truncated(fpath):  # Check if logrotate truncated file. (Use 'copytruncate' option for this to work I guess.)
    global last_pos

    if last_pos > os.path.getsize(fpath):
        last_pos = 0

def seek_to_end(fpath):
    global last_pos

    if not ADD_ON_START:
        while True:
            try:
                last_pos = os.path.getsize(fpath)
                return

            except(FileNotFoundError):
                print(f"File: {fpath} not found. Retrying in 10 seconds..")
                sleep(10)
                continue

def read_json(fpath):
    global last_pos

    while True:
        try:
            with open(fpath, "r") as f:
                f.seek(last_pos)
                alerts = [ujson.loads(line) for line in f.readlines()]
                last_pos = f.tell()
                return alerts

        except(FileNotFoundError):
            print(f"File: {fpath} not found. Retrying in 10 seconds..")
            sleep(10)
            continue

def add_to_tik(alerts):
    global last_pos
    global time
    global api

    _address = Key("address")
    _id = Key(".id")
    _list = Key("list")

    address_list = api.path("/ip/firewall/address-list")
    resources = api.path("system/resource")

    for event in { item['src_ip'] : item for item in alerts }.values():  # Remove duplicate src_ips.
        timestamp = dt.strptime(event["timestamp"], "%Y-%m-%dT%H:%M:%S.%f%z").strftime(COMMENT_TIME_FORMAT)

        if event["src_ip"].startswith(WHITELIST_IPS):  # If you are source ip, then add destination ip.
            if event["dest_ip"].startswith(WHITELIST_IPS):  
                continue  # Skip adding anything if both source and destination ips are from WHITELIST_IPS. (just in case)

            try:
                address_list.add(list=ROUTER_LIST_NAME, address=event["dest_ip"], comment=f"[{event['alert']['gid']}:{event['alert']['signature_id']}] {event['alert']['signature']} ::: SPort: {event.get('src_port')}/{event['proto']} ::: timestamp: {timestamp}", timeout=TIMEOUT)

            except librouteros.exceptions.TrapError as e:
                if "failure: already have such entry" in str(e):  # If such entry already exists, delete it and re-add.
                    for row in address_list.select(_id, _list, _address).where(_address == event["dest_ip"], _list == ROUTER_LIST_NAME):
                        address_list.remove(row[".id"])

                    address_list.add(list=ROUTER_LIST_NAME, address=event["dest_ip"], comment=f"[{event['alert']['gid']}:{event['alert']['signature_id']}] {event['alert']['signature']} ::: SPort: {event.get('src_port')}/{event['proto']} ::: timestamp: {timestamp}", timeout=TIMEOUT)

                else:
                    raise

        else:  # Add source ip.
            try:
                address_list.add(list=ROUTER_LIST_NAME, address=event["src_ip"], comment=f"[{event['alert']['gid']}:{event['alert']['signature_id']}] {event['alert']['signature']} ::: DPort: {event.get('dest_port')}/{event['proto']} ::: timestamp: {timestamp}", timeout=TIMEOUT)

            except librouteros.exceptions.TrapError as e:
                if "failure: already have such entry" in str(e):
                    for row in address_list.select(_id, _list, _address).where(_address == event["src_ip"], _list == ROUTER_LIST_NAME):
                        address_list.remove(row[".id"])
                        
                    address_list.add(list=ROUTER_LIST_NAME, address=event["src_ip"], comment=f"[{event['alert']['gid']}:{event['alert']['signature_id']}] {event['alert']['signature']} ::: DPort: {event.get('dest_port')}/{event['proto']} ::: timestamp: {timestamp}", timeout=TIMEOUT)

                else:
                    raise
    # If router has been rebooted in past 10 minutes, add whole file, then wait for 10 minutes. (so rules don't get constantly re-added for 10 minutes)
    if check_tik_uptime(resources) and (dt.now(tz.utc) - time) / td(minutes=1) > 10:
        time = dt.now(tz.utc)
        last_pos = 0
        add_to_tik(read_json(FILEPATH))


def check_tik_uptime(resources):  # Check if router has been up for less than 10 minutes
    for row in resources:
        uptime = row["uptime"]

    if any(letter in uptime for letter in "wdh"):  # If "w", "d" or "h" is in uptime then router is obviously up for more than 10 minutes.
        return False

    if "m" in uptime:
        minutes = int(re.search("(\A|\D)(\d*)m", uptime).group(2))  # Find numbers in front of "m".
    else:
        minutes = 0

    if minutes >= 10:
        return False

    return True

def connect_to_tik():
    global api
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.set_ciphers('ADH:@SECLEVEL=0')

    while True:
        try:
            api = connect(username=USERNAME, password=PASSWORD, host=ROUTER_IP, ssl_wrapper=ctx.wrap_socket, port=PORT)
            break

        except librouteros.exceptions.TrapError as e:
            if "invalid user name or password" in str(e):
                print("Invalid username or password.")
                sleep(10)
                continue
            else:
                raise

        except ConnectionRefusedError:
            print("Connection refused. (api-ssl disabled in router?)")

        except OSError as e:
            if "[Errno 113] No route to host" in str(e):
                print("No route to host. Retrying in 10 seconds..")
                sleep(10)
                continue
            elif "[Errno 101] Network is unreachable" in str(e):
                print("Network is unreachable. Retrying in 10 seconds..")
                sleep(10)
                continue
            else:
                raise

if __name__ == "__main__":
    time = dt.now(tz.utc) - td(minutes=10)  # Set time to 10 minutes before now, so "(dt.now(tz.utc) - time) / td(minutes=1) > 10" is True the first time around.
    last_pos = 0
    seek_to_end(FILEPATH)    
    connect_to_tik()

    wm = pyinotify.WatchManager()
    handler = EventHandler()
    notifier = pyinotify.Notifier(wm, handler)
    wm.add_watch(FILEPATH, pyinotify.IN_MODIFY)
    notifier.loop()
