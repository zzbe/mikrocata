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

import ssl
import os
import re
from time import sleep
from datetime import datetime as dt
from datetime import timedelta as td
from datetime import timezone as tz
import pyinotify
import ujson
import librouteros
from librouteros import connect
from librouteros.query import Key

# ------------------------------------------------------------------------------
# Edit these settings:

USERNAME = "suricata"
PASSWORD = "suricata123"
ROUTER_IP = "192.168.88.1"
TIMEOUT = "1d"
PORT = 8729  # api-ssl port
FILEPATH = os.path.abspath("/var/log/suricata/alerts.json")
BLOCK_LIST_NAME = "Suricata"

# You can add your WAN IP, so it doesn't get mistakenly blocked.
# (don't leave empty string)
WAN_IP = "n/a"
LOCAL_IP_PREFIX = "192.168."
WHITELIST_IPS = (WAN_IP, LOCAL_IP_PREFIX, "127.0.0.1")
COMMENT_TIME_FORMAT = "%-d %b %Y %H:%M:%S.%f"  # See datetime strftime formats.

# Save Mikrotik address lists to a file and reload them on Mikrotik reboot.
# You can add additional list(s), e.g. [BLOCK_LIST_NAME, "blocklist1", "list2"]
SAVE_LISTS = [BLOCK_LIST_NAME]

# (!) Make sure you have privileges (!)
SAVE_LOCATION = os.path.abspath("/var/log/mikrotik/lists.json")

# Add all alerts from alerts.json on start?
# Setting this to True will start reading alerts.json from beginning
# and will add whole file to firewall when pyinotify is triggered.
# Just for testing purposes, i.e. not good for systemd service.
ADD_ON_START = False

# ------------------------------------------------------------------------------


class EventHandler(pyinotify.ProcessEvent):
    def process_IN_MODIFY(self, event):
        try:
            add_to_tik(read_json(FILEPATH))
        except ConnectionError:
            connect_to_tik()

        check_truncated(FILEPATH)


# Check if logrotate truncated file. (Use 'copytruncate' option.)
def check_truncated(fpath):
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

            except FileNotFoundError:
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

        except FileNotFoundError:
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
    # Remove duplicate src_ips.
    for event in {item['src_ip']: item for item in alerts}.values():
        timestamp = dt.strptime(event["timestamp"],
                                "%Y-%m-%dT%H:%M:%S.%f%z").strftime(
                                    COMMENT_TIME_FORMAT)

        if event["src_ip"].startswith(WHITELIST_IPS):
            if event["dest_ip"].startswith(WHITELIST_IPS):
                continue

            try:
                address_list.add(list=BLOCK_LIST_NAME, address=event["dest_ip"],
                                 comment=f"""[{event['alert']['gid']}:{
                                 event['alert']['signature_id']}] {
                                 event['alert']['signature']} ::: SPort: {
                                 event.get('src_port')}/{
                                 event['proto']} ::: timestamp: {
                                 timestamp}""", timeout=TIMEOUT)

            except librouteros.exceptions.TrapError as e:
                if "failure: already have such entry" in str(e):
                    for row in address_list.select(_id, _list, _address).where(
                            _address == event["dest_ip"],
                            _list == BLOCK_LIST_NAME):
                        address_list.remove(row[".id"])

                    address_list.add(list=BLOCK_LIST_NAME,
                                     address=event["dest_ip"],
                                     comment=f"""[{event['alert']['gid']}:{
                                     event['alert']['signature_id']}] {
                                     event['alert']['signature']} ::: SPort: {
                                     event.get('src_port')}/{
                                     event['proto']} ::: timestamp: {
                                     timestamp}""", timeout=TIMEOUT)

                else:
                    raise

        else:
            try:
                address_list.add(list=BLOCK_LIST_NAME, address=event["src_ip"],
                                 comment=f"""[{event['alert']['gid']}:{
                                 event['alert']['signature_id']}] {
                                 event['alert']['signature']} ::: DPort: {
                                 event.get('dest_port')}/{
                                 event['proto']} ::: timestamp: {
                                 timestamp}""", timeout=TIMEOUT)

            except librouteros.exceptions.TrapError as e:
                if "failure: already have such entry" in str(e):
                    for row in address_list.select(_id, _list, _address).where(
                            _address == event["src_ip"],
                            _list == BLOCK_LIST_NAME):
                        address_list.remove(row[".id"])

                    address_list.add(list=BLOCK_LIST_NAME,
                                     address=event["src_ip"],
                                     comment=f"""[{event['alert']['gid']}:{
                                     event['alert']['signature_id']}] {
                                     event['alert']['signature']} ::: DPort: {
                                     event.get('dest_port')}/{
                                     event['proto']} ::: timestamp: {
                                     timestamp}""", timeout=TIMEOUT)

                else:
                    raise

    # If router has been rebooted in past 10 minutes, add saved list(s),
    # then wait for 10 minutes. (so rules don't get constantly re-added)
    if (check_tik_uptime(resources)
            and (dt.now(tz.utc) - time) / td(minutes=1) > 10):
        time = dt.now(tz.utc)
        add_saved_lists(address_list)

    if not check_tik_uptime(resources):
        save_lists(address_list)


def check_tik_uptime(resources):
    for row in resources:
        uptime = row["uptime"]

    if any(letter in uptime for letter in "wdh"):
        return False

    if "m" in uptime:
        minutes = int(re.search(r"(\A|\D)(\d*)m", uptime).group(2))
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
            api = connect(username=USERNAME, password=PASSWORD, host=ROUTER_IP,
                          ssl_wrapper=ctx.wrap_socket, port=PORT)
            break

        except librouteros.exceptions.TrapError as e:
            if "invalid user name or password" in str(e):
                print("Invalid username or password.")
                sleep(10)
                continue

            raise

        except ConnectionRefusedError:
            print("Connection refused. (api-ssl disabled in router?)")
            sleep(10)
            continue

        except OSError as e:
            if e.errno == 113:
                print("No route to host. Retrying in 10 seconds..")
                sleep(10)
                continue

            if e.errno == 101:
                print("Network is unreachable. Retrying in 10 seconds..")
                sleep(10)
                continue

            raise


def save_lists(address_list):
    _address = Key("address")
    _list = Key("list")
    _timeout = Key("timeout")
    _comment = Key("comment")
    os.makedirs(os.path.dirname(SAVE_LOCATION), exist_ok=True)

    with open(SAVE_LOCATION, "w") as f:
        for save_list in SAVE_LISTS:
            for row in address_list.select(_list, _address, _timeout,
                                           _comment).where(_list == save_list):
                f.write(ujson.dumps(row) + "\n")


def add_saved_lists(address_list):
    with open(SAVE_LOCATION, "r") as f:
        addresses = [ujson.loads(line) for line in f.readlines()]

    for row in addresses:
        cmnt = row.get("comment")
        if cmnt is None:
            cmnt = ""
        try:
            address_list.add(list=row["list"], address=row["address"],
                             comment=cmnt, timeout=row["timeout"])

        except librouteros.exceptions.TrapError as e:
            if "failure: already have such entry" in str(e):
                continue

            raise


if __name__ == "__main__":
    time = dt.now(tz.utc) - td(minutes=10)
    last_pos = 0
    seek_to_end(FILEPATH)
    connect_to_tik()

    wm = pyinotify.WatchManager()
    handler = EventHandler()
    notifier = pyinotify.Notifier(wm, handler)
    wm.add_watch(FILEPATH, pyinotify.IN_MODIFY)

    try:
        notifier.loop()
    except librouteros.exceptions.ConnectionClosed:
        connect_to_tik()
