## Mikrocata

Python script for adding Suricata alerts into Mikrotik routers.

It's reading from Suricata eve-log file named alerts.json.
It also saves all dynamic lists you have in router and re-adds them if you reboot
router. Check mikrocata.py settings.


Requirements:
- python-librouteros (try version 3 or above if you encounter ModuleNotFoundError)
- python-ujson
- python-pyinotify

For sniff TZSP in Mangle you will also need:
- tzsp2pcap (https://github.com/thefloweringash/tzsp2pcap)
- tcpreplay (https://github.com/appneta/tcpreplay)

IMPORTANT: In suricata.yaml add another eve-log:
```
  - eve-log:
      enabled: yes
      filetype: regular
      filename: alerts.json
      types:
        - alert
```

Additionally, if using logrotate for rotating logs, you should have 'copytruncate' option in /etc/logrotate.d/suricata:
```
# Sample /etc/logrotate.d/suricata configuration file.
/var/log/suricata/*.log /var/log/suricata/*.json {
    daily
    missingok
    rotate 30
    compress
    delaycompress
    copytruncate
    sharedscripts
    postrotate
        /bin/kill -HUP `cat /run/suricata.pid 2> /dev/null` 2> /dev/null || true
    endscript
}
```

Mikrocata as systemd service (copy mikrocata.py to /usr/local/bin):

```
[Unit]
Description=Suricata to Mikrotik API in Python
After=network.target network-online.target time-sync.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/bin/python3 /usr/local/bin/mikrocata.py
Restart=always
RestartSec=3
Environment=PYTHONUNBUFFERED=1

[Install]
WantedBy=multi-user.target
```

**Port mirroring vs sniff TZSP**

You can either use port mirroring or (my preferred) sniff TZSP in Mangle.

For port mirroring all you need to do is mirror your WAN port to the one 
Suricata is listening on. Example:
```
/interface ethernet switch
set 0 mirror-source=ether1 mirror-target=ether5
```

IMHO better, safer and more flexible way is to use 'sniff TZSP' in /ip firewall mangle:

You will need previously mentioned tzsp2pcap and tcpreplay installed.
You will also need to create a dummy interface - it will be used solely for replaying
packets for Suricata.

Here is example for systemd-networkd:

/etc/systemd/network/tzsp.netdev:
```
[NetDev]
Name=tzsp0
Kind=dummy
```
/etc/systemd/network/tzsp.network:
```
[Match]
Name=tzsp*

[Link]
MTUBytes=2000

[Network]
Address=192.168.254.10/24
DHCP=no
```

We combine tzsp2pcap and tcpreplay into TZSPreplay@.service. 
Copy it into /etc/systemd/system.
```
[Unit]
Description=TZSP Replay on dev %i
After=network.target network-online.target
Requires=network-online.target

[Service]
Type=simple
ExecStart=/bin/sh -c "/usr/bin/tzsp2pcap -f | /usr/bin/tcpreplay-edit --topspeed --mtu=$(cat /sys/class/net/%I/mtu) --mtu-trunc -i %I -"
Restart=always
RestartSec=3
ProtectSystem=full
ProtectHome=true

[Install]
WantedBy=multi-user.target
```

Start it on your dummy interface (I'm using name tzsp0, you can have dummy0 or whatever):
```
systemctl enable --now TZSPreplay@tzsp0.service
```

Edit suricata.service to listen on dummy interface (notice --af-packet=*dummy_interface*):
```
# Sample Suricata systemd unit file.
[Unit]
Description=Suricata IDS/IPS daemon
After=network.target

[Service]
# Environment file to pick up $OPTIONS. On Fedora/EL this would be
# /etc/sysconfig/suricata, or on Debian/Ubuntu, /etc/default/suricata.
#EnvironmentFile=-/etc/sysconfig/suricata
#EnvironmentFile=-/etc/default/suricata
Type=simple
PIDFile=suricata/suricata.pid
ExecStart=/usr/bin/suricata --af-packet=tzsp0 -c /etc/suricata/suricata.yaml -F /etc/suricata/capture-filter.bpf --pidfile /run/suricata/suricata.pid
ExecReload=/bin/kill -USR2 $MAINPID
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
```

Finally, we can add mangle rule to Mikrotik (you can add many):
```
/ip firewall mangle
add action=sniff-tzsp chain=prerouting comment="TZSP sniffing -> Suricata" sniff-target=<IP_OF_SURICATA> sniff-target-port=37008
```

Don't forget to block this address list (first rule might be enough):
```
/ip firewall raw
add action=drop chain=prerouting comment="Suricata list -> *" in-interface=!bridge log-prefix=Suricata src-address-list=Suricata
add action=drop chain=output comment="Router -> Suricata list" dst-address-list=Suricata log=yes log-prefix=Suricata out-interface=!bridge

/ip firewall filter
add action=reject chain=forward comment="Prohibit forward to Suricata list" dst-address-list=Suricata log=yes log-prefix=PROHIBITED out-interface=!bridge reject-with=icmp-host-prohibited
```
NOTE: Above mangle rule sniffs everything in prerouting but firewall rules don't block anything from bridge, so you might as well specify WAN port in mangle or if you want to block devices from bridge, omit in/out-interface=!bridge in firewall.
--------------------------------------------------------------------
Credits for idea:
- tomfisk - https://forum.mikrotik.com/viewtopic.php?f=2&t=111727
- elmaxid - https://github.com/elmaxid/Suricata2MikroTik
