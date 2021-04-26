#!/usr/bin/env python3
import argparse
import nmap
import os
import sys
import json

# def to scan ips or ip range for active hosts
def scan_active_hosts(target)
    # list for active ips
    iplist_active = []

    nmap_args = ['-sn', '-sn -PR -PO', '-sn -PM -PY -PU']
    # 0    
        # -sn --> Ping scan; disable port scan (ICMP echo, TCP SYN 443, TCP ACK 80, ICMP timestamp --> root privileges and no other scan types (-P*) defined)
    # 1
        # -PR --> ARP ping
        # -PO --> Protocol ping (ICMP, IGMP, IP-in-IP)
    # 2 
        # -PM --> ICMP Adress mask ping
        # -PY --> SCTP init ping (IP based tel)
        # -PU --> UDP ping scan   

    # 2 scans to make sure no ip slips through the scan
    for x in range(2):
        nm = nmap.PortScanner()

        for arg in nmap_args:
            nm.scan(hosts=target, arguments=arg)

            hosts_list = [(x, nm[x]['status']['state']) for x in nm.all_hosts()]
            # Hosts that ar alive and not yet in the iplist_active, are added to the list.
            for host, status in hosts_list:
                if status == 'up' and iplist_active.__contains__(host) != True:
                    iplist_active.append(host)

    return iplist_active



# def to sort IPs
def sort_ips(ips):
    for i in range(len(ips)):
        ips[i] = "%3s.%3s.%3s.%3s" % tuple(ips[i].split("."))
        ips.sort()

    for i in range(len(ips)):
        ips[i] = ips[i].replace(" ", "")    

    return ips

def main():
    # Add parser args
    parser = argparse.ArgumentParser('Scan a network for open ports and services.')
    # Target(s)
    parser.add_argument('target', nargs=1, type=str, \
        help='Target specification. E.g.: "192.168.0.0/24"')
    # Output location for json file
    parser.add_argument('output', \
        help='Output location. E.g.: "home/filename.json"')
    parser.add_argument('-u', '--udp', action='store_true', \
        help='Perform additional UDP scan on top of TCP scan, will take considerably more time.')
    args = parser.parse_args()

    return

if __name__ == "__main__":
    main()