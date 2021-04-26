#!/usr/bin/env python3

import argparse
import nmap
import os
import sys
import json

#def to sort IPs
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