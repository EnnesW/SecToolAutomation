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

def Main():
    return

if __name__ == "__main__":
    return