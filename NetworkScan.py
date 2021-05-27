#!/usr/bin/env python3
import argparse
import nmap
import os
import json
import ipcalc
import re
import datetime
import time
import shodan
from bs4 import BeautifulSoup
import requests

class NetworkScan(object):
    def __init__(self):
        self.outputfile = "NetworkScan_" + str(datetime.datetime.now()).replace(" ", "_") + ".json"
        self.udp = False
        self.API_KEY = ""
        self.results = []

    def argparse(self):
        parser = argparse.ArgumentParser('Scan an internal or external network for open ports and services.')
        parser.add_argument('-t', '--target', required=True, type=str, \
            help='Target specification. E.g.: "192.168.0.0/24". CIDR notation, a network range or a single ip are possible.')
        parser.add_argument('-m', '--mode', required=True, type=str, \
            help='Internal or external scan. Choices: "i" for internal or "e" for external.')
        parser.add_argument('-u', '--udp', action='store_true', \
            help='Perform UDP port scan.')
        parser.add_argument('-API_KEY', '--API_KEY', required=False, type=str, \
            help='The API-key for the Shodan API.')
        args = parser.parse_args()

        if args.udp == True: self.udp = True
        if args.API_KEY: self.API_KEY = args.API_KEY

        self.main(args.target, args.mode)

    def main(self, target, mode):
        # Regex to detect input type
        CIDR = r"^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])(\/(3[0-2]|[1-2][0-9]|[0-9]))$"
        oneip = r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$"

        if re.match(CIDR, target) or re.match(oneip, target):
            if mode == 'i':                    
                print("\n[+] STARTING INTERNAL NETWORK SCAN.\n")
                time.sleep(3)
                for ip in ipcalc.Network(target):
                    print(f"\n------------------------------------\nScanning {ip}\n------------------------------------")  
                    self.scanInternal(str(ip))

            elif mode == 'e':
                print("\n[+] STARTING EXTERNAL NETWORK SCAN.\n")
                time.sleep(3)
                for ip in ipcalc.Network(target):  
                    print(f"\n------------------------------------\nScanning {ip}\n------------------------------------")                   
                    self.scanExternal(str(ip))   

            else: print("\n[!][!] NOT A VALID MODE, USE 'i' FOR INTERNAL NETWORK SCAN OR USE 'e' FOR EXTERNAL NETWORK SCAN.\n")

        else:
            try:
                ipsplit = target.split('-')
                start = ipsplit[0].split('.')               
                endnumb = int(start[len(start)-1:][0])
                begin = start[:-1]
                ipstart = ""

                for xstring in begin:
                    ipstart = ipstart + xstring + "."

                if mode == 'i':
                    print("\n[+] STARTING INTERNAL NETWORK SCAN.\n")
                    time.sleep(3)
                    while endnumb <= int(ipsplit[1]):
                        ip = ipstart + str(endnumb) 
                        print(f"\n------------------------------------\nScanning {ip}\n------------------------------------")                       
                        self.scanInternal(ip)
                        endnumb += 1

                elif mode == 'e':
                    print("\n[+] STARTING EXTERNAL NETWORK SCAN.\n")
                    time.sleep(3)   
                    while endnumb <= int(ipsplit[1]):
                        ip = ipstart + str(endnumb)    
                        print(f"\n------------------------------------\nScanning {ip}\n------------------------------------")                           
                        self.scanExternal(ip)
                        endnumb += 1

                else: print("\n[!][!] NOT A VALID MODE, USE 'i' FOR INTERNAL NETWORK SCAN AND USE 'e' FOR EXTERNAL NETWORK SCAN.\n")
            except Exception as e: print("\n[!][!] NOT A VALID IP RANGE OR SUBNET.\n")

        self.output()

    def nmapScan(self, target):
        print("[x] NMAP ...")

        args = "-sS"
        if self.udp == True: args = "-sS -sU"
        nm = nmap.PortScanner()
        nm.scan(hosts=target, arguments='-sn -PR -PO -PM -PY -PU')
        # -sn --> Ping scan; disable port scan 
        # -PR --> ARP ping
        # -PO --> Protocol ping (ICMP, IGMP, IP-in-IP)
        # -PM --> ICMP Adress mask ping
        # -PY --> SCTP init ping (IP based tel)
        # -PU --> UDP ping scan

        ports = []

        hosts_list = [(x, nm[x]['status']['state']) for x in nm.all_hosts()]
        for host, status in hosts_list:
            if status == 'up' and self.results.__contains__(host) != True:
                nm.scan(hosts=target, arguments=f'-v -sV {args} p0-65535')
                for proto in nm[host].all_protocols():
                    lport = nm[host][proto].keys()
                    for port in lport:
                        service = nm[host][proto][port]['name']
                        if ports.__contains__(port) == False:
                            ports.append({'port': port, 'protocol': proto, 'service': service, 'found_by': 'NMAP', 'confirmed_by': []})

                dic = {'ip': target, 'ports': ports, 'found_by': 'NMAP', 'confirmed_by': []}
                self.results.append(dic)
    
    # def unicornScan(self, target):
    #     print("[x] UnicornScan ...")

    #     args = ""
    #     if self.udp == True: args = "-mUT"
    #     command = f'sudo unicornscan {args} -I {target}:a -l logfile.txt'
    #     os.system(command)

    #     lines = []
    #     with open ('logfile.txt', 'rt') as f:
    #         for line in f:
    #             if line.__contains__('TCP open') == True and line.__contains__('from') == True:
    #                 lines.append(line)
    #             if line.__contains__('UDP open') == True and line.__contains__('from') == True:
    #                 lines.append(line)

    #     if os.path.exists('logfile.txt'):
    #         os.remove('logfile.txt')

    #     ports = []
    #     portre = r"\[(.+[0-9_]+)\]"

    #     foundip = False
    #     for ip in self.results:
    #         if ip['ip'] == target:
    #             foundip = True
    #             ip['confirmed_by'].append("UnicornScan")
    #             print("LINE ")
    #             print(lines)
    #             for line in lines:
    #                 print(re.match(portre, line))
    #                 if re.match(portre, line):
    #                     port = re.search(portre, line)

    #                     portnumb = port.group(1).replace(' ','')
    #                     proto = str(line[:2]).lower()
    #                     print(proto)
    #                     foundport = False
    #                     for numb in ip['ports']:
    #                         if foundport == False:                                  
    #                             if int(numb['port']) == int(portnumb) and numb['protocol'] == proto:
    #                                 foundport = True
    #                                 numb['confirmed_by'].append("UnicornScan")
    #                         else: break

    #                     if foundport == False:
    #                         ports.append({'port': portnumb, 'protocol': proto, 'found_by': 'UnicornScan', 'confirmed_by': []})
    #         break
            
    #     if foundip == False:
    #         dic = {'ip': target, 'ports': ports, 'protocol': proto, 'found_by': 'UnicornScan', 'confirmed_by': []}
    #         self.results.append(dic)

            

    def masScan(self, target):
        print("[x] masscan ...")

        args = ""
        if self.udp == True: args = ",U:0-65535"

        command = f'sudo masscan -p1-65535{args} {target} -oJ masscan.json --rate=10000'
        os.system(command)

        ports = []

        with open(f'masscan.json', mode='r') as jsonf:
            data = jsonf.read()
        
        if data != "":
            foundip = False
            obj = json.loads(data)        
            for ip in self.results: 
                if ip['ip'] == target:
                    foundip = True
                    ip['confirmed_by'].append("masscan")
                    
                    for result in obj:
                        portnumb = result['ports'][0]['port']
                        proto = result['ports'][0]['proto']
                        foundport = False
                        for numb in ip['ports']:
                            if foundport == False:                                  
                                if int(numb['port']) == int(portnumb) and numb['protocol'] == proto:
                                    foundport = True
                                    numb['confirmed_by'].append("masscan")
                            else: break

                    if foundport == False:
                        ports.append({'port': portnumb, 'protocol': proto, 'service': 'unknown', 'found_by': 'masscan', 'confirmed_by': []})

            if foundip == False:
                for result in obj:
                    portnumb = result['ports'][0]['port']
                    proto = result['ports'][0]['proto']
                    ports.append({'port': portnumb, 'protocol': proto, 'service': 'unknown', 'found_by': 'masscan', 'confirmed_by': []})
                
                dic = {'ip': target, 'ports': ports, 'found_by': 'masscan', 'confirmed_by': []}
                self.results.append(dic)

    def shodanScan(self, target):
        print("[x] Shodan ...")

        ports = []

        try:
            api = shodan.Shodan(self.API_KEY)
            result = api.host(target)
            print(result)
            found = False
            for ip in self.results:
                if ip['ip'] == result['ip_str']:
                    found = True
                    ip['confirmed_by'].append("Shodan")

                    for portnumb in result['ports']:
                        proto = "tcp"
                        foundport = False
                        for numb in ip['ports']:
                            if foundport == False:                                  
                                if int(numb['port']) == int(portnumb) and numb['protocol'] == proto:
                                    foundport = True
                                    numb['confirmed_by'].append("Shodan")
                            else: break

                    if foundport == False:
                        ports.append({'port': portnumb, 'protocol': proto, 'service': 'unknown', 'found_by': 'Shodan', 'confirmed_by': []})
            
            if found == False:
                for portnumb in result['ports']:
                    proto = "tcp"
                    ports.append({'port': portnumb, 'protocol': proto, 'service': 'unknown', 'found_by': 'Shodan', 'confirmed_by': []})

                dic = {'ip': target, 'ports': [], 'found_by': 'Shodan', 'confirmed_by': []}
                self.results.append(dic)

        except Exception as e: 
            print(f"\n[!][!] AN ERROR OCCURRED, IT IS POSSIBLE NO INFORMATION WAS FOUND. SEE THE ERROR BELOW FOR FURTHER INFORMATION FOR IP {target}.\n")
            print(f"SHODAN ERROR: {e}")

    def censysScan(self, target):
        print("[x] Censys ...")
        ports = []

        url = f"https://censys.io/ipv4/{target}/raw"

        headers = {"User-Agent": 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/80.0.3987.132 Safari/537.36'}
        page = requests.get(url, headers=headers).text
        soup = BeautifulSoup(page, 'html.parser')
       
        text = soup.find("code").get_text()
        result = json.loads(text)

        try: 
            found = False
            for ip in self.results:
                if ip['ip'] == result['ip']:
                    found = True
                    ip['confirmed_by'].append("Censys")

                    for portnumb in result['ports']:
                        proto = "tcp"
                        foundport = False
                        for numb in ip['ports']:
                            if foundport == False:                                  
                                if int(numb['port']) == int(portnumb) and numb['protocol'] == proto:
                                    foundport = True
                                    numb['confirmed_by'].append("Censys")
                            else: break

                    if foundport == False:
                        ports.append({'port': portnumb, 'protocol': proto, 'service': 'unknown', 'found_by': 'Censys', 'confirmed_by': []})
                
            if found == False:
                for portnumb in result['ports']:
                    proto = "tcp"
                    ports.append({'port': portnumb, 'protocol': proto, 'service': 'unknown', 'found_by': 'Censys', 'confirmed_by': []})

                dic = {'ip': target, 'ports': [], 'found_by': 'Censys', 'confirmed_by': []}
                self.results.append(dic)

        except Exception as e:
            print(f"\n[!][!] AN ERROR OCCURRED, IT IS POSSIBLE NO INFORMATION WAS FOUND. SEE THE ERROR BELOW FOR FURTHER INFORMATION FOR IP {target}.\n")
            print(f"CENSYS ERROR: {e}")

    def scanInternal(self, target):
        self.nmapScan(target)
        self.masScan(target)
        # self.unicornScan(target)

    def scanExternal(self, target):
        self.nmapScan(target)
        # self.unicornScan(target)
        self.masScan(target)
        self.shodanScan(target)
        self.censysScan(target)

    def output(self):
        print("\n[+] CREATING OUTPUT\n")
        reporting = \
            {
                "description": [
                    "Detect internally or externally available IPs and open ports with IP discovery tools."
                ],
                "data": self.results
            }

        with open(self.outputfile, mode='w') as jsonf:
            jsonf.write(json.dumps(reporting, indent=4))

if __name__ == "__main__":
    headers = NetworkScan()
    headers.argparse()