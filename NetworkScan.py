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

results = []

class NetworkScan(object):
    def __init__(self):
        self.outputfile = "NetworkScan_" + str(datetime.datetime.now()).replace(" ", "_") + ".json"

    def argparse(self):
        parser = argparse.ArgumentParser('Scan an internal or external network for open ports and services.')
        parser.add_argument('-t', '--target', required=True, type=str, \
            help='Target specification. E.g.: "192.168.0.0/24"')
        parser.add_argument('-m', '--mode', required=True, type=str, \
            help='Internal or external scan. Choices: "i" or "e"')
        parser.add_argument('-API-KEY', '--API-KEY', required=False, type=str, \
            help='The')
        args = parser.parse_args()

        self.main(args.target, args.mode)

    def main(self, subnet, mode):
        # Regex to detect input type
        CIDR = r"^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])(\/(3[0-2]|[1-2][0-9]|[0-9]))$"
        iprange = r""

        if re.match(CIDR, subnet):
            if mode == 'i':                    
                print("\n[+] STARTING INTERNAL NETWORK SCAN.\n")
                time.sleep(3)
                for ip in ipcalc.Network(subnet):
                    print("Scanning " + str(ip))
                    self.scanInternal(str(ip))

            elif mode == 'e':
                print("\n[+] STARTING EXTERNAL NETWORK SCAN.\n")
                time.sleep(3)
                for ip in ipcalc.Network(subnet):                   
                    print("Scanning " + str(ip))
                    self.scanExternal(str(ip))   

            else: print("\n[!][!] NOT A VALID MODE, USE 'i' FOR INTERNAL NETWORK SCAN AND USE 'e' FOR EXTERNAL NETWORK SCAN.\n")

        else:
            try:
                ipsplit = subnet.split('-')
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
                        print("Scanning " + ip)                       
                        self.scanInternal(ip)
                        endnumb += 1

                elif mode == 'e':
                    print("\n[+] STARTING EXTERNAL NETWORK SCAN.\n")
                    time.sleep(3)   
                    while endnumb <= int(ipsplit[1]):
                        ip = ipstart + str(endnumb)    
                        print("Scanning " + ip)                                         
                        self.scanExternal(ip)
                        endnumb += 1

                else: print("\n[!][!] NOT A VALID MODE, USE 'i' FOR INTERNAL NETWORK SCAN AND USE 'e' FOR EXTERNAL NETWORK SCAN.\n")
            except Exception as e: print("\n[!][!] NOT A VALID IP RANGE OR SUBNET.\n")

        self.output()

    def nmapScan(self, target):
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
            if status == 'up' and results.__contains__(host) != True:
                nm.scan(hosts=target, arguments='-v -sS')
                for proto in nm[host].all_protocols():
                    lport = nm[host][proto].keys()
                    for port in lport:
                        if ports.__contains__(port) == False:
                            ports.append({'port': port, 'found_by': 'NMAP', 'confirmed_by': []})

                dic = {'ip': target, 'ports': ports, 'found_by': 'NMAP', 'confirmed_by': []}
                results.append(dic)
    
    # def unicornScan(self, target):
    #     command = f'sudo unicornscan -msf -v -I {target} -l logfile.txt'
    #     os.system(command)

    #     lines = []
    #     with open ('logfile.txt', 'rt') as f:
    #         for line in f:
    #             print(line)
    #             if line.__contains__('TCP open') == True and line.__contains__('from') == True:
    #                 lines.append(line)

    #     if os.path.exists('logfile.txt'):
    #         os.remove('logfile.txt')

    #     ports = []

    #     for line in lines:
    #         foundip = False
    #         if line.__contains__("TCP open"):
    #             for ip in results:
    #                 if ip['ip'] == target:
    #                     foundip = True
    #                     ip['confirmed_by'].append("UnicornScan")

    #                     for line in lines:
    #                         port = re.search(r"\[(.+[0-9_]+)\]", line)
    #                         portnumb = port.group(1).replace(' ','')

    #                         foundport = False
    #                         for numb in ip['ports']:
    #                             if foundport == False:
    #                                 print(ip['ports'][numb])
    #                                 if ip['ports'][numb] == port:
    #                                     foundport = True
    #                                     ip['ports']['confirmed_by'] += "UnicornScan"
    #                                     break

    #                         if foundport == False:
    #                             ports.append({'port': portnumb, 'found_by': 'UnicornScan', 'confirmed_by': []})
    #             break
            
    #         if foundip == False:
    #             dic = {'ip': target, 'ports': ports, 'found_by': 'UnicornScan', 'confirmed_by': []}
    #             results.append(dic)

            

    def masScan(self, target):
        command = ''
        os.system(command)

        return

    def shodanScan(self, target):
        try:
            api = shodan.Shodan(self.API_KEY)
            result = api.host(target)

            found = False
            for ip in results:
                if ip['ip'] == result:
                    found = True
                    ip['confirmed_by'] += "Shodan"
                    break
            
            if found == False:
                dic = {'ip': target, 'ports': [], 'found_by': 'Shodan', 'confirmed_by': []}
                results.append(dic)

        except Exception as e: 
            print(f"\n[!][!] AN ERROR OCCURRED, IT IS POSSIBLE NO INFORMATION WAS FOUND. SEE THE ERROR BELOW FOR FURTHER INFORMATION FOR IP {target}.\n")
            print(f"SHODAN ERROR: {e}")

    def censysScan(self, target):
        return

    def scanInternal(self, target):
        self.nmapScan(target)
        # self.unicornScan(target)

    def scanExternal(self, target):
        self.nmapScan(target)
        self.unicornScan(target)
        self.masScan(target)
        self.shodanScan(target)
        self.censysScan(target)

    def output(self):
        print("\n[+] CREATING OUTPUT\n")
        reporting = \
            {
                "description": [
                    "Detect internally or externally available IPs with IP discovery tools."
                ],
                "data": results
            }

        with open(self.outputfile, mode='w') as jsonf:
            jsonf.write(json.dumps(reporting, indent=4))

if __name__ == "__main__":
    headers = NetworkScan()
    headers.argparse()