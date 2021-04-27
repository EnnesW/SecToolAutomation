#!/usr/bin/env python3
import argparse
import nmap
import os
import sys
import json

# def to scan ips or ip range for active hosts
def scan_active_hosts(target):
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
    print(iplist_active)
    return iplist_active

# def to scan active hosts for open ports and services
def scan_ips_nmap(iplist_active, udp, all_ports):
    nm = nmap.PortScanner()
    portsList = []      

    nmap_args = ['-v -sS -p0-65535']
    # -v  --> verbose
    # -sS --> TCP SYN 
    # -p065535 --> all ports
    portscan_args = ['-v -sS -sV -sC -p']
    # -v  --> verbose
    # -sS --> TCP SYN 
    # -sV --> Probe open ports to determine service/version info
    # -sC --> equivalent to --script=default
    # -p --> port to scan
    if udp == True:
        if all_ports == True:
            nmap_args.append('-v -sU -p0-65535') 
            # -v  --> verbose
            # -sU --> UDP 
            # -p0-65535 --> all ports
        elif all_ports == False:
            nmap_args.append('-v -sU --top-ports 1000')
            # -v  --> verbose
            # -sU --> UDP
            # --top-ports 1000 --> top 1000 ports 
        portscan_args.append('-v -sU -sV -sC -p')
        # -v  --> verbose
        # -sU --> UDP
        # -sV --> Probe open ports to determine service/version info
        # -sC --> equivalent to --script=default
        # -p --> port to scan

    for arg in nmap_args:
        for ip in iplist_active:
            ports = []
            # SCAN OPEN PORTS
            nm.scan(hosts=ip, arguments=arg) 
            host = ip
            for proto in nm[host].all_protocols():
                lport = nm[host][proto].keys()
                sorted(lport)
                for port in lport:
                    if ports.__contains__(port) == False:
                        ports.append(port)
            
            for arg in portscan_args: 
                for port in ports:
                    if port != '':
                        # SCAN OPEN PORTS FOR SERVICES
                        print(f'{arg}{port}')
                        nm.scan(hosts=ip, arguments=f'{arg}{port}')
                        for proto in nm[host].all_protocols():
                            lport = nm[host][proto].keys()
                            sorted(lport)
                            for port in lport:
                                port_ = port
                                service = nm[host][proto][port]['name']
                                version = nm[host][proto][port]['version']
                                product = nm[host][proto][port]['product']
                                if version == "" or product == "":
                                    port_service = f'{port} [{proto.upper()}]: {service} ({product}{version})'
                                    print ('port: %s\tname : %s (%s%s)' % (port, nm[host][proto][port]['name'], nm[host][proto][port]['product'], nm[host][proto][port]['version']))

                                else:
                                    port_service = f'{port} [{proto.upper()}]: {service} ({product} - {version})'
                                    print ('port: %s\tname : %s (%s - %s)' % (port, nm[host][proto][port]['name'], nm[host][proto][port]['product'], nm[host][proto][port]['version']))

                                portsList.append(port_service)

        finding = \
            {
                "id": "S06-001",
                "host": host,
                "data": 
                    portsList                               
            }        


        # Add to list for findings
        _List.append(finding)
        print('\n')             

    return _List
    return portsList

# def to sort IPs
def sort_ips(ips):
    for i in range(len(ips)):
        ips[i] = "%3s.%3s.%3s.%3s" % tuple(ips[i].split("."))
        ips.sort()

    for i in range(len(ips)):
        ips[i] = ips[i].replace(" ", "")    

    return ips

# Create findings
def create_findings(list_findings):
    findings = \
    {
        "findings":  
            list_findings          
    }

    return findings

#def to add findings to findings.json
def findings_to_json(findings, output_loc):
    with open(output_loc, mode='w') as jsonf:
        jsonf.write(json.dumps(findings, indent=4))

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
        help='Perform additional UDP scan if top 1000 ports on top of TCP scan, will take considerably more time.')
    parser.add_argument('-uA', '--udpall', action='store_true', \
        help='Perform additional UDP scan of all ports on top of TCP scan, will take considerably more time.')
    args = parser.parse_args()

    # Execute defs
    ips = str(sys.argv[1])   
    hosts = sort_ips(scan_active_hosts(ips))
    if args.udp:
        portsList = scan_ips_nmap(hosts, True, False)
    elif args.udpall:
        portsList = scan_ips_nmap(hosts, True, True)
    else:   
        portsList = scan_ips_nmap(hosts, False, False) 
    findings = create_findings(portsList)
    findings_to_json(findings, args.output)

if __name__ == "__main__":
    main()