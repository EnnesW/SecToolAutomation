#!/usr/bin/env python3
import argparse
import shodan

class EternalBlue(object):
    def __init__(self):
        self.API_KEY = ""
        self.country = ""
        self.organisation = ""
        self.query = 'port:445 "SMB Version: 1" os:Windows !product:Samba'
        self.ips = []

    def shodanAPI(self):
        api = shodan.Shodan(self.API_KEY)
        search = f"{self.query} {self.country} {self.organisation}"
        print(f"Searching for {search}")

        try:
            results = api.search_cursor(search)

            for r in results: 
                print([r['ip_str']][0])
                self.ips.append([r['ip_str']][0])
        
        except Exception as e:
            print(f"Shodan error: {e}")

        if self.organisation != "": print(f"\n[!]\nAmount of IPs vulnerable to the EternalBlue exploit in {self.organisation}, {self.country}: \n{len(self.ips)}\n[!]\n")            
        else: print(f"\n[!]\nAmount of IPs vulnerable to the EternalBlue exploit in {self.country}: \n{len(self.ips)}\n[!]\n")

    def argparse(self):
        parser = argparse.ArgumentParser('Use the Shodan API to get IP addresses vulnerable to the EternalBlue exploit.')
        parser.add_argument('-org', '--organisation', required=False, type=str, \
            help='The organisation you want the API to search.')
        parser.add_argument('-c', '--country', required=False, type=str, \
            help='The country you want the API to search in. For example: US, DE, CA, RU')
        parser.add_argument('-API_KEY', '--API_KEY', required=False, type=str, \
            help='The API-key for the Shodan API.')
        args = parser.parse_args()

        if args.organisation: self.organisation = f'org:"{args.organisation}"' 
        if args.country: self.country = f'country:"{args.country}"' 
        if args.API_KEY: self.API_KEY = args.API_KEY

        self.shodanAPI()

if __name__ == '__main__':
    headers = EternalBlue()
    headers.argparse()


