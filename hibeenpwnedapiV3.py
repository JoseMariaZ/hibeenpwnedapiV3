#!/usr/bin/env python3
#
#   Author: Jose Maria Zaragoza.
#   Hibpwned API: V3
#   November 2020 - Script Creation.
#   Version = 2.1
#   References:
#       https://haveibeenpwned.com/API/v3
#       https://github.com/m0nkeyplay
#       https:/gist.github.com/mikerr/6389549

import requests
import json
import os
import time
import datetime
import signal
import argparse

ap = argparse.ArgumentParser()
ap.add_argument("-e", "--email", required=False, help="Search one email")
ap.add_argument("-f", "--file", required=False, help="emails from a list one per line -f /path/to/file")
ap.add_argument("-d", "--domain", required=False, help="Check breaches for a domain.Use -d All to see all the domains breached")
args = vars(ap.parse_args())

# CTRL+C handler  
def handler(signum, frame):
    print("\n^^^^^^Task aborted by user.  Some cleanup may be necessary.")
    exit(0)

signal.signal(signal.SIGINT,handler)

# Banner Info
def show_banner():
  print('#####################################################################')
  print('###                  HIBPWNED API CHECKER V3                      ###')
  print('###                                                               ###')
  print('### Usage: hibeenpwnedapiv3.py -e email|-f textFile|-d domain/All ###')
  print('#####################################################################\n')

# Help Menu
def show_help():
    print('\n::Help with argument usage::\n')
    print('Are you searching one or many emails?')
    print('-e  or -f with textFile having one email per line')
    print('-d To search breaches on a domain, use -d All to see all the domains breached')

#Args checker
if args['email']:
      chkType = 'email'
      chkIt = args['email']
elif args['file']:
      chkType = 'file'
      chkIt = args['file']
elif args ['domain']:
      chkType = 'domain'
      chkIt = args['domain']
else:
    show_banner()
    show_help()
    exit()

# Headers
headers = {}
headers['content-type']= 'application/json'
headers['api-version']= '3'
headers['User-Agent']='HIBPWNEDV3 Tool'
# The API key here
headers['hibp-api-key']='API KEY HERE'

# Check Breach
def check_breach(eml):
    url = 'https://haveibeenpwned.com/api/v3/breachedaccount/'+eml+'?truncateResponse=false'
    r = requests.get(url, headers=headers)
    if r.status_code == 404:
        print("%s [-]Account not found in a breach."%eml)
    elif r.status_code == 200:
        data = r.json()
        print('Breach Check for: %s'%eml)
        for d in data:
            #   Simple info
            breach = d['Name']
            domain = d['Domain']
            breachDate = d['BreachDate']
            sensitive = d['IsSensitive']
            print('[!]Account: %s\n[+]Breach: %s\n[+]Sensitive: %s\n[+]Domain: %s\n[+]Breach Date:%s\n'%(eml,breach,sensitive,domain,breachDate))
            #   or to print out the whole shebang comment above and uncomment below
            #for k,v in d.items():
            #    print(k+":"+str(v))
    else:
        data = r.json()
        print('Error: <%s>  %s'%(str(r.status_code),data['message']))
        exit()

# Check Paste
def check_paste(eml):
    url = 'https://haveibeenpwned.com/api/v3/pasteaccount/'+eml
    #print(url)
    r = requests.get(url, headers=headers)
    if r.status_code == 404:
        print("%s [-]Account not found in a paste.\n"%eml)
    elif r.status_code == 200:
        data = r.json()
        print('Paste Check for: %s'%eml)
        for d in data:
            source = d['Source']
            id = str(d['Id'])
            pasteDate = d['Date']
            #   Uncomment and add these if you like
            #title = str(d['Title'])
            #EmailCount = str(d['EmailCount'])
            print('[!!]Paste Source: %s\n[+]ID: %s\n[+]Date: %s\n\n'%(source,id,pasteDate))
    else:
        data = r.json()
        print('Error: <%s>  %s'%(str(r.status_code),data['message']))
        exit()

def check_domain(dm1):
    if dm1=='All':
        url = 'https://haveibeenpwned.com/api/v3/breaches'
        r = requests.get(url, headers=headers)
        if r.status_code == 404:
            print("[-]Domain %s not found in a breach."%dm1)
        elif r.status_code == 200:
            data = r.json()
            print("Breach Check for domain:%s"%dm1)
            for d in data:
                #   Simple info
                breach = d['Name']
                domain = d['Domain']
                breachDate = d['BreachDate']
                sensitive = d['IsSensitive']
                print('[!]Name: %s\n[+]Breach: %s\n[+]Sensitive: %s\n[+]Domain: %s\n[+]Breach Date:%s\n'%(breach,dm1,sensitive,domain,breachDate))
            exit()
    else:
        url = 'https://haveibeenpwned.com/api/v3/breaches?domain='+dm1
        r = requests.get(url, headers=headers)
    if r.status_code == 404:
        print("[-]Domain %s not found in a breach."%dm1)
    elif r.status_code == 200:
        data = r.json()
        print("Breach Check for domain:%s"%dm1)
        for d in data:
            #   Simple info
            breach = d['Name']
            domain = d['Domain']
            breachDate = d['BreachDate']
            sensitive = d['IsSensitive']
            pwnedaccounts = d['PwnCount']
            dataclass = d['DataClasses']
            description = d['Description']
            print('[!]Name %s\n[+]Breach: %s\n[+]Sensitive: %s\n[+]Domain: %s\n[+]Breach Date: %s\n[+]Powned Accounts: %s\n[+]Data Class: %s\n[+]Description: %s\n'%(breach,dm1,sensitive,domain,breachDate,pwnedaccounts,dataclass,description))
    else:
        data = r.json()
        print('Error: <%s>  %s'%(str(r.status_code),data['message']))
        exit()

		
# Main
if __name__ == '__main__':
    show_banner()
    # Single Checks
    if headers['hibp-api-key']=='API KEY HERE':
        print("ERROR: Setup still required.\nPlease register an API key to start using this script.\nRegister https://haveibeenpwned.com/API/Key")
        exit()
    if chkType == 'email':
        check_breach(chkIt)
        check_paste(chkIt)
    # File Checks
    elif chkType == 'file':
        if not os.path.isfile(chkIt):
            print('\n\nWe can\'t find/open %s.  Please check that it\'s a valid file.\n\n'%chkIt)
        else:
            get_emails = open(chkIt, 'r')
            for line in get_emails:
                cleanEmail = line.strip()
                check_breach(cleanEmail)
                time.sleep(1)
                check_paste(cleanEmail)
                time.sleep(2)
            get_emails.close()
    elif chkType == 'domain':
        check_domain(chkIt)
    # Something really interesting happened
    else:
        print('Unknow error, please check th API key and the headers.')
