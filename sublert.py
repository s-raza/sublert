#!/usr/bin/env python
# coding: utf-8
# Announced and released during OWASP Seasides 2019 & NullCon.
# Huge shout out to the Indian bug bounty community for their hospitality.

import argparse
import dns.resolver
import sys
import requests
import json
import difflib
import os
import re
import psycopg2
from tld import get_fld
from tld.utils import update_tld_names
from termcolor import colored
import threading
is_py2 = sys.version[0] == "2" #checks if python version used == 2 in order to properly handle import of Queue module depending on the version used.
if is_py2:
    import Queue as queue
else:
    import queue as queue
import config as cfg
import time

from db.SLDB import *



version = "1.4.7"
requests.packages.urllib3.disable_warnings()



def banner():
    print('''
                   _____       __    __          __
                  / ___/__  __/ /_  / /__  _____/ /_
                  \__ \/ / / / __ \/ / _ \/ ___/ __/
                 ___/ / /_/ / /_/ / /  __/ /  / /_
                /____/\__,_/_.___/_/\___/_/   \__/
    ''')
    print(colored("             Author: Yassine Aboukir (@yassineaboukir)", "red"))
    print(colored("                           Version: {}", "red").format(version))

def parse_args():
        parser = argparse.ArgumentParser(formatter_class=argparse.ArgumentDefaultsHelpFormatter)
        parser.add_argument('-u','--url',
                            dest = "target",
                            help = "Domain to monitor. E.g: yahoo.com",
                            required = False)
        parser.add_argument('-d', '--delete',
                            dest = "remove_domain",
                            help = "Domain to remove from the monitored list. E.g: yahoo.com",
                            required = False)
        parser.add_argument('-t', '--threads',
                            dest = "threads",
                            help = "Number of concurrent threads to use. Default: 20",
                            type = int,
                            default = 20)
        parser.add_argument('-r', '--resolve',
                            dest = "resolve",
                            help = "Perform DNS resolution.",
                            required=False,
                            nargs='?',
                            const="True")
        parser.add_argument('-l', '--logging',
                            dest = "logging",
                            help = "Enable Slack-based error logging.",
                            required=False,
                            nargs='?',
                            const="True")
        parser.add_argument('-a', '--list',
                            dest = "listing",
                            help = "Listing all monitored domains.",
                            required =  False,
                            nargs='?',
                            const="True")
        parser.add_argument('-m', '--reset',
                            dest = "reset",
                            help = "Reset everything.",
                            nargs='?',
                            const="True")
        return parser.parse_args()

def domain_sanity_check(domain): #Verify the domain name sanity
    if domain:
        try:
            domain = get_fld(domain, fix_protocol = True)
            return domain
        except:
            print(colored("[!] Incorrect domain format. Please follow this format: example.com, http(s)://example.com, www.example.com", "red"))
            sys.exit(1)
    else:
        pass

def slack(data): #posting to Slack
    webhook_url = cfg.slack['posting_webhook']
    slack_data = {'text': data}
    response = requests.post(
                        webhook_url,
                        data = json.dumps(slack_data),
                        headers = {'Content-Type': 'application/json'}
                            )
    if response.status_code != 200:
        error = "Request to slack returned an error {}, the response is:\n{}".format(response.status_code, response.text)
        errorlog(error, enable_logging)
    if cfg.slack['sleep_enabled']:
        time.sleep(1)

def reset(do_reset): #clear the monitored list of domains and remove all locally stored files
    if do_reset:
        sldb.delete_all_domains()
        print(colored("\n[!] Sublert was reset successfully. Please add new domains to monitor!", "red"))
        sys.exit(1)
    else: pass

def remove_domain(domain_to_delete): #remove a domain from the monitored list
    new_list = []
    if domain_to_delete:
                
        if sldb.domain_exists(domain_to_delete):
            sldb.delete_domain(domain_to_delete)
            print(colored("\n[-] {} was successfully removed from the monitored list.".format(domain_to_delete), "green"))
        else:
            print(colored("\n[!] {} - Not found".format(domain_to_delete), "red"))
                
        sys.exit(1)

def domains_listing(): #list all the monitored domains
    global list_domains
    if list_domains:

        domains = sldb.get_all_domains()
        
        if len(domains) > 0 :
            print(colored("\n[*] Below is the list of monitored domain names:\n", "green"))
            for domain in domains:
                print(colored("{}".format(domain.replace("\n", "")), "yellow"))
        else:
            print(colored("\n[!] The domain monitoring list is currently empty\n", "red"))
        sys.exit(1)

def errorlog(error, enable_logging): #log errors and post them to slack channel
    if enable_logging:
        print(colored("\n[!] We encountered a small issue, please check error logging slack channel.", "red"))
        webhook_url = cfg.slack['errorlogging_webhook']
        slack_data = {'text': '```' + error + '```'}
        response = requests.post(
                            webhook_url,
                            data = json.dumps(slack_data),
                            headers = {'Content-Type': 'application/json'}
                                )
        if response.status_code != 200:
            error = "Request to slack returned an error {}, the response is:\n{}".format(response.status_code, response.text)
            errorlog(error, enable_logging)
    else: pass

class cert_database(object): #Connecting to crt.sh public API to retrieve subdomains
    global enable_logging
    def lookup(self, domain, wildcard = True):
        try:
            try: #connecting to crt.sh postgres database to retrieve subdomains.
                unique_domains = set()
                domain = domain.replace('%25.', '')
                conn = psycopg2.connect("dbname={0} user={1} host={2}".format(cfg.crtsh['name'], cfg.crtsh['user'], cfg.crtsh['host']))
                conn.autocommit = True
                cursor = conn.cursor()
                cursor.execute("SELECT ci.NAME_VALUE NAME_VALUE FROM certificate_identity ci WHERE ci.NAME_TYPE = 'dNSName' AND reverse(lower(ci.NAME_VALUE)) LIKE reverse(lower('%{}'));".format(domain))
                for result in cursor.fetchall():
                    matches = re.findall(r"\'(.+?)\'", str(result))
                    for subdomain in matches:
                        try:
                            if get_fld("https://" + subdomain) == domain:
                                unique_domains.add(subdomain.lower())
                        except: pass
                return sorted(unique_domains)
            except:
                error = "Unable to connect to the database. We will attempt to use the API instead."
                errorlog(error, enable_logging)
        except:
            base_url = "https://crt.sh/?q={}&output=json"
            if wildcard:
                domain = "%25.{}".format(domain)
                url = base_url.format(domain)
            subdomains = set()
            user_agent = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.14; rv:64.0) Gecko/20100101 Firefox/64.0'
            req = requests.get(url, headers={'User-Agent': user_agent}, timeout=20, verify=False) #times out after 8 seconds waiting
            if req.status_code == 200:
                try:
                    content = req.content.decode('utf-8')
                    data = json.loads(content)
                    for subdomain in data:
                        subdomains.add(subdomain["name_value"].lower())
                    return sorted(subdomains)
                except:
                    error = "Error retrieving information for {}.".format(domain.replace('%25.', ''))
                    errorlog(error, enable_logging)

def queuing(): #using the queue for multithreading purposes
    global domain_to_monitor
    global q1
    global q2
    q1 = queue.Queue(maxsize=0)
    q2 = queue.Queue(maxsize=0)
    if domain_to_monitor:
        pass
    elif len(sldb.get_all_domains()) == 0:
        print(colored("[!] Please consider adding a list of domains to monitor first.", "red"))
        sys.exit(1)
    else:
                
        for line in sldb.get_all_domains():
            if line != "":
                q1.put(line.replace('\n', ''))
                q2.put(line.replace('\n', ''))
            else:
                pass
                

def adding_new_domain(q1): #adds a new domain to the monitoring list
    unique_list = []
    global domain_to_monitor
    global input
    if domain_to_monitor:
                
        if sldb.domain_exists(domain_to_monitor):
            print(colored("[!] The domain name {} is already being monitored.".format(domain_to_monitor), "red"))
            sys.exit(1)
            
        
        sldb.add_domain(domain_to_monitor) # Adding new domain for monitoring.
        
        response = cert_database().lookup(domain_to_monitor)
        
        print(colored("\n[+] Adding {} to the monitored list of domains.\n".format(domain_to_monitor), "yellow"))
        
        if response:
        
            sldb.insert_subdomains(domain_name=domain_to_monitor, subdomains=response) #saving a copy of current subdomains retreived for the new domain.
            
            try: input = raw_input #fixes python 2.x and 3.x input keyword
            except NameError: pass
            
            choice = input(colored("[?] Do you wish to list subdomains found for {}? [Y]es [N]o (default: [N]) ".format(domain_to_monitor), "yellow")) #listing subdomains upon request
            if choice.upper() == "Y":
                for subdomain in response:
                    unique_list.append(subdomain)
                unique_list = list(set(unique_list))
                for subdomain in unique_list:
                    print(colored(subdomain, "yellow"))
            else:
                sys.exit(1)    
        else:
            print(colored("\n[!] Unfortunately, we couldn't find any subdomain for {}".format(domain_to_monitor), "red"))
          
    else: #checks if a domain is monitored but has no text file saved in ./output
                try:
                    line = q1.get(timeout=10)
                    if not sldb.domain_exists(line):
                        response = cert_database().lookup(line)
                                    
                        if response:
                            sldb.insert_subdomains(domain_name=line, subdomains=response)
                            
                                    
                        else: pass
                    else: pass
                except queue.Empty:
                    pass

def check_new_subdomains(q2): #retrieves new list of subdomains and stores a temporary text file for comparaison purposes
    global domain_to_monitor
    global domain_to_delete
    if domain_to_monitor is None:
        if domain_to_delete is None:
            try:
                line = q2.get(timeout=10)
                print("[*] Checking {}".format(line))
                with open("./output/" + line.lower() + "_tmp.txt", "a") as subs:
                    response = cert_database().lookup(line)
                    if response:
                        for subdomain in response:
                            subs.write(subdomain + "\n")
            except queue.Empty:
                pass
    else: pass

def compare_files_diff(domain_to_monitor): #compares the temporary text file with previously stored copy to check if there are new subdomains
    global enable_logging
    if domain_to_monitor is None:
        if domain_to_delete is None:
            result = []
                
            for domain in sldb.get_all_domains():
            
                subdomains_lookup = cert_database().lookup(domain)
            
                all_subdomains = sldb.get_all_subdomains(domain)

                new_subdomains = list(set(subdomains_lookup) - set(all_subdomains))
                
                [result.append(i) for i in new_subdomains]
            
            
            return(result)

def dns_resolution(new_subdomains): #Perform DNS resolution on retrieved subdomains
    dns_results = {}
    subdomains_to_resolve = new_subdomains
    print(colored("\n[!] Performing DNS resolution. Please do not interrupt!", "red"))
    for domain in subdomains_to_resolve:
        domain = domain.replace('+ ','')
        domain = domain.replace('*.','')
        dns_results[domain] = {}
        try:
            for qtype in ['A','CNAME']:
                dns_output = dns.resolver.query(domain,qtype, raise_on_no_answer = False)
                if dns_output.rrset is None:
                    pass
                elif dns_output.rdtype == 1:
                    a_records = [str(i) for i in dns_output.rrset]
                    dns_results[domain]["A"] = a_records
                elif dns_output.rdtype == 5:
                    cname_records = [str(i) for i in dns_output.rrset]
                    dns_results[domain]["CNAME"] = cname_records
                else: pass
        except dns.resolver.NXDOMAIN:
            pass
        except dns.resolver.Timeout:
            dns_results[domain]["A"] = eval('["Timed out while resolving."]')
            dns_results[domain]["CNAME"] = eval('["Timed out error while resolving."]')
            pass
        except dns.exception.DNSException:
            dns_results[domain]["A"] = eval('["There was an error while resolving."]')
            dns_results[domain]["CNAME"] = eval('["There was an error while resolving."]')
            pass
    if dns_results:
        return posting_to_slack(None, True, dns_results) #Slack new subdomains with DNS ouput
    else:
        return posting_to_slack(None, False, None) #Nothing found notification

def at_channel(): #control slack @channel
    return("<!channel> " if cfg.slack['at_channel_enabled'] else "")

def posting_to_slack(result, dns_resolve, dns_output): #sending result to slack workplace
    global domain_to_monitor
    global new_subdomains
    if dns_resolve:
        dns_result = dns_output
        if dns_result:
            dns_result = {k:v for k,v in dns_result.items() if v} #filters non-resolving subdomains
            rev_url = []
            print(colored("\n[!] Exporting result to Slack. Please do not interrupt!", "red"))

            unique_list = list(set(new_subdomains) & set(dns_result.keys())) #filters non-resolving subdomains from new_subdomains list

            for subdomain in unique_list:
                data = "{}:new: {}".format(at_channel(), subdomain)
                slack(data)
                try:
                    if dns_result[subdomain]["A"]:
                        for i in dns_result[subdomain]["A"]:
                            data = "```A : {}```".format(i)
                            slack(data)
                except: pass
                try:
                    if dns_result[subdomain]['CNAME']:
                        for i in dns_result[subdomain]['CNAME']:
                            data = "```CNAME : {}```".format(i)
                            slack(data)
                except: pass
                
            print(colored("\n[!] Done. ", "green"))
            
            for subdomain in unique_list:
                
                sldb.insert_subdomains(get_fld(subdomain, fix_protocol = True), subdomain)

    elif len(result) > 0:
        rev_url = []
        print(colored("\n[!] Exporting the result to Slack. Please don't interrupt!", "red"))
        for url in result:
            url = "https://" + url.replace('+ ', '')
            data = "{}:new: {}".format(at_channel(), url)
            slack(data)
        print(colored("\n[!] Done. ", "green"))
        
        for subdomain in result:
                
                sldb.insert_subdomains(get_fld(subdomain, fix_protocol = True), subdomain)

    else:
        if not domain_to_monitor:
            data = "{}:-1: We couldn't find any new valid subdomains.".format(at_channel())
            slack(data)
            print(colored("\n[!] Done. ", "green"))
        else: pass

def multithreading(threads):
    global domain_to_monitor
    threads_list = []
    if not domain_to_monitor:
        num = len(sldb.get_all_domains())
        for i in range(max(threads, num)):
            if not (q1.empty() and q2.empty()):
                t1 = threading.Thread(target = adding_new_domain, args = (q1, ))
                #t2 = threading.Thread(target = check_new_subdomains, args = (q2, ))
                t1.start()
                #t2.start()
                threads_list.append(t1)
                #threads_list.append(t2)
    else:
        adding_new_domain(domain_to_monitor)

    for t in threads_list:
        t.join()

if __name__ == '__main__':
    
    
#Setup connection to database
    sldb = SLDB(conn_string = cfg.sldb['conn_string'])

#parse arguments
    dns_resolve = parse_args().resolve
    enable_logging = parse_args().logging
    list_domains = parse_args().listing
    domain_to_monitor = domain_sanity_check(parse_args().target)
    domain_to_delete = domain_sanity_check(parse_args().remove_domain)
    do_reset = parse_args().reset

#execute the various functions
    banner()
    reset(do_reset)
    remove_domain(domain_to_delete)
    domains_listing()
    queuing()
    multithreading(parse_args().threads)
    new_subdomains = compare_files_diff(domain_to_monitor)

# Check if DNS resolution is checked
    if not domain_to_monitor:
        if (dns_resolve and len(new_subdomains) > 0):
            dns_resolution(new_subdomains)
        else:
            posting_to_slack(new_subdomains, False, None)
    else: pass

#Tear down connection to database    
    sldb.session.close()
    sldb.session.remove()
