# Projet SDV - 2024 Cybersécurité
# Author DMO, LIT & MNE
# A python program that use the python-nmap library to scan a host and store the open ports and their versions in an array
# Each port is an array for which the first element is the service name and the second element is the version
# Example : if the port is vsftpd 3.0.3, the array will be ['vsftpd', '3.0.3']
# The user call the function scan_host() and pass the host ip address as a parameter

import nmap
import sys
import os
import re

def scan_host(host):
    nm = nmap.PortScanner()
    nm.scan(host, arguments='-sV')
    open_ports = []
    for host in nm.all_hosts():
        for proto in nm[host].all_protocols():
            lport = nm[host][proto].keys()
            for port in lport:
                product = nm[host][proto][port]['product']
                version = nm[host][proto][port]['version']
                open_ports.append([product, version])
    return open_ports

def trim_results(results):
    edb_ids = re.findall(r'\| (\d+)', results)
    all_edb_ids = []
    for edb_id in edb_ids:
        all_edb_ids.append(edb_id)
    print(all_edb_ids)

def search_sploit(open_ports):
    for port in open_ports:
        product = port[0]
        version = port[1]
        print(f'Searching for exploits for {product} {version}...')
        result = os.system(f'searchsploit {product} {version} --id ')
        print(result)
        #trim_results(result)

if __name__ == '__main__':
    if len(sys.argv) != 2:
        print('Usage: python3 main.py <host>')
        sys.exit(1)
    host = sys.argv[1]
    open_ports = scan_host(host)
    search_sploit(open_ports)
    print('Done')
