# Projet SDV - 2024 Cybersécurité
# Author DMO, LIT & MNE
# A python program that use the python-nmap library to scan a host and store the open ports and their versions in an array
# Each port is an array for which the first element is the service name and the second element is the version
# The user call the function scan_host() and pass the host ip address as a parameter

import nmap
import sys

def scan_host(host):
    nm = nmap.PortScanner()
    nm.scan(host, arguments='-sV')
    open_ports = []
    for host in nm.all_hosts():
        for proto in nm[host].all_protocols():
            lport = nm[host][proto].keys()
            for port in lport:
                service = nm[host][proto][port]['name']
                version = nm[host][proto][port]['version']
                open_ports.append([service, version])
    return open_ports

if __name__ == '__main__':
    if len(sys.argv) != 2:
        print('Usage: python3 main.py <host>')
        sys.exit(1)
    host = sys.argv[1]
    open_ports = scan_host(host)
    print(open_ports)



