# Projet SDV - 2024 Cybersécurité
# Author DMO, LIT & MNE
# A python program that use the python-nmap library to scan a host and store the open ports and their versions in an array
# Each port is an array for which the first element is the service name and the second element is the version
# Example : if the port is vsftpd 3.0.3, the array will be ['vsftpd', '3.0.3']
# The user call the function scan_host() and pass the host ip address as a parameter

import nmap
import sys
from pdf_reports import pug_to_html, write_report
# import all the functions from the exploit_deck.py file in the same directory
from exploit_deck import *

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

# ptet tout suppr pour utiliser metasploit on sait pas
def search_sploit(open_ports):
    possible_exploits = []
    for port in open_ports:
        product = port[0]
        version = port[1]
        print(f'Searching for exploits for {product} {version}...')
        result = compare_exploit(product, version)
        if(result != "No exploit found"):
            # if an exploit is found, we add it to the list of possible_exploits
            possible_exploits.append(result)
            print("Possible exploit found: " + result)
        else:
            print('No exploit found')
    return possible_exploits

def sploit_to_pdf(list_of_sploit):
    # We pass the list of possible exploits to the pug file
    report_writer = ReportWriter(
    default_template="",
    title="Report d'exploitation de la machine " + host,
    )
    html = pug_to_html("template.pug", title="My report")
    write_report(html, "example.pdf")  
    
if __name__ == '__main__':
    if len(sys.argv) != 2:
        print('Usage: python3 main.py <host>')
        sys.exit(1)
    global host
    host = sys.argv[1]
    open_ports = scan_host(host)
    list_of_sploit = search_sploit(open_ports)
    sploit_to_pdf(list_of_sploit)
    
    print('Done')
