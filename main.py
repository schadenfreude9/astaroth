# Projet SDV - 2024 Cybersécurité
# Author DMO, LIT & MNE
# A python scanner using metasploit module and nmap vulnhub script to get a list of CVE for a given host

import pymetasploit3
import nmap
import sys

# Function to get the list of CVE for a given host

def get_cve(host):
    # Create a new instance of the Metasploit API
    msf = pymetasploit3.MSF()
    # Connect to the Metasploit API
    msf.login('msf', 'msf')
    # Get the list of CVE for the host
    cve = msf.get_cve(host)
    # Disconnect from the Metasploit API
    msf.logout()
    return cve

# Function to get the list of CVE for a given host

def get_cve_nmap(host):
    # Create a new instance of the Nmap API
    nm = nmap.Nmap()
    # Get the list of CVE for the host
    cve = nm.get_cve(host)
    return cve

# Main function

def main():
    # Check if the user has provided a host
    if len(sys.argv) != 2:
        print('Usage: python main.py <host>')
        sys.exit(1)
    # Get the host
    host = sys.argv[1]
    # Get the list of CVE for the host
    cve = get_cve(host)
    cve_nmap = get_cve_nmap(host)
    # Print the list of CVE
    print('CVE found with Metasploit:')
    for c in cve:
        print(c)
    print('CVE found with Nmap:')
    for c in cve_nmap:
        print(c)
