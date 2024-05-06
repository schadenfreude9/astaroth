# Projet SDV - 2024 Cybersécurité
# Author DMO, LIT & MNE
# A python scanner using metasploit module and nmap vulnhub script to get a list of CVE for a given host
# VULSCAN deja installée sur le systeme

import pymetasploit3.msfrpc as msfrpc
import sys
import os 

def launch_rpc_server():
    # Launch the Metasploit RPC server
    os.system('msfrpcd -P astaroth')

def get_cves(host):
    # Connect to the Metasploit RPC server
    client = msfrpc.MsfRpcClient('astaroth', ssl=True)
    listOfCVE = os.system("nmap -sV --script vulners " + host)
    print("list of CVEs: ", listOfCVE)

def main():
    # Check if the user has provided a host
    if len(sys.argv) != 2:
        print('Usage: python main.py <host>')
        sys.exit(1)

    # Get the host
    host = sys.argv[1]
    launch_rpc_server() # On lance le serveur RPC
    cves = get_cves(host) #

main()