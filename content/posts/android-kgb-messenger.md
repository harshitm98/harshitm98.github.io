---
title: Android CTF - KGB Messenger
date: "2019-12-04"
draft: false
tags: ["android", "apktool", "smali" ,"writeup"]
---

This is a write up of an open source CTF practice challenge. The aim of this CTF is to learn how to reverse engineer an Android Application. You can find the CTF link [here](https://github.com/tlamb96/kgb_messenger).

*Note: This was originally written on [Medium](https://medium.com/@fake_batman_/android-ctf-kgb-messenger-d9069f4cedf8) and has been converted to markdown using [mediumexporter](https://github.com/xdamman/mediumexporter)*

### Tools used

* [Apktool](https://ibotpeaches.github.io/Apktool/)

* [jd-gui](https://github.com/java-decompiler/jd-gui/releases/)

* [Uber Apk Signer](https://github.com/patrickfav/uber-apk-signer)

* [dex2jar](https://github.com/pxb1988/dex2jar/)

### **Installing the application**

Make sure to connect the android phone with debugging mode enabled and then install the application.

adb install kgb-messenger.apk

### Decoding using Apktool

Decode the APK using Apktool and output it into kgb-smali folder.

![](https://cdn-images-1.medium.com/max/2000/1*Bi7Q_rVomlGzdFko5DJlIw.png)

### Converting the apk in .jar format using dex2jar

We convert to jar because then we can use **JD-GUI** to see Java code.

![](https://cdn-images-1.medium.com/max/2000/0*c5DGqjKODExd_TJl)

Using **JD-GUI**, we open the kgb-jar.jar created by the dex2jar (previous command).

![**Note**: I downloaded JD-GUI and created a directory called tools and move it to that directory](https://cdn-images-1.medium.com/max/2000/1*-PNbYjV-6jDsq1ISkKAvnA.png)
***Note**: I downloaded JD-GUI and created a directory called tools and move it to that directory*

### **Launching the app now**

As soon as we launch the app we get this error.

![](https://cdn-images-1.medium.com/max/2000/1*yXOwagk_u6Fq_PwrsdRXSw.jpeg)

To see what is causing this error, we need to see which Activity is being launched first. So we open AndroidManifest.xml which can be found inside kgb-smali (Files created by apktool)

![](https://cdn-images-1.medium.com/max/2000/1*abkleTtjpX__IeiSd2HShQ.png)

Using vim editor, we open AndroidManifest.xml

![Snippet of part of AndroidManifest.xml](https://cdn-images-1.medium.com/max/2000/1*oVI2pqnG3OaqOWbwKL1JRA.png)
*Snippet of part of AndroidManifest.xml*

MainActivity is the activity that is launched first. So use JD-GUI to view MainActivity.class

![](https://cdn-images-1.medium.com/max/2000/1*nl_NWIixkGk4_K5bKXifGQ.png)

We can see, when the activity is created, two string values are checked. First str1 is checked if it equals to *Russia. *Similarly, str2** **is checked if it equals to getResources().getString(*2131558400*).** **The number is numerical representation for the value of string stored in [strings.xml](https://developer.android.com/guide/topics/resources/string-resource) file.

Since we also have the .smali** **files inside smali folder created by Apktool, we open MainActivity.smali and locate this particular line getResources().getString(2131558400)

Before that we need to represent 2131558400 in hex format so that it becomes easier for us to find the value inside of smali code.

![](https://cdn-images-1.medium.com/max/2000/1*u1KvXOorF9aFAI55s7l9hg.png)

So we open MainActivity.smali file using Vim editor.

![](https://cdn-images-1.medium.com/max/2000/0*PbT0zbT5PyaccPDk)

Now, we try to locate the String resource which has the id 0x7f0d0000 and is being compared to str2.

We go to the **res/values **directory and search where does 0x7f0d0000** **occurs

![](https://cdn-images-1.medium.com/max/2000/1*pS-1flAXQrOjTtRRqtHoHA.png)

We see that the name is **“User”** and type is **“string”**. So we search for **“User” **and in strings.xml file the name=”User” has value encoded using Base64. We docode it.

![](https://cdn-images-1.medium.com/max/2000/1*_5l9saOR-njueyJgldPSZQ.png)

## Capturing the Second Flag

*To capture the second flag we need to go to the next activity, that is LoginActivity.*

![onCreate method of MainActivity](https://cdn-images-1.medium.com/max/2000/1*hI8Kajk8qBuNzrs2IQxABA.png)
*onCreate method of MainActivity*

In order to get to LoginActivity, we need to find a way to get through both if conditions or we could just remove them.

Let’s open the .smali version of MainActivity.class to remove the code responsible for both if conditions.

![Smali version of first condition](https://cdn-images-1.medium.com/max/2000/0*eqJBxvnnE2HQL2tz)
*Smali version of first condition*

![Smali version of second condition](https://cdn-images-1.medium.com/max/2000/0*LoOSIYFg4CN0OeVw)
*Smali version of second condition*

### Getting rid of both conditions

![Selecting the code for removal](https://cdn-images-1.medium.com/max/2000/0*maA0rMCkgZiglXk_)
*Selecting the code for removal*

![After removal](https://cdn-images-1.medium.com/max/2000/0*FEm9b0f8VqTC-5AU)
*After removal*

*Note: Make sure after removing your code looks this and ends with goto :go_to_0*

### Building the apk

After making the changes we need to build the apk. So we build the apk using Apktool.

![](https://cdn-images-1.medium.com/max/2000/1*kZVaENKs7Wq_CZaSxLXuog.png)

### Signing the apk

We cannot directly install the apk. We need to [sign](http://www.androiddocs.com/tools/publishing/app-signing.html) them first. However, since we are not the original developers of this app, we will Uber Apk Signer for this purpose.

![**Note:** I downloaded Uber Apk Signer and created a directory called tools and move it to that directory](https://cdn-images-1.medium.com/max/2000/0*S4gIFG1JJDynyUND)
***Note:** I downloaded Uber Apk Signer and created a directory called tools and move it to that directory*

### Installing and running the modified apk

Now when we launch, we are directly taken to LoginActivity.

![](https://cdn-images-1.medium.com/max/2000/1*iXBg8Htuw8wb2s7UUA3nWA.jpeg)

Now we have to find out what the username and password is. Let’s take a look at the source code again but this time for LoginActivity using JD-GUI

![](https://cdn-images-1.medium.com/max/2000/1*EhH3Q8kmfI9m3vGOml_Pxg.png)

Inside onLogin method, we have two edit text who are converted to string. EditText1 is converted to string n and EditText2 is converted to string o. Right now we do not know which EditText corresponds to username and password.

### Finding username

We look at the first nested if condition, string n is being compared to a resource with id 2131158450. So we convert it to hex code again and check if we can find the corresponding string name.

![Finding the **username** value by using id which is found using hex code of 2131158450](https://cdn-images-1.medium.com/max/2000/1*CuTQtfLwnPq9Ig-DFRx8Dg.png)
*Finding the **username** value by using id which is found using hex code of 2131158450*

So the username is **codenameduchess**.

### Finding password

Let’s try to find the password using the same method used for username.

We go through the code again, and can see that function j should return false.

![](https://cdn-images-1.medium.com/max/2000/1*1VnPhBbncBCYlqwqgiAONA.png)

![](https://cdn-images-1.medium.com/max/2000/1*etHk9x6vEt-GcyS6fpqo7w.png)

![](https://cdn-images-1.medium.com/max/2000/1*C9aaQCw1cJOEJ9hNA-vQLw.png)

Here, the string o is hashed using MD5 and then compared with string resource id 2131558446.

We try to find the value of hash from strings.xml and would use findmyhashto find its original value.

![](https://cdn-images-1.medium.com/max/2000/1*iE1i-MlasrMZ50Z2TcBGtA.png)

We get hash value in the strings.xml, but when we try to use findmyhash to find the hash’s original value, we do not get any results. 
The question did say that we would have to use social engineering to get the password. So we try googling **codenameduchess**.

![Google result for codenameduchess](https://cdn-images-1.medium.com/max/2000/0*pQfTGuSgeW_bAWoS)
*Google result for codenameduchess*

The name of account **‘Sterling Archer’** also checks out with the first flag. So we take a look at it’s twitter account.

![Twitter page for codenameduchess (Sterling Archer)](https://cdn-images-1.medium.com/max/2462/0*5efkfUlhLBwWccQC)
*Twitter page for codenameduchess (Sterling Archer)*

It looks like it is a character of a TV show. We now try to Google for codename duchess password.

![Google result for codename duchess password](https://cdn-images-1.medium.com/max/2000/0*kCTg8tkgzelbTbQr)
*Google result for codename duchess password*

We open the PDF, and search through it for password.

![](https://cdn-images-1.medium.com/max/2000/0*RUhLhqm0GDv_H5va)

According to this, the password is **Guest**. So we input the password as ‘**guest**’ (all lowercase).

![](https://cdn-images-1.medium.com/max/2000/1*exESxY33phclNRn3z6I-mw.jpeg)

And..we are in. The Flag is **G00G13_PR0**.

### Checking the value of hash

Just for fun, let’s see why could we not find the hash. So when we calculate the MD5 hash of guest, we get

![](https://cdn-images-1.medium.com/max/2000/0*XLjWrxUB6xRbFgBp)

So the reason we were not able to find the result was the hash we had was incomplete (did not have the zero at the start).

## Capturing the third flag

*After logging in, we are taken to MessageActivity. There’s where we will find our third flag.*

So we open MessageActivity using JD-GUI, we take a look at the source code.

![Function onSendMessage from MessageActivity](https://cdn-images-1.medium.com/max/2000/0*LMB1vOs34Zg_KVtC)
*Function onSendMessage from MessageActivity*

Whenever we send the message, onSendMessage function is called, and the text entered using EditText is converted to String str.

Now if we look closely, the string **str** is passed to a function named **a **on which equals function is called to check if it is equal to **p**.

![](https://cdn-images-1.medium.com/max/2000/0*gzeSfauvA_nblVaC)

The value of **p** is:

![](https://cdn-images-1.medium.com/max/2000/1*ftWhJr5rN_ZSA-rNzTEx6Q.png)

Now, let’s take a look at function a

![](https://cdn-images-1.medium.com/max/2000/0*serjcz7YzZkD70kI)

Function a** **returns string. In this function, the value of string passed as an argument obtained by:

![Visual representation of the function a](https://cdn-images-1.medium.com/max/2000/1*WNgLkw-NgbZvZJ3sfACG8g.png)
*Visual representation of the function a*

So, the value of **p** equals to the parameter string passed to this function **a**. So, we can reverse engineer the original value of **p** by doing these steps in reverse. As we know (A XOR B) XOR B = A, we can use this to find the original value of the string:

![Visual representation of function where we XOR again](https://cdn-images-1.medium.com/max/2000/1*vC6PV5N1cytGKcOEcW_lvw.png)
*Visual representation of function where we XOR again*

We recreate this above algorithm using Python:

```
p = "V@]EAASB\022WZF\022e,a$7(&am2(3.\003"
p = list(str(p))

for i in range(len(p) // 2):
	p[i] = chr(ord(p[i]) ^ 0x32)
	p[len(p) // 2 + 1 + i] = chr(ord(p[len(p) // 2 + 1 + i]) ^ 0x41)

p.reverse()
print("".join(p))
```

When we run this file, we get

![](https://cdn-images-1.medium.com/max/2000/0*e4tzOJ7YacoD7-fm)

So we enter this string as the input for the EditText of the app:

![](https://cdn-images-1.medium.com/max/2000/1*OdUTNQfQSU42HpxQlN-QsA.png)

Similarly, the input from the EditText is passed through function b and check if it equals to string r.

![The value of String r](https://cdn-images-1.medium.com/max/2000/1*Gr-cQn_dQSM88B4JbftQWQ.png)
*The value of String r*

![Function b whose returned value is compared to String r](https://cdn-images-1.medium.com/max/2000/0*kDT9QhVm015Q5pY6)
*Function b whose returned value is compared to String r*

While converting the smali code to java class, there seems to be some problem. The code can be refactored so it can be better understood.

![Just a readable version of function b](https://cdn-images-1.medium.com/max/2000/0*LSNKMof9nI_hhx0W)
*Just a readable version of function b*

Here it is not possible to reverse engineer, so we try to brute force our way in. We check for what values of loop iterable i and alphabet, we get the output r.

```
import string

r = "\000dslp}oQ\000 dks$|M\000h +AYQg\000P*!M$gQ\000"
r = list(str(r))
r.reverse()

for i in range(len(r)):
	if i % 8 == 0:
		print("_", end="")
		continue 
```

After running this file, we get the output.

![](https://cdn-images-1.medium.com/max/2000/0*2l3YUXwHRTiocYUK)

The values for every 8th position is ‘_’ because we have i%8 == 0. And irrespective of the alphabets, the output from the function is 0, so it is difficult to find the answer using brute force.

So the message could be **May I *PLEASE* have the password**.

Let’s put this message

![](https://cdn-images-1.medium.com/max/2160/1*Q3uWdINI9QQ9NF4EpMtaig.jpeg)

Third flag captured.

### Why did not directly type this message and type the message before?

To understand this, we need to see how the flag is calculated. Function i is responsible for calculating the flag. Let’s see how

![](https://cdn-images-1.medium.com/max/2000/1*6gHnhid59KUUj7mDg54lkw.png)

The first condition checks if String q and s are not null. That is they have to be initialized and set to some specific value. We cannot delete this if condition like before because we need values of q and s to calculate the flag.

![In function onSendMessage](https://cdn-images-1.medium.com/max/2000/1*o-0u1INYr1chxf7yUPA-NQ.jpeg)*In function onSendMessage*

It’s only after successfully sending both questions, the values for q and s are set. So it is necessary to send both messages.

So that’s my solution for this CTF. This was my first ever CTF and learned a lot during this challenge. Hope you also learned something.

Thanks for reading my write-up! Cheers! 🍺

Follow me on [Twitter](https://twitter.com/fake_batman_), [Github](https://github.com/harshitm98) or connect on [LinkedIn](https://linkedin.com/in/harshitm98).