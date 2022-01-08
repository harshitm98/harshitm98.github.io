---
title: Android CTF - CyberTruck Challenge 2019 
date: "2019-12-04"
draft: false
tags: ["android", "apktool", "smali" ,"writeup"]
---

CyberTruck Challenge 2019 is a premier event to bring together a community of interest related to heavy vehicle cybersecurity issued and develop talent to address those challenges. This is a write up for their CTF. Their website can be found here and the Github profile for the challenge can found here.

*Note: This was originally written on [Medium](https://medium.com/bugbountywriteup/cybertruck-challenge-2019-android-ctf-e39c7f796530) and has been converted to markdown using [mediumexporter](https://github.com/xdamman/mediumexporter)*

*Note: I was not present during the event. All I wanted to do was practice Android CTFs and that’s when I came across their [Github page](https://github.com/nowsecure/cybertruckchallenge19).*



### Tools used

* [ApkTool](https://ibotpeaches.github.io/Apktool/)

* [dex2jar](https://github.com/pxb1988/dex2jar/)

* [jd-gui](https://github.com/java-decompiler/jd-gui/releases/)

* [frida](https://frida.re/docs/android/)

* [radare2](https://www.radare.org/n/radare2.html)

## Challenge description

A new mobile remote keyless system “CyberTruck” has been implemented by one of the most well-known car security companies “NowSecure Mobile Vehicles”. The car security company has ensured that the system is entirely uncrackable and therefore attackers will not be able to recover secrets within the mobile application.

If you are an experienced Android reverser, then enable the tamperproof button to harden the application before unlocking your cars. Your goal will consist on recovering up to 6 secrets in the application.

## Preparing for the CTF

### Installing the app

Using adb to install the app on the phone.

adb install cybertruck19.apk

### Decoding the app using ApkTool

Decode the APK using Apktool and output it into cybertruck-smali folder.

apktool d cybertruck19.apk -o cybertruck-smali

### Converting the apk in .jar format using dex2jar

I converted the .apk to jar because then I can use **JD-GUI** to see Java source code.

![*Note: I downloaded dex2jar and create a tools directory so all my tools are easily accessible*](https://cdn-images-1.medium.com/max/2000/1*2_E6zZYGLoHbzXVHoknouQ.png)**Note: I downloaded dex2jar and create a tools directory so all my tools are easily accessible**

Using **JD-GUI**, we open the cybertruck.jar created by the dex2jar (previous command).

![*Note: I downloaded jd-gui and create a tools directory so all my tools are easily accessible*](https://cdn-images-1.medium.com/max/2000/1*ZO9UeWlGMJ6iUF_jLKIDmg.png)**Note: I downloaded jd-gui and create a tools directory so all my tools are easily accessible**

### Launching the app

As soon as we launch the app, we get this image.

![](https://cdn-images-1.medium.com/max/2000/1*HC27j26RSGCGyorq1rpzzg.png)

So we try to understand what the unlock button and toggle buttons do.

## Challenge #1

*Challenge1 to unlock car1. “DES key: Completely Keyless. Completely safe”*

To figure out what activity is being launched, let’s take a look at AndroidManifest.xml

![AndroidManifest.xml file is under cybertruck-smali directory (created by apktool)](https://cdn-images-1.medium.com/max/2000/1*lgNrddThBMQIefRoQZ-QjQ.png)*AndroidManifest.xml file is under cybertruck-smali directory (created by apktool)*

![MainActivity is the activity that is being launched first](https://cdn-images-1.medium.com/max/2000/1*XB65TsjaoFMw4ozIGs9VUA.png)*MainActivity is the activity that is being launched first*

So, using JD-GUI to take a look at the source code of MainActivity.class

![Note: I downloaded jd-gui jar file inside tools directory and launch using java](https://cdn-images-1.medium.com/max/2000/1*w0aOQOh_VRsAfUUg29_Bzw.png)*Note: I downloaded jd-gui jar file inside tools directory and launch using java*

![](https://cdn-images-1.medium.com/max/2000/1*06ES7P75_kbMrd5tWZhF3w.png)

Looking at the onCreate function, we find the Unlock button. On clicking the unlock button, it calls this.b.k() . So we further investigate.

![Snapshot of function k](https://cdn-images-1.medium.com/max/2000/1*9gPSJx9oCmbFKXs7oRueyQ.png)*Snapshot of function k*

The function creates an instance of class Challenge1. So we take a look at Challenge1.class

![](https://cdn-images-1.medium.com/max/2000/1*O6G7O4nAz12bdpAiUXVgcg.png)

Static Flag for challenge1 is s3cr3t$_n3veR_mUst_bE_h4rdc0d3d_m4t3!

For dynamic flag, we will have to find a way to get the value returned by generateDynamicKey function in the runtime. These are exactly the scenario where Frida comes in handy. You can learn more about Frida from their [official documentation](https://frida.re/docs/home/).

<iframe src="https://medium.com/media/d8d2ef0b672e0f625bb0a61096bc1d4a" frameborder=0></iframe>

generateDynamicKey returns a byte array. The byte array is stored in variable result which we forward it python function on_message. Here we convert byte array to string.

### Capturing Dynamic flag

![First we run frida-server on the android device. Then we use the flag-capture.py, to capture the dynamic flag](https://cdn-images-1.medium.com/max/2000/1*7PVEQ4QoPLJvUlwXyzNKjg.png)*First we run frida-server on the android device. Then we use the flag-capture.py, to capture the dynamic flag*

The dynamic flag is 046e04ff67535d25dfea022033fcaaf23606b95a5c07a8c6

## Challenge #2

*Challenge2 to unlock car2: “AES key: Your Cell Mobile Is Your Key”*

Going through the `this.b.k()` function in `MainActivity.class`

![](https://cdn-images-1.medium.com/max/2000/1*Dzo-ZgUqs-V9ezyxpWR2xg.png)

Instance of class a is called. Let’s investigate further.

![](https://cdn-images-1.medium.com/max/2000/1*hTcEQlKpyt1ClEkFJ2tChg.png)

So we have class a with constructor a and two functions with name a.

While declaring constructors, you do not have specify the return value. So public a(Context paramContext) is the constructor and the rest are functions.

So this file contains:

![Constructor](https://cdn-images-1.medium.com/max/2000/1*QY11GmOV97eaXFte38qnWw.png)*Constructor*

![Function that takes one argument and returns byte array](https://cdn-images-1.medium.com/max/2000/1*cqV8aDib4K0fg7q_SK8pwg.png)*Function that takes one argument and returns byte array*

![Function that takes two arguments and return byte array](https://cdn-images-1.medium.com/max/2000/1*T0UMh2i--l9yuOezRyZzRQ.png)*Function that takes two arguments and return byte array*

Anyways, coming back to constructor a, it calls a(Context paramContext) and then its returned value is then passed as one of the arguments in a(byte[] paramArrayOfbyte1, byte[] paramArrayOfbyte2)

So we take a look at function a(Context paramContext)

![](https://cdn-images-1.medium.com/max/2000/1*Q6rw5ylIwa-bqlig4YqT5Q.png)

File ch2.key is opened. So we take a look at its contents.

![](https://cdn-images-1.medium.com/max/2000/1*nB1XWbSakEY5RrjKS_b0-w.png)

The value of static flag for Challenge2 is d474_47_r357_mu57_pR073C73D700!!

Now let’s take look at function a(byte[] paramArrayOfbyte1, byte[] paramArrayOfbyte2)

![](https://cdn-images-1.medium.com/max/2000/1*ls3a6PTjEcRVWpUf8Mc39Q.png)

For dynamic flag, we will need to use Frida again to capture the returned value of this function

<iframe src="https://medium.com/media/2867e9cf6e9344013aca1ecec4581b66" frameborder=0></iframe>

![After appending the above snippet to js_code, we rerun the flag-capture.py](https://cdn-images-1.medium.com/max/2000/1*H5E7QZBuctqOm4x4ijhJRg.png)*After appending the above snippet to js_code, we rerun the flag-capture.py*

The dynamic flag for Challenge2 is 512100f7cc50c76906d23181aff63f0d642b3d947f75d360b6b15447540e4f16

## Challenge #3

*Challenge3 to unlock car3. “Mr Truck: Unlock me Baby!”*

**Challenge3 description:** There is an interesting string in the native code. Can you catch it?

Inside MainActivity.class, this native-lib.so is loaded.

![](https://cdn-images-1.medium.com/max/2000/1*XSxqkWea5tnGJ05hugxxHw.png)

![We first locate this file and then use **strings** to print all the strings in the file](https://cdn-images-1.medium.com/max/2000/1*dIC-ILhAHsH0F9uAe32Jag.png)*We first locate this file and then use **strings** to print all the strings in the file*

The static flag for this challenge is Native_c0d3_1s_h4rd3r_To_r3vers3

For dynamic flag, it depends upon on your device’s instruction set. In my case, it was arm64-v8a which requires you to be able to understand assembly language instructions for the same. Which seems to be out of my league (..yet!).

### How to bypass Tamperproof check?

![This function checks if there is a frida server in this device](https://cdn-images-1.medium.com/max/2000/1*cj-7s8Woz1RAnjnykNbzAw.png)*This function checks if there is a frida server in this device*

![](https://cdn-images-1.medium.com/max/2000/1*JXfcr5TDB_GnjecEs8_Veg.png)

This function returns true if there is frida server is present and false otherwise. So we use Frida to overwrite this function’s return value

<iframe src="https://medium.com/media/85de014b91164a569e60e5af1b0d77df" frameborder=0></iframe>

So that’s my solution for this CTF. I am still new to CTFs and have a lot to learn yet. Still this CTF was a good learning opportunity. Hope you also learned something.

Thanks for reading my write-up! Cheers! 🍺

Follow me on [Twitter](https://twitter.com/fake_batman_), [Github](https://github.com/harshitm98) or connect on [LinkedIn](https://linkedin.com/in/harshitm98).