## Introduction
Request & Response encryption in an HTTP request is essentially just a client side protection mechanism and should be treated just as an additional layer of security. The logic to encrypt and in many cases the logic to decrypt the data is present in the js code. It is fundamentally not possible for a web application to encrypt request data without having the encryption keys and encryption logic present in the JS code. Simmilarly it is fundamentally not possible for a web application to decrypt the response data without it not having the decryption keys and decryption logic in the JS code. Armed with this JS code and given enough time any attacker can decrypt the encrypted body and/or encrypt malicious payloads to be sent in the request body.

This repository contains a web application that I use to demonstrate encryption bypass techniques. Please go through the Installation and setup steps mentioned below if you want to try it out. Skip to the Solutions section below if you are here to find techniques to bypass encryption.

## Installation and Setup


## Challenges
There is 1 sql injection vulnerability in the application in the login page in the email parameter

### Level 0 - No encryption
Set the encryption to none in the config.ini file
```
[base]
enc = None
```
**Target** - Find the sql injection vulnerability

### Level 1 - Symettric encryption type 1 
Set the encryption to AES in the config.ini file
```
[base]
enc = AES
```
**Target** - Find the sql injection vulnerability

### Level 2 - Symettric encryption type 2
Set the encryption to AES-2 in the config.ini file
```
[base]
enc = AES-2
```
**Target** - Find the sql injection vulnerability

### Level 3 - Asymettric encryption
Set the encryption to RSA in the config.ini file
```
[base]
enc = RSA
```
**Target** - Find the sql injection vulnerability

### Level 4 - Hybrid encryption
Set the encryption to AES-3 in the config.ini file
```
[base]
enc = AES-3
```
**Target** - Find the sql injection vulnerability

### Level 5 - Brute force the password
This can be done with any encryption mode however for this challenger we will stick to the encryption used in the level 1 challenge.
Set the encryption to AES in the config.ini file
```
[base]
enc = AES
```
**Target** - Run a dictionary attack or brute force attack to obtain the password for admin@test.com

## Solution

### Level 1 
