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
1. The application uses AES encryption with hardcoded keys. the encrypted text will look something like this.
```
qD5j5psRyXjqtsoObXEwvQQwVQB1XD9ZDfMdxvOjtMK%2FwrRQascsKUZ8gT6oLr4d    
```
2. We can find the hardcoded keys in the script.js file in the encrypt_aes function. Use the hardcoded keys very-secure-key- and hardcoded iv very-secure-iv-- to decrypt the encrypted request with AES-128 CBC mode. Use Cyberchef to perform various kinds of encryption and decryption - [CyberChef](https://cyberchef.org/)
```
function encrypt_aes(plaintext, key="very-secure-key-", iv="very-secure-iv--"){
    key = CryptoJS.enc.Utf8.parse(key);
    iv = CryptoJS.enc.Utf8.parse(iv);
    var encrypted = CryptoJS.AES.encrypt(plaintext, key, { iv: iv, mode: CryptoJS.mode.CBC});
    return encodeURIComponent(encrypted.ciphertext.toString(CryptoJS.enc.Base64))
}
...
function decrypt_aes(ciphertext, key="very-secure-key-", iv="very-secure-iv--"){
    var ciphertext = CryptoJS.enc.Base64.parse(decodeURIComponent(ciphertext));
    var key = CryptoJS.enc.Utf8.parse(key);
    var iv = CryptoJS.enc.Utf8.parse(iv);
    var decrypted = CryptoJS.AES.decrypt({ciphertext: ciphertext}, key, { iv: iv, mode: CryptoJS.mode.CBC});
    decrypted_res = decrypted.toString(CryptoJS.enc.Utf8);
    return decrypted_res;
}
```
3. We can also use the functions in the JS console in the browser to encrypt and decrypt the text. Add the payload to the email parameter and encrypt the body. Send the request.
```
> decrypt_aes('qD5j5psRyXjqtsoObXEwvQQwVQB1XD9ZDfMdxvOjtMK%2FwrRQascsKUZ8gT6oLr4d')
'{"email":"admin@test.com","password":"test"}'
> encrypt_aes('{"email":"admin@test.com\'","password":"test"}')
'qD5j5psRyXjqtsoObXEwvd8LxYpV3Eo3zPtJTxJfgVmsYEmDswHTGkYJODFQnAyh'
```
4. decrypt the recieved response and notice that the sql error is returened. Confirming the existence of sql injection vulnerability.
```
> decrypt_aes('xWixTGVwHrqacwGexv1PzYmrGxx7OWr3Lj8856DDXzcl8AEsfpa24%2Bf%2BF6fXWm9OiAtYQLgxcoENgryCVBg%2By6wMLheYMCUzaahqfFevEKHPzsnOZksCPfWKLmKuoHi6DPHRw/mG1KHkg%2BTzs0sqK1ZcpZIQRr3oj1DnReZsjluBK%2BVRmqKHfbExmoMEQ1xYhYeqoQTq8m7/1on/qyHDArqo0McyLcj7BJvvSkr7KOo%3D')
`syntax error at or near "test"\nLINE 1: ...rom users where email='admin@test.com'' and password='test';\n
```

### Level 2
1. The application uses AES encryption with a dynamic key and a dynamic IV. The dynamic key is sent to the server in a request header - x-secure as observed in the JS code in sript.js file. The first 16 characters of the header is the key and the next 16 characters are the IV.
```
else if (document.querySelector("body > div > form").classList.contains("AES-2")){
  rand_key = generateRandomString(16)
  rand_iv = generateRandomString(16)
  headers["x-secure"] = rand_key+rand_iv
  data = encrypt_aes(data, rand_key, rand_iv)
}
```
```
POST /login HTTP/1.1
Host: 192.168.0.114:5000
x-secure: 4eIjTaqyyLyRIU53vUz3epWgC9inhgMN
...

%2BJfWvCZjOX572PT7i1TM5MJIetsHClp87NnNY4hYsnOh5AlzHG%2FmGkuvFsvY0OQV
```
4. Using this key and iv from the header decrypt the body with AES-128 algorithm CBC mode. Use Cyberchef to perform various kinds of encryption and decryption - [CyberChef](https://cyberchef.org/)
5. Manipulate the value of email in the plaintext and add your payload.
6. The encrypted response contains 2 parts separated by a pine(|) as observed in the script.js file. The first part is the key and IV. The 2nd part is the encrypted response body.
```
if (document.querySelector("body > div > form").classList.contains("AES-2") | document.querySelector("body > div > form").classList.contains("AES-3")){
  data = data_res.split("|")
  res = decrypt_aes(data[1], data[0].slice(0,16), data[0].slice(16,32));
}
```
8. Decrypt the 2nd part of the response body using the key and value in the first part of the response body. Notice that the decrypted response contains the sql error confirming the sql injection vulnerability.

### Level 3
1. The application uses Asymetric RSA encryption so we will not be able to decrypt the request body.
2. Add a breakpoint in the js file at the line where encrypt_rsa function is called. Also add a break point at the line where the decrypted response is returned.
3. After submitting the login form when the debugger reaches the encrypt_rsa line, edit the data variable and add your sql injection payload in the email parameter. Resume the execution in the debugger. 
4. When the debugger reaches the return res code. You will notice that the response contains the sql error confirming the sql injection vulnerability.

### Level 4
1. The application uses a combination of AES and RSA encryption. The request body is encrypted with a dynamic AES key and IV. then the key and IV are encrypted with an RSA key and sent in the request as a header - x-secure
2. Use the 'Match and replace' feature in burp to replace the randomisation code in the js body with a hardcoded key and IV. Refresh the page.
3. We can now decrypt the new encrypted request with our hardcoded key simmilar to Level 2. The plain text can also be encrypted with our hardcoded key and IV.
4. The response can also be decrypted simmilar to level 2.
