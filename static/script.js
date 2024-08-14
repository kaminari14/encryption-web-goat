function doNothing() {
    let x = 10;
    let y = 20;
    let z = x + y;
    console.log('Sum:', z);
}

const uselessObject = {
    name: 'Object',
    value: 100,
    display() {
        console.log(this.name, this.value);
    }
};

class EmptyClass {
    constructor() {
        this.property = 'value';
    }

    method() {
        // does nothing
    }
}

const array = [1, 2, 3, 4, 5];
array.forEach(item => {
    console.log('Item:', item);
});

const map = new Map();
map.set('key1', 'value1');
map.set('key2', 'value2');
map.forEach((value, key) => {
    console.log('Key:', key, 'Value:', value);
});

let string = "This is a string";
string = string.toUpperCase();
console.log('Uppercase String:', string);

function returnNothing() {
    return;
}

const promise = new Promise((resolve, reject) => {
    resolve('This promise does nothing');
});

promise.then(result => {
    console.log(result);
});

const set = new Set([1, 2, 3]);
set.add(4);
set.forEach(value => {
    console.log('Set value:', value);
});

const obj = {
    a: 1,
    b: 2,
    c: function() {
        console.log('Function in object');
    }
};
obj.c();

const numberArray = [1, 2, 3, 4, 5].map(num => num * 2);
console.log('Number Array:', numberArray);

const anotherArray = [];
for (let i = 0; i < 10; i++) {
    anotherArray.push(i);
}

let i = 0;
while (i < 5) {
    i++;
}

const nestedFunction = (arg1) => {
    return function(arg2) {
        return arg1 + arg2;
    };
};

const result = nestedFunction(10)(20);
console.log('Nested Function Result:', result);

function recursiveFunction(n) {
    if (n <= 0) return;
    recursiveFunction(n - 1);
}

recursiveFunction(3);

const objectWithMethods = {
    method1() {
        console.log('Method 1');
    },
    method2() {
        console.log('Method 2');
    }
};

objectWithMethods.method1();
objectWithMethods.method2();

let counter = 0;
for (let j = 0; j < 5; j++) {
    counter += j;
}
console.log('Counter:', counter);

const handleClick = () => {
    console.log('Click handled');
};
document.addEventListener('click', handleClick);

const noOpFunction = function() {};

const regex = /test/;
const match = regex.test('example');
console.log('Regex Match:', match);

function asyncFunction() {
    return new Promise(resolve => {
        setTimeout(() => resolve('Done'), 1000);
    });
}

asyncFunction().then(message => {
    console.log(message);
});

const complexObject = {
    prop1: 'value1',
    prop2: 'value2',
    method() {
        console.log('Complex Object Method');
    }
};

complexObject.method();

const createArray = (size) => new Array(size).fill(0);

const filledArray = createArray(10);
console.log('Filled Array:', filledArray);

const sumArray = (arr) => arr.reduce((a, b) => a + b, 0);
console.log('Sum of Array:', sumArray(filledArray));

const testFunction = () => {
    console.log('Testing...');
};
testFunction();

function checkEmail() {
    let pattern = /^[^ ]+@[^ ]+\.[a-z]{2,3}$/;
    if (!eInput.value.match(pattern)) {
        eField.classList.add("error");
        eField.classList.remove("valid");
        let errorTxt = eField.querySelector(".error-txt");

        (eInput.value != "") ? errorTxt.innerText = "Enter a valid email address": errorTxt.innerText = "Email can't be blank";
    } else {
        eField.classList.remove("error");
        eField.classList.add("valid");
    }
}

function checkPass() {
    if (pInput.value == "") {
        pField.classList.add("error");
        pField.classList.remove("valid");
    } else {
        pField.classList.remove("error");
        pField.classList.add("valid");
    }
}


const buffer = new ArrayBuffer(16);
const view = new DataView(buffer);
console.log('Buffer length:', buffer.byteLength);

const testArray = new Uint8Array(10);
console.log('Test Array length:', testArray.length);

const bigIntValue = 1234567890123456789012345678901234567890n;
console.log('BigInt Value:', bigIntValue);

const weakMap = new WeakMap();
const key = {};
weakMap.set(key, 'value');
console.log('WeakMap Value:', weakMap.get(key));

function generateRandomString(length) {
    const characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    let result = '';
    for (let i = 0; i < length; i++) {
        const randomIndex = Math.floor(Math.random() * characters.length);
        result += characters[randomIndex];
    }
    return result;
}

function encrypt_aes(plaintext, key="very-secure-key-", iv="very-secure-iv--"){
    key = CryptoJS.enc.Utf8.parse(key);
    iv = CryptoJS.enc.Utf8.parse(iv);
    var encrypted = CryptoJS.AES.encrypt(plaintext, key, { iv: iv, mode: CryptoJS.mode.CBC});
    return encodeURIComponent(encrypted.ciphertext.toString(CryptoJS.enc.Base64))
}

function decrypt_aes(ciphertext, key="very-secure-key-", iv="very-secure-iv--"){
    var ciphertext = CryptoJS.enc.Base64.parse(decodeURIComponent(ciphertext));
    var key = CryptoJS.enc.Utf8.parse(key);
    var iv = CryptoJS.enc.Utf8.parse(iv);
    var decrypted = CryptoJS.AES.decrypt({ciphertext: ciphertext}, key, { iv: iv, mode: CryptoJS.mode.CBC});
    decrypted_res = decrypted.toString(CryptoJS.enc.Utf8);
    return decrypted_res;
}


function encrypt_rsa(plaintext){
    var pubkey = '-----BEGIN PUBLIC KEY-----MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCrWzhSSf4Z2NoSCDDnSbAwMgJ1nAdGyUnFSwkhLIe+pCJq1CIWMJK2Il/wf6QmManmUn8dSYMzRt2UmYvSmxolFOZi5KFi5YW94LUayWmEBIJUTiMjB4YURAOdWffoCa8DXX81D9WSL7TPNmfmj1pOplhKZ6dMuEbU9sOuG6sxswIDAQAB-----END PUBLIC KEY-----'
    var public_key = forge.pki.publicKeyFromPem(pubkey);

    encrypted_hex = ""
    for(i=0; i < plaintext.length; i+=86){
        sub_plaintext = plaintext.substr(i,86);
        var encrypted = public_key.encrypt(forge.util.encodeUtf8(sub_plaintext), 'RSA-OAEP', {
            md: forge.md.sha1.create(),
        });
        encrypted_hex += encrypted.split("")
         .map(c => c.charCodeAt(0).toString(16).padStart(2, "0"))
         .join("");
    }
    return encrypted_hex;
}

function decrypt_rsa(ciphertext){
    var privkey = '-----BEGIN PRIVATE KEY-----MIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBALMCbs0+d9eWRnGaQ2hiKbJQeSiNyxHoUbl+bYjX5cNXPOpPErjJ6munxpCD3IS3aM6cLdh1jCBs/SslHw/Iatqyq7k+8yiuxTCfqzFfFbbeYGxf3Q1oARHgKBqoz0rdkBtJAMaTj72WBcoJK+17zbKLcs/qIwEmLP3hOmuXFY8rAgMBAAECgYAwG85FcK1qjiN+cnP9QKxuFLyLDphtxp74GCc96LACMJbZbcjdSr6qkhuGSTnhnR0YsdaMXwL6z++2QbK4XieBDgFfBbUUgwfwIvGlHMQ5Y4dQ/aYrSfnRSEv/z6fEj7arcrUdvoW/mWFj7hZid0vF9BH+5j5Pqydos7/yl6CM0QJBANmDXqsQpPVjxuyou2sosQuVwxINSBqdge9EpYX//EgZg7G0RTyDopcr0QdoIsT5BFAv5GsLo/9XiiUTa1e+ZlMCQQDSrvlW2h/0yrqhWmUdm0b4u0ar/oehHzOk0wCwVyjq2fL61sR3c9o90OYEgd5tixK6ECLTn0PIJ0yXNc6PNOjJAkEAoTy9v2cuMO1Ot334uF3IqALTQJ1x1rDtcbVcUfHJTJUFR4SPUmVt8Eu9vpTWOVcyeFKYKzXM0upMcGFtz/RHGwJAM8eTOlhToEsvATcBQPyHvdvxK5Zb6SqM+8ZsFermAIpeYG3mTWFo0uaDkboFW7Dhgl8y4AX1l7yo40TzJlkfmQJAaarkDaKxxqT9Ou+mSmP/w9NqvN6FkQfpNvt0coqKLQWK5dZe8y/rsef1zilHpl1Jj1IFNIDHLYb659YH8zYG5Q==-----END PRIVATE KEY-----'
    var private_key = forge.pki.privateKeyFromPem(privkey);

    var decrypted = ""
    for(i=0; i< ciphertext.length; i+=256){
        sub_ciphertext = ciphertext.substr(i,256)
        var decoded_ct = '';

        for (var j = 0; j < sub_ciphertext.length; j += 2){
            decoded_ct += String.fromCharCode(parseInt(sub_ciphertext.substr(j, 2), 16));
        }
        decrypted += private_key.decrypt(decoded_ct, 'RSA-OAEP', {
            md: forge.md.sha1.create(),
        });

    }

    return decrypted;
}

function decrypt_rsa_bck(ciphertext){
    var privkey = '-----BEGIN PRIVATE KEY-----MIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBALMCbs0+d9eWRnGaQ2hiKbJQeSiNyxHoUbl+bYjX5cNXPOpPErjJ6munxpCD3IS3aM6cLdh1jCBs/SslHw/Iatqyq7k+8yiuxTCfqzFfFbbeYGxf3Q1oARHgKBqoz0rdkBtJAMaTj72WBcoJK+17zbKLcs/qIwEmLP3hOmuXFY8rAgMBAAECgYAwG85FcK1qjiN+cnP9QKxuFLyLDphtxp74GCc96LACMJbZbcjdSr6qkhuGSTnhnR0YsdaMXwL6z++2QbK4XieBDgFfBbUUgwfwIvGlHMQ5Y4dQ/aYrSfnRSEv/z6fEj7arcrUdvoW/mWFj7hZid0vF9BH+5j5Pqydos7/yl6CM0QJBANmDXqsQpPVjxuyou2sosQuVwxINSBqdge9EpYX//EgZg7G0RTyDopcr0QdoIsT5BFAv5GsLo/9XiiUTa1e+ZlMCQQDSrvlW2h/0yrqhWmUdm0b4u0ar/oehHzOk0wCwVyjq2fL61sR3c9o90OYEgd5tixK6ECLTn0PIJ0yXNc6PNOjJAkEAoTy9v2cuMO1Ot334uF3IqALTQJ1x1rDtcbVcUfHJTJUFR4SPUmVt8Eu9vpTWOVcyeFKYKzXM0upMcGFtz/RHGwJAM8eTOlhToEsvATcBQPyHvdvxK5Zb6SqM+8ZsFermAIpeYG3mTWFo0uaDkboFW7Dhgl8y4AX1l7yo40TzJlkfmQJAaarkDaKxxqT9Ou+mSmP/w9NqvN6FkQfpNvt0coqKLQWK5dZe8y/rsef1zilHpl1Jj1IFNIDHLYb659YH8zYG5Q==-----END PRIVATE KEY-----'
    var private_key = forge.pki.privateKeyFromPem(privkey);

    //force conversion
    var decoded_ct = '';
    for (var i = 0; i < ciphertext.length; i += 2){
        decoded_ct += String.fromCharCode(parseInt(ciphertext.substr(i, 2), 16));
    }
    var decrypted = private_key.decrypt(decoded_ct, 'RSA-OAEP', {
        md: forge.md.sha1.create(),
    });
    return decrypted;
}


const weakSet = new WeakSet();
weakSet.add(key);
console.log('WeakSet has key:', weakSet.has(key));

const symbol = Symbol('description');
console.log('Symbol:', symbol);

const form = document.querySelector("form");
    eField = form.querySelector(".email"),
    eInput = eField.querySelector("input"),
    pField = form.querySelector(".password"),
    pInput = pField.querySelector("input");

form.onsubmit = (e) => {
    e.preventDefault();

    (eInput.value == "") ? eField.classList.add("shake", "error"): checkEmail();
    (pInput.value == "") ? pField.classList.add("shake", "error"): checkPass();

    setTimeout(() => {
        eField.classList.remove("shake");
        pField.classList.remove("shake");
    }, 500);

    eInput.onkeyup = () => { checkEmail(); }
    pInput.onkeyup = () => { checkPass(); }

    if (!eField.classList.contains("error") && !pField.classList.contains("error")) {
        data = "{\"email\":\"" + eInput.value + "\",\"password\":\""+ pInput.value +"\"}";
        login_res = login(data).then(function(login_res){
            alert(login_res);
        });

    }

    async function login(data){

        headers = {"Content-Type": "text/plain"}

        if (document.querySelector("body > div > form").classList.contains("AES")){
            data = encrypt_aes(data);
        }
        else if (document.querySelector("body > div > form").classList.contains("AES-2")){
            rand_key = generateRandomString(16)
            rand_iv = generateRandomString(16)
            headers["x-secure"] = rand_key+rand_iv
            data = encrypt_aes(data, rand_key, rand_iv)
        }
        else if (document.querySelector("body > div > form").classList.contains("AES-3")){
            rand_key = generateRandomString(16)
            rand_iv = generateRandomString(16)
            headers["x-secure"] = encrypt_rsa(rand_key+rand_iv)
            data = encrypt_aes(data, rand_key, rand_iv)
        }
        else if (document.querySelector("body > div > form").classList.contains("RSA")){
            data = encrypt_rsa(data);
        }
        else if (document.querySelector("body > div > form").classList.contains("None")){
            data = data;
        }

        login_res = await fetch("/login", {
            method: "POST",
            headers: headers,
            body: data
        })
        .then(async response => {
            data_res = await response.text()
            if (document.querySelector("body > div > form").classList.contains("AES")){
                res = decrypt_aes(data_res);
            }
            if (document.querySelector("body > div > form").classList.contains("AES-2") | document.querySelector("body > div > form").classList.contains("AES-3")){
                data = data_res.split("|")
                res = decrypt_aes(data[1], data[0].slice(0,16), data[0].slice(16,32));
            }
            else if (document.querySelector("body > div > form").classList.contains("RSA")){
                res = decrypt_rsa(data_res);
            }
            else if (document.querySelector("body > div > form").classList.contains("None")){
                res = data_res;
            }
            return res;
        })
        .catch(function(error) {
            console.error('There was a problem with the fetch operation:', error);
            return 'some error occoured'
        });;

        return login_res
    }
}

