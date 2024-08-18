from flask import Flask, render_template, request, jsonify
import json, psycopg2
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Util.Padding import unpad, pad
from Crypto.PublicKey import RSA
from urllib.parse import unquote, quote
import base64
from Crypto import Hash
import binascii, configparser, secrets, string



private_key = RSA.import_key(open("certs/server/rsa_1024_priv.pem", "rb").read())

public_key = RSA.import_key(open("certs/client/rsa_1024_pub_client.pem", "rb").read())


def start_server(config_file):
    app = Flask(__name__, template_folder='templates', static_folder='static')
    config = configparser.ConfigParser()
    config.read(config_file)

    @app.route("/")
    def base_view():
        data = {"enc": config["base"]["enc"]}
        return render_template('base.html', data=data)

    @app.route("/login", methods=['POST'])
    def login():
        req_body = get_decrypted_data(request.data, request.headers.get("x-secure"))
        args = json.loads(req_body)
        email = args.get("email")
        password = args.get("password")
        query = "SELECT * from users where email='" + email + "' and password=%s;"

        connection = psycopg2.connect(user=config["database"]["username"],
                                      password=config["database"]["password"],
                                      host=config["database"]["ip"],
                                      port=config["database"]["port"],
                                      database=config["database"]["database_name"])
        cursor = connection.cursor()
        try:
            cursor.execute(query,(password,))

            connection.commit()
            print(cursor.fetchall())
            count = cursor.rowcount
            print(count)

            if count > 0:
                res = {"status":"success"}
            else:
                res = {"status":"failure"}
            print(type(jsonify(res).data))
            print(jsonify(res).data)
            return get_encrypted_data(jsonify(res).data)
        except Exception as e:
            return get_encrypted_data(str(e).encode("utf-8"))


    def generate_random_string(length=16):
        characters = string.ascii_letters + string.digits
        random_string = ''.join(secrets.choice(characters) for _ in range(length))
        return random_string

    def encrypt_AES(plaintext, key=b"very-secure-key-", iv=b"very-secure-iv--", mode=1):
        cipher = AES.new(key, AES.MODE_CBC, iv=iv)
        cipher_text = cipher.encrypt(pad(plaintext, block_size=16))
        if mode == 2:
            return key.decode("utf-8") + iv.decode("utf-8") + "|" + base64.b64encode(cipher_text).decode("utf-8")
        else:
            return quote(base64.b64encode(cipher_text))

    def decrypt_AES(ciphertext, key=b"very-secure-key-", iv=b"very-secure-iv--"):
        print(ciphertext)
        ct = base64.b64decode(unquote(ciphertext))
        cipher = AES.new(key, AES.MODE_CBC, iv=iv)
        plaintext = unpad(cipher.decrypt(ct), block_size=16)
        return plaintext

    def decrypt_rsa(data):
        decryptor = PKCS1_OAEP.new(private_key, hashAlgo=Hash.SHA1)
        decrypted = ""
        print(len(quote(data)))
        for i in range(0, len(data), 256):
            to_decr = binascii.unhexlify(data[i:i+256])
            decrypted += decryptor.decrypt(to_decr).decode("utf-8")
        return decrypted

    def decrypt_rsa_bck(data):
        decryptor = PKCS1_OAEP.new(private_key, hashAlgo=Hash.SHA1)
        to_decr = binascii.unhexlify(data)
        decrypted = decryptor.decrypt(to_decr)
        return decrypted.decode("utf-8")

    def encrypt_rsa(data):
        encryptor = PKCS1_OAEP.new(public_key)
        encrypted = ""
        for i in range(0,len(data),86):
            encrypted += binascii.hexlify(encryptor.encrypt(data[i:i+86])).decode('utf-8')
        return encrypted

    def encrypt_rsa_bck(data):
        encryptor = PKCS1_OAEP.new(public_key)
        print(data)
        encrypted = encryptor.encrypt(data)
        return binascii.hexlify(encrypted)

    def get_decrypted_data(encrypted_data, key_iv=""):
        if config["base"]["enc"] == "RSA":
            return decrypt_rsa(encrypted_data)
        elif config["base"]["enc"] == "AES":
            return decrypt_AES(encrypted_data)
        elif config["base"]["enc"] == "AES-2":
            key = key_iv[0:16].encode("utf-8")
            iv = key_iv[16:].encode("utf-8")
            return decrypt_AES(encrypted_data, key, iv)
        elif config["base"]["enc"] == "AES-3":
            key_iv = decrypt_rsa(key_iv)
            key = key_iv[0:16].encode("utf-8")
            iv = key_iv[16:].encode("utf-8")
            return decrypt_AES(encrypted_data, key, iv)
        elif config["base"]["enc"] == "None":
            return encrypted_data

    def get_encrypted_data(plaintext):
        if config["base"]["enc"] == "RSA":
            print("---------", plaintext)
            return encrypt_rsa(plaintext)
        elif config["base"]["enc"] == "AES":
            return encrypt_AES(plaintext)
        elif config["base"]["enc"] in ["AES-2","AES-3"]:
            key = generate_random_string().encode("utf-8")
            iv = generate_random_string().encode("utf-8")
            return encrypt_AES(plaintext,key,iv, 2)
        elif config["base"]["enc"] == "None":
            return plaintext



    #todo: obfuscation
    return app