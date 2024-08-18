import http.server
import http.client
import urllib.parse
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad, pad
import base64
from urllib.parse import unquote, quote
import argparse

parser = argparse.ArgumentParser()
parser.add_argument('--target', type=str)
parser.add_argument('--port', type=str)
args = parser.parse_args()



def encrypt_AES(plaintext):
    cipher = AES.new(b"very-secure-key-", AES.MODE_CBC, iv=b"very-secure-iv--")
    cipher_text = cipher.encrypt(pad(plaintext, block_size=16))
    return quote(base64.b64encode(cipher_text))

def decrypt_AES(ciphertext):
    ct = base64.b64decode(unquote(ciphertext))
    cipher = AES.new(b"very-secure-key-", AES.MODE_CBC, iv=b"very-secure-iv--")
    plaintext = unpad(cipher.decrypt(ct), block_size=16)
    return plaintext


class ReverseProxyHTTPRequestHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        # Forward the GET request to the target server
        self.forward_request("GET")

    def do_POST(self):
        self.forward_request("POST")

    def forward_request(self, method):
        parsed_url = urllib.parse.urlparse(self.path)
        target_host = args.target.split(":")[0]
        target_port = int(args.target.split(":")[1])

        conn = http.client.HTTPConnection(target_host, target_port)

        if method == "POST":
            content_length = int(self.headers.get('Content-Length', 0))
            body = encrypt_AES(self.rfile.read(content_length))
        else:
            body = None
        self.headers.replace_header('Content-Length', len(body))

        conn.request(method, parsed_url.path, body, headers=dict(self.headers))

        response = conn.getresponse()
        response_body = decrypt_AES(response.read()) #this is where we decrypt the response


        self.send_response(response.status)
        for header in response.getheaders():
            self.send_header(header[0], header[1])
        self.end_headers()

        self.wfile.write(response_body)

        conn.close()

def run(server_class=http.server.HTTPServer, handler_class=ReverseProxyHTTPRequestHandler, port=int(args.port)):
    server_address = ('', port)
    httpd = server_class(server_address, handler_class)
    print(f'Starting reverse proxy on port {port}...')
    httpd.serve_forever()

if __name__ == "__main__":
    run()
