# seller_client.py
import socket
import struct
import json
from hashlib import sha256
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
import sys

HOST = "127.0.0.1"
PORT = 65432

def send_bytes(sock, b):
    sock.sendall(struct.pack("!I", len(b)))
    sock.sendall(b)

def recv_bytes(sock):
    hdr = sock.recv(4)
    if not hdr:
        raise ConnectionError("connection closed")
    length = struct.unpack("!I", hdr)[0]
    data = b""
    while len(data) < length:
        chunk = sock.recv(length - len(data))
        if not chunk:
            raise ConnectionError("connection closed")
        data += chunk
    return data

def int_from_str(s): return int(s)

def run_seller(seller_name, transactions):
    # transactions: list of integers (amounts)
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.connect((HOST, PORT))
        # receive paillier public key
        pub_json = recv_bytes(sock)
        pub = json.loads(pub_json.decode())
        n = int(pub["n"]); g = int(pub["g"])
        nsq = n*n

        # function to encrypt in same format as gateway
        import secrets
        def paillier_encrypt_local(m):
            r = secrets.randbelow(n-1) + 1
            c = (pow(g, m, nsq) * pow(r, n, nsq)) % nsq
            return c

        # send seller name
        send_bytes(sock, seller_name.encode())
        # send tx count
        send_bytes(sock, str(len(transactions)).encode())
        # send encrypted txs
        for m in transactions:
            if m < 0:
                raise ValueError("negative not supported in this demo")
            c = paillier_encrypt_local(m)
            send_bytes(sock, str(c).encode())

        # wait ack
        ack = recv_bytes(sock)
        print(f"[Seller:{seller_name}] Gateway ack: {ack.decode()}")

if __name__ == "__main__":
    # Example quick mode: python seller_client.py seller_name 10 20 30
    if len(sys.argv) >= 3:
        name = sys.argv[1]
        txs = [int(x) for x in sys.argv[2:]]
        run_seller(name, txs)
    else:
        # default: two sellers with two+ transactions
        run_seller("Seller_A", [100, 250, 50])
        run_seller("Seller_B", [200, 300])


'''
How to run (step-by-step)

Put gateway_server.py and seller_client.py in the same folder.

Open terminal 1 and run the gateway:

python gateway_server.py


Gateway will print keys generation messages and then listen on 127.0.0.1:65432.

It will then wait for sellers to connect. Do not press Enter yet — that input signals when sellers are done.

Open terminal 2 and run one seller instance:

python seller_client.py Seller_A 100 250 50


(or run the script with no args: it will send two seller batches as a convenience).

Open additional terminals for additional sellers (or run more instances):

python seller_client.py Seller_B 200 300


After all sellers have connected and their transactions are accepted, go back to the gateway terminal and press Enter. The gateway will:

Build the transaction summary for all sellers,

Compute SHA-256 digest of the summary,

Sign the digest with its RSA private key,

Verify the signature locally,

Print the signed summary and save transaction_summary_signed.json.

You can use the printed RSA public key (PEM) and transaction_summary_signed.json to verify the signature independently if desired.
'''
