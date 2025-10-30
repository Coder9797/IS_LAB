'''
Two or more sellers, each doing ≥2 transactions.

Paillier encryption for transaction amounts; sellers encrypt with gateway public key.

Homomorphic addition of encrypted amounts on the gateway; gateway decrypts totals.

Gateway produces a transaction summary (seller name, individual encrypted/decrypted amounts, totals, signature status, verification result).

Gateway signs the full summary with RSA (SHA-256) and verifies the signature.

Clear instructions to run and an example output.
'''
# gateway_server.py
import socket
import threading
import json
import struct
from hashlib import sha256
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.exceptions import InvalidSignature
import secrets
import math

# ----------------- Paillier implementation (toy/educational) -----------------
def is_probable_prime(n, k=16):
    if n < 2: return False
    # small primes quick check
    small_primes = [2,3,5,7,11,13,17,19,23,29]
    for p in small_primes:
        if n == p:
            return True
        if n % p == 0:
            return False
    # Miller-Rabin
    r, d = 0, n-1
    while d % 2 == 0:
        d //= 2
        r += 1
    for _ in range(k):
        a = secrets.randbelow(n-3) + 2
        x = pow(a, d, n)
        if x == 1 or x == n-1:
            continue
        for _ in range(r-1):
            x = (x * x) % n
            if x == n-1:
                break
        else:
            return False
    return True

def gen_prime(bits):
    while True:
        p = secrets.randbits(bits) | (1 << (bits-1)) | 1
        if is_probable_prime(p):
            return p

def lcm(a, b):
    return a // math.gcd(a, b) * b

def modinv(a, m):
    g, x, y = extended_gcd(a, m)
    if g != 1:
        raise ValueError("No modular inverse")
    return x % m

def extended_gcd(a, b):
    if b == 0:
        return (a, 1, 0)
    g, x1, y1 = extended_gcd(b, a % b)
    x = y1
    y = x1 - (a // b) * y1
    return (g, x, y)

class PaillierPrivateKey:
    def __init__(self, p, q, n, g, lam, mu):
        self.p = p; self.q = q; self.n = n; self.g = g; self.lam = lam; self.mu = mu

class PaillierPublicKey:
    def __init__(self, n, g):
        self.n = n; self.g = g

def paillier_keygen(bits=256):
    # NOTE: 256-bit primes here are for fast lab runs. Increase to >= 2048 in real usage.
    p = gen_prime(bits)
    q = gen_prime(bits)
    n = p * q
    g = n + 1  # common choice simplifies mu computation
    lam = lcm(p-1, q-1)
    nsq = n * n
    # compute mu = (L(g^lambda mod n^2))^{-1} mod n
    x = pow(g, lam, nsq)
    L = (x - 1) // n
    mu = modinv(L, n)
    priv = PaillierPrivateKey(p, q, n, g, lam, mu)
    pub = PaillierPublicKey(n, g)
    return pub, priv

def paillier_encrypt(pub: PaillierPublicKey, m: int):
    n = pub.n
    nsq = n * n
    if m < 0:
        raise ValueError("paillier_encrypt: message must be non-negative int")
    r = secrets.randbelow(n-1) + 1
    c = (pow(pub.g, m, nsq) * pow(r, n, nsq)) % nsq
    return c

def paillier_decrypt(priv: PaillierPrivateKey, c: int):
    n = priv.n; nsq = n*n
    x = pow(c, priv.lam, nsq)
    L = (x - 1) // n
    m = (L * priv.mu) % n
    return m

def paillier_homomorphic_add(pub: PaillierPublicKey, *ciphertexts):
    nsq = pub.n * pub.n
    result = 1
    for c in ciphertexts:
        result = (result * c) % nsq
    return result

# ----------------- Networking helpers -----------------
def send_bytes(sock, b):
    sock.sendall(struct.pack("!I", len(b)))
    sock.sendall(b)

def recv_bytes(sock):
    hdr = sock.recv(4)
    if not hdr:
        return None
    length = struct.unpack("!I", hdr)[0]
    data = b""
    while len(data) < length:
        chunk = sock.recv(length - len(data))
        if not chunk:
            raise ConnectionError("connection closed")
        data += chunk
    return data

# ----------------- Payment Gateway Server -----------------
HOST = "127.0.0.1"
PORT = 65432

class GatewayServer:
    def __init__(self):
        print("[Gateway] Generating Paillier keypair (toy sizes for lab)...")
        self.pub, self.priv = paillier_keygen(bits=256)
        print("[Gateway] Generating RSA keypair for signing...")
        self.rsa_priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.rsa_pub = self.rsa_priv.public_key()
        self.summaries = {}  # seller_name -> dict

    def handle_seller(self, conn, addr):
        try:
            # Step 1: send Paillier public key (n and g) as JSON
            pub_json = json.dumps({"n": str(self.pub.n), "g": str(self.pub.g)}).encode()
            send_bytes(conn, pub_json)

            # Step 2: receive seller name
            data = recv_bytes(conn)
            seller_name = data.decode()
            print(f"[Gateway] Received seller: {seller_name} from {addr}")

            # Step 3: receive transaction count
            data = recv_bytes(conn)
            tx_count = int(data.decode())

            enc_list = []
            dec_list = []
            enc_ints = []
            # receive tx ciphertexts
            for i in range(tx_count):
                data = recv_bytes(conn)
                c = int(data.decode())
                enc_ints.append(c)
                dec = paillier_decrypt(self.priv, c)
                enc_list.append(str(c))
                dec_list.append(int(dec))

            # homomorphic addition (multiply ciphertexts)
            total_enc = paillier_homomorphic_add(self.pub, *enc_ints)
            total_dec = paillier_decrypt(self.priv, total_enc)

            # store summary
            self.summaries[seller_name] = {
                "seller": seller_name,
                "trans_count": tx_count,
                "encrypted_transactions": enc_list,
                "decrypted_transactions": dec_list,
                "total_encrypted": str(total_enc),
                "total_decrypted": int(total_dec)
            }

            # ack to seller with a short message
            send_bytes(conn, b"OK")
            print(f"[Gateway] Stored summary for {seller_name}")

        except Exception as e:
            print("[Gateway] Exception handling seller:", e)
        finally:
            conn.close()

    def build_and_sign_summary(self):
        # build a canonical JSON summary (sorted keys for stable hash)
        summary = {"sellers": list(self.summaries.values())}
        summary_bytes = json.dumps(summary, sort_keys=True).encode()
        digest = sha256(summary_bytes).digest()
        signature = self.rsa_priv.sign(
            digest,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256()
        )
        # verify locally (gateway verifies before sending)
        try:
            self.rsa_pub.verify(
                signature,
                digest,
                padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                hashes.SHA256()
            )
            verification = True
        except InvalidSignature:
            verification = False

        signed_package = {
            "summary": summary,
            "summary_hash_hex": digest.hex(),
            "signature_hex": signature.hex(),
            "signature_verified_by_gateway": verification
        }
        return signed_package, summary_bytes, signature

    def run(self):
        print(f"[Gateway] Listening on {HOST}:{PORT}")
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind((HOST, PORT))
            s.listen(5)
            # We'll accept incoming seller connections until user stops (Ctrl-C)
            try:
                while True:
                    conn, addr = s.accept()
                    threading.Thread(target=self.handle_seller, args=(conn, addr), daemon=True).start()
            except KeyboardInterrupt:
                print("[Gateway] Stopping accept loop...")

if __name__ == "__main__":
    gateway = GatewayServer()
    # Run accept loop in a separate thread so we can later build & sign summary after sellers connect
    server_thread = threading.Thread(target=gateway.run, daemon=True)
    server_thread.start()

    print("[Gateway] Waiting for sellers to connect... (press Enter when done sending)")
    input()  # operator signals when all sellers have sent their data

    package, summary_bytes, signature = gateway.build_and_sign_summary()
    print("\n========== TRANSACTION SUMMARY ==========")
    print(json.dumps(package["summary"], indent=2))
    print("\nSummary SHA-256:", package["summary_hash_hex"])
    print("Signature (hex, first 128 chars):", package["signature_hex"][:128] + "...")
    print("Gateway verified signature:", package["signature_verified_by_gateway"])

    # Also output RSA public key so sellers/verifiers can verify the signature externally:
    rsa_pub_pem = gateway.rsa_pub.public_bytes(encoding=serialization.Encoding.PEM,
                                               format=serialization.PublicFormat.SubjectPublicKeyInfo)
    print("\nGateway RSA public key (PEM):")
    print(rsa_pub_pem.decode())

    # Save summary+signature to file for convenience
    with open("transaction_summary_signed.json", "w") as f:
        json.dump(package, f, indent=2)
    print("\nSaved signed summary to transaction_summary_signed.json")
    print("Done. You can now verify the signature using the RSA public key and the saved summary.")
