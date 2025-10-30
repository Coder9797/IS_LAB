'''
Doctor reads an input text file (contains text, timestamps, budgets).

Doctor:

computes MD5 hash of file,

signs the MD5 digest with ElGamal (toy implementation),

encrypts the file using AES-GCM (symmetric),

encrypts the AES key with the Auditor’s RSA public key (hybrid encryption),

Paillier-encrypts numeric budgets so the Auditor can add budgets homomorphically without decrypting them,

creates search tags (deterministic HMAC-SHA256 of keywords like doctor names/branches) so Auditor can search without decrypting,

sends package to Auditor.

Auditor:

receives package,

can search for doctors using tags (no file decryption needed),

can add budgets homomorphically (multiply Paillier ciphertexts and produce encrypted sum; optionally decrypt if it holds Paillier private key),

can verify the ElGamal signature over the MD5 digest (verification does not require file decryption — it verifies signature over the digest the doctor supplied), and

can decrypt the AES key (using RSA private key) and the file if desired (but the three requested functions operate without decrypting file content as explained).
'''

# auditor_server.py
import socket, struct, threading, json
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import secrets
import hmac, hashlib
from hashlib import md5
import math

# --- Paillier (toy educational) ---
def extended_gcd(a, b):
    if b == 0:
        return (a, 1, 0)
    g, x1, y1 = extended_gcd(b, a % b)
    x = y1
    y = x1 - (a // b) * y1
    return (g, x, y)

def modinv(a, m):
    g, x, y = extended_gcd(a, m)
    if g != 1:
        raise ValueError("No inverse")
    return x % m

# Simple prime test + small primes generator for toy Paillier
def is_probable_prime(n, k=10):
    if n < 2: return False
    small_primes = [2,3,5,7,11,13,17,19,23,29]
    for p in small_primes:
        if n == p: return True
        if n % p == 0: return False
    # Miller-Rabin
    d = n - 1
    s = 0
    while d % 2 == 0:
        s += 1
        d //= 2
    import secrets
    for _ in range(k):
        a = secrets.randbelow(n-3) + 2
        x = pow(a, d, n)
        if x == 1 or x == n-1:
            continue
        for _ in range(s-1):
            x = (x*x) % n
            if x == n-1:
                break
        else:
            return False
    return True

def gen_prime(bits=256):
    import secrets
    while True:
        p = secrets.randbits(bits) | (1 << (bits-1)) | 1
        if is_probable_prime(p):
            return p

def lcm(a, b): return a // math.gcd(a, b) * b

class PaillierPriv:
    def __init__(self, p,q,n,g,lam,mu): 
        self.p,self.q,self.n,self.g,self.lam,self.mu = p,q,n,g,lam,mu

class PaillierPub:
    def __init__(self, n,g): self.n,self.g=n,g

def paillier_keygen(bits=256):
    p = gen_prime(bits); q = gen_prime(bits)
    n = p*q; g = n+1
    lam = lcm(p-1, q-1)
    nsq = n*n
    x = pow(g, lam, nsq)
    L = (x-1)//n
    mu = modinv(L, n)
    return PaillierPub(n,g), PaillierPriv(p,q,n,g,lam,mu)

def paillier_encrypt(pub:PaillierPub, m:int):
    if m < 0: raise ValueError("message must be non-negative int")
    n=pub.n; nsq=n*n
    r = secrets.randbelow(n-1)+1
    return (pow(pub.g, m, nsq) * pow(r, n, nsq)) % nsq

def paillier_decrypt(priv:PaillierPriv, c:int):
    n=priv.n; nsq=n*n
    x = pow(c, priv.lam, nsq)
    L = (x-1)//n
    return (L * priv.mu) % n

def paillier_homomorphic_add(pub:PaillierPub, *cs):
    nsq = pub.n*pub.n
    res = 1
    for c in cs: res = (res * c) % nsq
    return res

# --- Networking helpers ---
def recv_msg(sock):
    hdr = sock.recv(4)
    if not hdr: return None
    length = struct.unpack("!I", hdr)[0]
    data = b""
    while len(data) < length:
        chunk = sock.recv(length - len(data))
        if not chunk: raise ConnectionError("closed")
        data += chunk
    return data

def send_msg(sock, b):
    sock.sendall(struct.pack("!I", len(b)))
    sock.sendall(b)

# --- Server (Auditor) ---
HOST = "127.0.0.1"
PORT = 9000

class Auditor:
    def __init__(self):
        # RSA keys to decrypt AES keys from doctors
        self.rsa_priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.rsa_pub = self.rsa_priv.public_key()
        # Paillier keys for homomorphic operations (auditor may hold priv)
        self.paillier_pub, self.paillier_priv = paillier_keygen(bits=256)  # toy
        # Map from tag -> list of records (simple searchable map)
        self.tag_index = {}   # tag (hex) -> list of record ids
        self.records = {}     # record_id -> metadata (keeps encrypted file, signature, etc.)
        print("[Auditor] RSA public key (PEM):")
        print(self.rsa_pub.public_bytes(encoding=serialization.Encoding.PEM,
                                        format=serialization.PublicFormat.SubjectPublicKeyInfo).decode())

    def handle(self, conn, addr):
        try:
            raw = recv_msg(conn)
            package = json.loads(raw.decode())
            rid = secrets.token_hex(8)
            # store package data for this record
            self.records[rid] = package
            # index tags for search
            for t in package.get("tags", []):
                self.tag_index.setdefault(t, []).append(rid)
            # respond with OK and provide Paillier public params to client if client wants to use it
            resp = {"status":"OK", "paillier_n": str(self.paillier_pub.n), "paillier_g": str(self.paillier_pub.g)}
            send_msg(conn, json.dumps(resp).encode())
            print(f"[Auditor] Received record {rid} from {addr}, indexed tags: {package.get('tags',[])}")
        except Exception as e:
            print("Error:", e)
        finally:
            conn.close()

    # 1) Search for doctors by tag (without decrypting file)
    def search_by_tag(self, keyword, search_key_hex):
        # keyword must be HMACed by same key as doctor used; we accept the tag directly or compute it if search_key provided
        # We'll accept caller passes precomputed tag
        tag = search_key_hex
        rids = self.tag_index.get(tag, [])
        print(f"[Auditor] Search tag {tag} -> records {rids}")
        return rids

    # 2) Add budgets (homomorphically) from a list of record IDs and budget-field names
    def sum_budgets(self, record_ids, budget_field_name="paillier_budgets"):
        # Each record's package contains paillier_encrypted budgets as list of integer strings
        ciphers = []
        for rid in record_ids:
            pkg = self.records[rid]
            # package expected to contain "paillier_budgets": list of strings
            for cstr in pkg.get("paillier_budgets", []):
                ciphers.append(int(cstr))
        if not ciphers:
            return 0
        total_enc = paillier_homomorphic_add(self.paillier_pub, *ciphers)
        # If auditor wishes to decrypt (it holds private key), it can:
        total_plain = paillier_decrypt(self.paillier_priv, total_enc)
        return {"total_encrypted": str(total_enc), "total_decrypted": int(total_plain)}

    # 3) Verify ElGamal signature using provided public key and MD5 digest (no file decryption needed)
    def verify_elgamal(self, pub_params, pub_y, signature, md5_hex):
        # pub_params: dict with p,g
        p = int(pub_params["p"]); g = int(pub_params["g"]); y = int(pub_y)
        e = int(signature["e"]); s = int(signature["s"])
        # recompute r' = g^s * y^{-e} mod p
        def inv_mod(a,m):
            g,x,y = extended_gcd(a,m)
            if g!=1: raise ValueError("no inv")
            return x % m
        r_prime = (pow(g, s, p) * inv_mod(pow(y, e, p), p)) % p
        # compute e2 = H(r'||md5)
        h = hashlib.sha256()
        rbytes = r_prime.to_bytes((r_prime.bit_length()+7)//8 or 1, 'big')
        h.update(rbytes + bytes.fromhex(md5_hex))
        e2 = int.from_bytes(h.digest(), 'big') % ((p-1)//2 if ((p-1)//2)>0 else p-1)
        verified = (e2 == e)
        return verified

auditor = Auditor()

def serve_forever():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, PORT))
        s.listen(5)
        print(f"[Auditor] Listening on {HOST}:{PORT}")
        while True:
            conn, addr = s.accept()
            threading.Thread(target=auditor.handle, args=(conn, addr), daemon=True).start()

if __name__ == "__main__":
    serve_forever()
