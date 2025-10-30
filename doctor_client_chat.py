# doctor_client.py
import socket, struct, json, sys
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import secrets, hmac, hashlib
from hashlib import md5

HOST = "127.0.0.1"
PORT = 9000

def send_msg(sock, b):
    sock.sendall(struct.pack("!I", len(b))); sock.sendall(b)

def recv_msg(sock):
    hdr = sock.recv(4)
    if not hdr: return None
    l = struct.unpack("!I", hdr)[0]; data=b""
    while len(data) < l:
        chunk = sock.recv(l-len(data))
        if not chunk: raise ConnectionError("closed")
        data += chunk
    return data

# --- Simple ElGamal sign/verify utilities (toy) ---
def gen_elgamal_params(bits=256):
    # find prime p where p = 2*q + 1
    from math import gcd
    import secrets
    def gen_prime(bits):
        while True:
            v = secrets.randbits(bits) | (1 << (bits-1)) | 1
            if is_probable_prime(v): return v
    def is_probable_prime(n,k=10):
        if n<2: return False
        small=[2,3,5,7,11,13,17,19,23,29]
        for p in small:
            if n==p: return True
            if n%p==0: return False
        d=n-1; s=0
        while d%2==0: s+=1; d//=2
        for _ in range(k):
            a = secrets.randbelow(n-3)+2
            x = pow(a,d,n)
            if x==1 or x==n-1: continue
            for _ in range(s-1):
                x=(x*x)%n
                if x==n-1: break
            else: return False
        return True
    while True:
        q = gen_prime(bits-1)
        p = 2*q + 1
        if is_probable_prime(p):
            break
    g = 2
    while pow(g, q, p) == 1:
        g += 1
    return {"p":p,"q":q,"g":g}

def elgamal_keygen(params):
    import secrets
    p = params["p"]; q=params["q"]; g=params["g"]
    x = secrets.randbelow(q-1) + 1
    y = pow(g, x, p)
    return x, y

def elgamal_sign(params, x, md5_bytes):
    import secrets
    p = params["p"]; q=params["q"]; g=params["g"]
    k = secrets.randbelow(q-1) + 1
    r = pow(g, k, p)
    # e = H(r || md5) mod q
    h = hashlib.sha256()
    rbytes = r.to_bytes((r.bit_length()+7)//8 or 1, 'big')
    h.update(rbytes + md5_bytes)
    e = int.from_bytes(h.digest(), 'big') % q
    s = (k + x*e) % q
    return {"e": str(e), "s": str(s), "r": str(r)}

# --- Read file, prepare package ---
def prepare_package(filename, auditor_rsa_pub_pem, search_key):
    # read file bytes
    with open(filename, "rb") as f:
        data = f.read()

    # 1) compute MD5 digest of file (doctor requirement)
    digest = md5(data).digest()
    md5_hex = md5(data).hexdigest()

    # 2) ElGamal sign the md5 digest (toy)
    params = gen_elgamal_params(bits=160)  # small for speed; increase for real use
    x, y = elgamal_keygen(params)
    signature = elgamal_sign(params, x, digest)

    # 3) AES-GCM encrypt the file; then encrypt AES key with auditor's RSA public key
    aes_key = secrets.token_bytes(32)
    iv = secrets.token_bytes(12)
    encryptor = Cipher(algorithms.AES(aes_key), modes.GCM(iv)).encryptor()
    ciphertext = encryptor.update(data) + encryptor.finalize()
    tag = encryptor.tag

    # Load auditor RSA pub
    rsa_pub = serialization.load_pem_public_key(auditor_rsa_pub_pem)

    enc_aes_key = rsa_pub.encrypt(
        aes_key,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )

    # 4) Extract numeric budgets from file (simple heuristic): lines with "BUDGET: <number>"
    budgets = []
    for line in data.splitlines():
        try:
            t = line.decode(errors='ignore').strip()
            if t.upper().startswith("BUDGET:"):
                num = int(''.join(ch for ch in t.split(":",1)[1] if ch.isdigit()))
                budgets.append(num)
        except:
            pass

    # 5) Paillier-encrypt the budgets (use auditor's paillier pub if provided later; here we'll encrypt using our own local Paillier public that should match auditor's)
    # For simplicity we'll ask auditor for Paillier params after connection; but for this demo we'll include budget ciphertexts to send as ints (we'll encrypt using the n/g auditor sends back).
    # Instead, we'll set placeholders; real flow: client gets auditor's paillier pub and encrypts budgets with it.
    # We'll leave paillier_budgets empty for now; server will return paillier params which client can use in second round in a real protocol.

    # 6) Build deterministic tags (search): HMAC-SHA256(search_key, keyword)
    # Extract doctor names/branches heuristically from file lines like "DOCTOR: Name" / "BRANCH: X"
    tags=[]
    def make_tag(k):
        return hmac.new(search_key, k.encode(), hashlib.sha256).hexdigest()
    for line in data.splitlines():
        try:
            s=line.decode().strip()
            if s.upper().startswith("DOCTOR:"):
                tags.append(make_tag(s.split(":",1)[1].strip()))
            if s.upper().startswith("BRANCH:"):
                tags.append(make_tag(s.split(":",1)[1].strip()))
        except:
            pass

    package = {
        "filename": filename,
        "enc_aes_key": enc_aes_key.hex(),
        "iv": iv.hex(),
        "ciphertext": ciphertext.hex(),
        "tag_list": tags,
        "md5_hex": md5_hex,
        "elgamal_params": {"p": str(params["p"]), "g": str(params["g"]), "q": str(params["q"])},
        "elgamal_pub_y": str(y),
        "elgamal_signature": signature,
        # 'paillier_budgets' will be added after client obtains auditor paillier params in an extended protocol
        "paillier_budgets": [],   # placeholder (left empty to show structure)
    }
    return package, x  # return secret x to doctor (to allow doctor to show proof later if needed)

def send_package(package):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((HOST, PORT))
        send_msg(s, json.dumps(package).encode())
        resp = recv_msg(s)
        print("[Doctor] Auditor response:", resp.decode())

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python doctor_client.py inputfile.txt")
        sys.exit(1)
    filename = sys.argv[1]
    # In a real setup doctor would fetch auditor RSA public key from a trusted source.
    # For demo you can copy the PEM printed by auditor_server and paste below:
    auditor_rsa_pem = input("Paste auditor RSA public key PEM (end with blank line), then press Enter twice:\n")
    # For convenience allow reading from a file containing PEM:
    if auditor_rsa_pem.strip().endswith(".pem"):
        with open(auditor_rsa_pem.strip(), "rb") as f:
            auditor_rsa_pem = f.read()
    else:
        # read lines until blank line
        lines = []
        while True:
            line = sys.stdin.readline()
            if not line.strip():
                break
            lines.append(line)
        auditor_rsa_pem = (auditor_rsa_pem + "".join(lines)).encode()

    # search key (shared secret) for deterministic tags (doctor and auditor must agree on this key out-of-band)
    search_key = secrets.token_bytes(16)
    print("[Doctor] Using a one-time search key (in practice share securely):", search_key.hex())

    package, x = prepare_package(filename, auditor_rsa_pem, search_key)
    # include the search key hex so auditor can index tags (in real world this key is shared out-of-band!)
    package['search_key_hex'] = search_key.hex()

    send_package(package)
    print("[Doctor] Sent package.")
