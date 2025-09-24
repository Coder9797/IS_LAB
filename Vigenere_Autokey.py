# ---------------------------------------------------------
# Classical Ciphers: Vigenère Cipher and Autokey Cipher
# ---------------------------------------------------------
# This program implements:
# 1. Vigenère Cipher (encrypt & decrypt)
# 2. Autokey Cipher (encrypt & decrypt)
# Both ciphers are based on shifting letters using keys,
# with modular arithmetic (mod 26 for English alphabets).
# ---------------------------------------------------------


# Dictionary mapping: letter -> number (a=0, b=1, ..., z=25)
letter_to_num = {ch: i for i, ch in enumerate('abcdefghijklmnopqrstuvwxyz')}
# Reverse mapping: number -> letter (0=a, 1=b, ..., 25=z)
num_to_letter = {i: ch for i, ch in enumerate('abcdefghijklmnopqrstuvwxyz')}


# Function to preprocess text:
# Converts all letters to lowercase, keeps non-letters unchanged.
def preprocess_text(text):
    return ''.join(ch.lower() if ch.isalpha() else ch for ch in text)


# ---------------- VIGENÈRE CIPHER ----------------
def vigenere_encrypt(key, plaintext):
    """
    Encrypts plaintext using the Vigenère cipher.
    Formula: C = (P + K) mod 26
    """
    ciphertext = []
    key = key.lower()               # ensure key is lowercase
    key_len = len(key)
    key_nums = [letter_to_num[k] for k in key]   # convert key letters to numbers

    j = 0   # index for key
    for ch in plaintext:
        if ch.isalpha():
            p = letter_to_num[ch]         # number form of plaintext char
            k = key_nums[j % key_len]     # repeat key cyclically
            c = (p + k) % 26              # encryption formula
            ciphertext.append(num_to_letter[c])  # convert back to letter
            j += 1
        else:
            ciphertext.append(ch)   # keep non-letters unchanged
    return ''.join(ciphertext)


def vigenere_decrypt(key, ciphertext):
    """
    Decrypts ciphertext using the Vigenère cipher.
    Formula: P = (C - K) mod 26
    """
    plaintext = []
    key = key.lower()
    key_len = len(key)
    key_nums = [letter_to_num[k] for k in key]

    j = 0
    for ch in ciphertext:
        if ch.isalpha():
            c = letter_to_num[ch]
            k = key_nums[j % key_len]
            p = (c - k) % 26              # decryption formula
            plaintext.append(num_to_letter[p])
            j += 1
        else:
            plaintext.append(ch)
    return ''.join(plaintext)


# ---------------- AUTOKEY CIPHER ----------------
def autokey_encrypt(key, plaintext):
    """
    Encrypts plaintext using the Autokey cipher.
    Formula: C = (P + K) mod 26
    The key is extended by appending plaintext letters.
    """
    ciphertext = []
    key = key.lower()
    key_nums = [letter_to_num[k] for k in key]

    # Extend the key: key + plaintext letters
    extended_key = key_nums + [letter_to_num[ch] for ch in plaintext if ch.isalpha()]

    j = 0
    for ch in plaintext:
        if ch.isalpha():
            p = letter_to_num[ch]
            k = extended_key[j]     # use extended key
            c = (p + k) % 26
            ciphertext.append(num_to_letter[c])
            j += 1
        else:
            ciphertext.append(ch)
    return ''.join(ciphertext)


def autokey_decrypt(key, ciphertext):
    """
    Decrypts ciphertext using the Autokey cipher.
    Formula: P = (C - K) mod 26
    The key is reconstructed on the fly using plaintext.
    """
    plaintext = []
    key = key.lower()
    key_nums = [letter_to_num[k] for k in key]

    j = 0
    for ch in ciphertext:
        if ch.isalpha():
            c = letter_to_num[ch]
            if j < len(key_nums):
                # Use original key letters first
                k = key_nums[j]
            else:
                # After key is exhausted, use previously decrypted plaintext
                k = letter_to_num[plaintext[j - len(key_nums)]]
            p = (c - k) % 26
            plaintext.append(num_to_letter[p])
            j += 1
        else:
            plaintext.append(ch)
    return ''.join(plaintext)


# ---------------- MAIN (Example Usage) ----------------
if __name__ == "__main__":
    pt = "HELLO, World!"   # original plaintext
    key = "KEY"            # secret key

    pt_processed = preprocess_text(pt)   # convert to lowercase
    print("Plaintext:", pt)
    print("Processed:", pt_processed)

    # --- Vigenère Cipher ---
    ct_vig = vigenere_encrypt(key, pt_processed)
    print("Vigenère Encrypted:", ct_vig)
    print("Vigenère Decrypted:", vigenere_decrypt(key, ct_vig))

    # --- Autokey Cipher ---
    ct_auto = autokey_encrypt(key, pt_processed)
    print("Autokey Encrypted:", ct_auto)
    print("Autokey Decrypted:", autokey_decrypt(key, ct_auto))
