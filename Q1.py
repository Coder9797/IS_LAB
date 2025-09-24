# Create a mapping from letters to numbers: 'a' -> 0, 'b' -> 1, ..., 'z' -> 25
letter_to_num = {ch: i for i, ch in enumerate('abcdefghijklmnopqrstuvwxyz')}

# Create the reverse mapping: 0 -> 'a', 1 -> 'b', ..., 25 -> 'z'
num_to_letter = {i: ch for i, ch in enumerate('abcdefghijklmnopqrstuvwxyz')}


# Function to compute the modular inverse of 'a' under modulo m (default m=26 for English alphabet)
def mod_inverse(a, m=26):
    a = a % m  # ensure a is within modulo range
    for x in range(1, m):   # brute-force check from 1 to m-1
        if (a * x) % m == 1:   # condition for modular inverse
            return x
    return None   # return None if no modular inverse exists


# ---------- ADDITIVE CIPHER ----------
def additive_encrypt(key, plaintext):
    ct = ""  # ciphertext string
    for ch in plaintext:
        if ch.isalpha():  # only encrypt letters
            is_upper = ch.isupper()     # preserve uppercase
            base = ch.lower()           # work in lowercase
            ctc_code = (letter_to_num[base] + key) % 26  # shift by key (mod 26)
            ctc = num_to_letter[ctc_code]   # convert back to letter
            ct += ctc.upper() if is_upper else ctc  # restore original case
        else:
            ct += ch  # keep non-letters unchanged
    return ct


def additive_decrypt(key, ciphertext):
    pt = ""  # plaintext string
    for ch in ciphertext:
        if ch.isalpha():
            is_upper = ch.isupper()
            base = ch.lower()
            ptc_code = (letter_to_num[base] - key) % 26  # reverse shift
            ptc = num_to_letter[ptc_code]
            pt += ptc.upper() if is_upper else ptc
        else:
            pt += ch
    return pt


# ---------- MULTIPLICATIVE CIPHER ----------
def multiplicative_encrypt(key, plaintext):
    ct = ""
    for ch in plaintext:
        if ch.isalpha():
            is_upper = ch.isupper()
            base = ch.lower()
            ctc_code = (letter_to_num[base] * key) % 26  # multiply by key (mod 26)
            ctc = num_to_letter[ctc_code]
            ct += ctc.upper() if is_upper else ctc
        else:
            ct += ch
    return ct


def multiplicative_decrypt(key, ciphertext):
    pt = ""
    inv_key = mod_inverse(key)   # need modular inverse of key to decrypt
    if inv_key is None:          # if no inverse exists, decryption is impossible
        return None
    for ch in ciphertext:
        if ch.isalpha():
            is_upper = ch.isupper()
            base = ch.lower()
            ptc_code = (letter_to_num[base] * inv_key) % 26  # multiply by inverse
            ptc = num_to_letter[ptc_code]
            pt += ptc.upper() if is_upper else ptc
        else:
            pt += ch
    return pt


# ---------- AFFINE CIPHER (combination of multiplicative + additive) ----------
def affine_encrypt(key_a, key_b, plaintext):
    ct = ""
    for ch in plaintext:
        if ch.isalpha():
            is_upper = ch.isupper()
            base = ch.lower()
            # encryption formula: E(x) = (a*x + b) mod 26
            ctc_code = (letter_to_num[base] * key_a + key_b) % 26
            ctc = num_to_letter[ctc_code]
            ct += ctc.upper() if is_upper else ctc
        else:
            ct += ch
    return ct


def affine_decrypt(key_a, key_b, ciphertext):
    pt = ""
    inv_key_a = mod_inverse(key_a)   # find modular inverse of multiplicative key
    if inv_key_a is None:            # if no inverse exists, can't decrypt
        return None
    for ch in ciphertext:
        if ch.isalpha():
            is_upper = ch.isupper()
            base = ch.lower()
            # decryption formula: D(y) = inv_a * (y - b) mod 26
            ptc_code = (inv_key_a * (letter_to_num[base] - key_b)) % 26
            ptc = num_to_letter[ptc_code]
            pt += ptc.upper() if is_upper else ptc
        else:
            pt += ch
    return pt


# ---------- MAIN PROGRAM ----------
def main():
    message = input("Enter original message: ")   # user input
    print("Original message:", message)
    plaintext = message   # treat message as plaintext
    print("Plaintext (unchanged):", plaintext)

    while True:  # menu loop
        print("\nChoose cipher:")
        print("1. Additive cipher")
        print("2. Multiplicative cipher")
        print("3. Affine cipher")
        print("4. Exit")

        choice = input("Enter choice (1-4): ").strip()

        if choice == '1':
            try:
                key = int(input("Enter additive key (integer): "))
            except ValueError:   # error handling if input is not integer
                print("Invalid input. Try again.")
                continue
            ciphertext = additive_encrypt(key, plaintext)
            decrypted = additive_decrypt(key, ciphertext)
            print("Encrypted text:", ciphertext)
            print("Decrypted text:", decrypted)

        elif choice == '2':
            try:
                key = int(input("Enter multiplicative key (integer coprime with 26): "))
                if mod_inverse(key) is None:  # check key validity
                    print("Key is not coprime with 26, no modular inverse. Try again.")
                    continue
            except ValueError:
                print("Invalid input. Try again.")
                continue
            ciphertext = multiplicative_encrypt(key, plaintext)
            decrypted = multiplicative_decrypt(key, ciphertext)
            if decrypted is None:
                print("Error: No modular inverse found. Can't decrypt.")
            else:
                print("Encrypted text:", ciphertext)
                print("Decrypted text:", decrypted)

        elif choice == '3':
            try:
                key_a = int(input("Enter multiplicative key a (coprime with 26): "))
                if mod_inverse(key_a) is None:   # check if a is valid
                    print("Key a is not coprime with 26, no modular inverse.")
                    continue
                key_b = int(input("Enter additive key b (integer): "))
            except ValueError:
                print("Invalid input.")
                continue
            ciphertext = affine_encrypt(key_a, key_b, plaintext)
            decrypted = affine_decrypt(key_a, key_b, ciphertext)
            if decrypted is None:
                print("Error: No modular inverse found. Can't decrypt.")
            else:
                print("Encrypted text:", ciphertext)
                print("Decrypted text:", decrypted)

        elif choice == '4':   # exit option
            print("Exiting program.")
            break
        else:
            print("Invalid choice, try again.")


# Entry point for program execution
if __name__ == "__main__":
    main()
