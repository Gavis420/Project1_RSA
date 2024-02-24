# Algorithms Project 1 - RSA
# Objective: implement RSA Encryption and apply it to digital signature
import pandas as pd
import numpy as np
import sys
import random
import hashlib

# python main.py
# python main.py 2 s "file.txt"
# python main.py 2 v "file.txt.signed"

# check if p is prime (most likely a prime)
def FermatPrimalityTest(p, iterations=50):
    if p == 2 or p == 3:
        return True
    if p <= 1 or p % 2 == 0:
        return False
    for _ in range(iterations):
        a = random.randint(2, p - 2)
        if pow(a, p - 1, p) != 1:
            return False
    return True


def generate_large_prime(bit_size):
    while True:
        p = random.getrandbits(bit_size)
        # Ensure p is odd
        p |= 1
        if FermatPrimalityTest(p):
            return p


def RSA_key_generation():
    # Generate two large prime numbers
    p = generate_large_prime(512)
    q = generate_large_prime(512)

    # Calculate n and phi(n)
    n = p * q

    # Choose e such that 1 < e < phi(n) and gcd(e, phi(n)) = 1
    phi_n = (p - 1) * (q - 1)
    e = random.randint(2, phi_n - 1)
    while np.gcd(e, phi_n) != 1:
        e = random.randint(2, phi_n - 1)

    # Compute d, the modular multiplicative inverse of e mod phi(n)
    d = pow(e, -1, phi_n)

    # Save p and q
    with open("p_q.csv", "w") as pq_file:
        pq_file.write(str(p) + "\n")
        pq_file.write(str(q))

    # Save (e, n)
    with open("e_n.csv", "w") as en_file:
        en_file.write(str(e) + "\n")
        en_file.write(str(n))

    # Save (d, n)
    with open("d_n.csv", "w") as dn_file:
        dn_file.write(str(d) + "\n")
        dn_file.write(str(n))

    print("done with key generation!")


def Signing(doc, key):
    match = False

    # Define the file name
    file_name = 'file.txt'

    # Open the file in binary mode
    with open(file_name, 'rb') as file:
        # Read the contents of the file
        contents = file.read()

        # Compute the SHA-256 hash of the file contents
        h = hashlib.sha256(contents)

        # Get the hexadecimal representation of the hash
        hash_hex = h.hexdigest()

        # Convert hexadecimal representation to base-10 integer
        hash_base10 = int(hash_hex, 16)

    # Read values from d_n.csv
    with open('d_n.csv', 'r') as file:
        # Read the first line as the exponent
        d_signing = int(file.readline().strip())

        # Read the second line as the modulus
        n_signing = int(file.readline().strip())

    # Compute my signature
    signature = pow(hash_base10, d_signing, n_signing)

    # Read the original content of 'file.txt'
    with open('file.txt', 'r') as file:
        original_content = file.read()

    # Combine the original content with the result
    signed_content = original_content + '\n' + str(signature)

    # Write the combined content to a new file called 'file.txt.signed'
    with open('file.txt.signed', 'w') as file_signed:
        file_signed.write(signed_content)

    print("\nSigned ...")


def verification(doc, key):

    match = False

    # Read the content of the signed file
    with open('file.txt.signed', 'r') as signed_file:
        signed_content = signed_file.read().strip()

    # Extract the original text and the signature
    original_text, signature = signed_content.rsplit('\n', 1)

    # Compute the SHA-256 hash of the file contents and get the new hash
    new_hash = hashlib.sha256(original_text.encode()).hexdigest()

    # Convert hexadecimal representation to base-10 integer
    new_hash_base10 = int(new_hash, 16)

    # Read values from e_n.csv
    with open('e_n.csv', 'r') as file:
        # Read the first line as the exponent
        e_verifying = int(file.readline().strip())

        # Read the second line as the modulus
        n_verifying = int(file.readline().strip())

    # Read values from d_n.csv
    with open('d_n.csv', 'r') as file:
        # Read the first line as the exponent
        d_verifying = int(file.readline().strip())

        # Read the second line as the modulus
        n_verifying2 = int(file.readline().strip())

    # Compute new signature
    new_signature = pow(new_hash_base10, d_verifying, n_verifying2)

    # Compute the new signature and limit it to 32 bits
    verified_signature = pow(new_signature, e_verifying, n_verifying)

    # does the signature match
    if signature == verified_signature:
        match = True

    if match:
        print("\nAuthentic!")
    else:
        print("\nModified!")


# No need to change the main function.
def main():
    # part I, command-line arguments will be: python yourProgram.py 1
    if int(sys.argv[1]) == 1:
        RSA_key_generation()
    # part II, command-line will be for example: python yourProgram.py 2 s file.txt
    #                                       or   python yourProgram.py 2 v file.txt.signed
    else:
        (task, fileName) = sys.argv[2:]
        if "s" in task:  # do signing
            doc = None  # you figure out
            key = None  # you figure out
            Signing(doc, key)
        else:
            # do verification
            doc = None   # you figure out
            key = None   # you figure out
            verification(doc, key)

    print("done!")


if __name__ == '__main__':
    main()
