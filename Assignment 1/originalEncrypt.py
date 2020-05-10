from cryptography import *
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import sys
import os

def encryption(B, password):
    # apply sha-1 to B to create t
    t = hashes.Hash(hashes.SHA1(), backend=default_backend())
    t.update(B)
    t = t.finalize()

    # append t to B, result is B'
    Bprime = B + t

    # convert password to bytes
    password_bytes = bytearray(password, 'utf-8')

    # apply SHA1 to password to derive encryption key
    key = hashes.Hash(hashes.SHA1(), backend=default_backend())
    key.update(password_bytes)
    key = key.finalize()

    # change key back to bytearray slice to 16 bytes for AES
    key = bytearray(key)
    key = key[:16]

    # generate random 16 byte IV
    iv = os.urandom(16)

    # write iv to F
    file = open("F", 'wb')
    file.write(iv)

    # pad B' using PKCS7
    Bprime = bytes(Bprime)
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(Bprime)
    padded_data = padded_data + padder.finalize()

    # Encrypt padded_data with AES-128 in CBC mode
    cipher_ob = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher_ob.encryptor()
    ct = encryptor.update(padded_data) + encryptor.finalize()

    file.write(ct)
    file.close()

# setup file name and password as variables
fileName = sys.argv[1]
password = sys.argv[2]

# open file name specified as arg1 as bytes (with rb option in file open)
f = open(fileName, "r")
B = f.read()
f.close()

# convert to bytearray
B = bytearray(B, 'utf-8')

encryption(B, password)
