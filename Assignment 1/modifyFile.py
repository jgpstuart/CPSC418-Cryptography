from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import sys
import os
import datetime

"""
Submitted by Jeremy Stuart (UCID: 00311644)
CPSC 418: Introduction to cryptography
Winter 2020, Prof. Scheidler

Note: Coding was done in collaboration with Emily Baird (10097606)
as such there may be segments of code that are very similar.  She
assisted with familiarizing me with the cryptography library, and
I assisted her with python functionality for working with bytes
and array slicing.

This is the modifyFile program.  The output file will be titled:
"modifiedPlaintext.txt".
"""


"""
Main loop for brute forcing the password
1) Choose date
2) SHA1 the date to get password
3) Unencrypt Bprime in AES-128-CBC using IV and guessesed password
4) Check resulting string for "Foxhound"
5) break if Foxhound found, otherwise iterate with date = day + 1
"""
def bruteForce(IV, Bprime):
    guess = datetime.datetime(1984,1,1)  #date object to increment for password
    today = datetime.datetime.today()
    while(guess <= today):
        #create password from date, into bytearray
        password = bytearray(guess.strftime("%Y%m%d"), 'utf-8')

        #SHA1 the password from last step
        key = hashes.Hash(hashes.SHA1(), backend=default_backend())
        key.update(password)
        key = key.finalize()
        key = key[:16]

        #Decrypt BPrime with IV and guessed password
        cipher = Cipher(algorithms.AES(key), modes.CBC(IV), backend=default_backend())
        decryptor = cipher.decryptor()
        plainbytes = decryptor.update(Bprime) + decryptor.finalize()

        keyPhrase = bytes("FOXHOUND", 'utf-8')
        if keyPhrase in plainbytes:
            return guess.strftime("%Y%m%d"), plainbytes
        else:
            guess += datetime.timedelta(days=1)


"""
Replace CODE-RED with CODE-BLUE and run encryption algorithm on it again
"""
def codeRed(plaintext, password):
    #unpad the password_bytes
    unpadder = padding.PKCS7(128).unpadder()
    plaintext = unpadder.update(plaintext)
    plaintext = plaintext + unpadder.finalize()

    #remove the 20 bytes from SHA1 of the plaintext
    plaintext = plaintext[:-20]

    #Replace CODE-RED with CODE-BLUE
    plaintext = plaintext.decode()
    plaintext = plaintext.replace("CODE-RED", "CODE-BLUE")

    writeFile(plaintext)

"""
Writes the plaintext (modified or otherwise) to a file called
"modifiedPlaintext.txt"
"""
def writeFile(plaintext):
    f = open("modifiedPlaintext.txt", "w+")
    f.write(plaintext)
    f.close()

# setup file name and password as variables
cipherText = sys.argv[1]

# open file name specified as arg1 as bytes (with rb option in file open)
f = open(cipherText, "rb")
B = f.read()
f.close()

# convert to bytearray
B = bytearray(B)

# slice IV and Bprime off of the ciphertext
IV = B[:16]
Bprime = B[16:]

# run bruteForce to find the password, print password
foundPassword, plaintext = bruteForce(IV, Bprime)
print("The password is: " + foundPassword)



# check to see if CODE-RED in plaintext
trigger = bytes("CODE-RED", 'utf-8')
if trigger in plaintext:
    codeRed(plaintext, foundPassword)
else:
    writeFile(plaintext)
