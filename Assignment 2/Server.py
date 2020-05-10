"""
Submitted by Jeremy Stuart (UCID: 00311644)
CPSC 418: Introduction to cryptography
Winter 2020, Prof. Scheidler

Note: Must be started before Client.py  Time must be left for the values
to initialize before the Client can connect.
"""

import socket
import sys
import os
import ast
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from sympy import *
from secrets import *

HOST = '127.0.4.18'
PORT = 31802

# generated the value of q by generating random bits
def generateq():
    while True:
        number = randbits(511)
        # bit mask with 1 to make sure the number is odd
        test = bin(number)
        if len(test[2:]) == 511:
            #number = number | 1
            if isprime(number) == True:
                return number

# generates N using the q value returned by generateq()
def generateNg():
    while True:
        q = generateq()
        N = (q * 2) + 1
        if isprime(N) == True:
            g = primitive_root(N)
            return N, g
        else:
            continue


# beginning of main code
# generate N and g
N, g = generateNg()
sys.stdout.flush()
print("Server: N = " + str(N))
print("Server: g = " + str(g))
sys.stdout.flush()

# compute k = hash(N||g)
Nbytes = N.to_bytes(64, 'big')
gBytes = g.to_bytes(64, 'big')
tohash = b"".join([Nbytes, gBytes])

k = hashes.Hash(hashes.SHA256(), backend=default_backend())
k.update(tohash)
kBytes = k.finalize()
kDecimal = int.from_bytes(kBytes, 'big')
print("Server: k = " + str(kDecimal))
sys.stdout.flush()


with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as serv:

    serv.bind((HOST, PORT))
    print('Server listening...')

    serv.listen(20)

    conn, addr = serv.accept()

    ## conn is a new socket which is used to communicate with the client
    with conn:

        # send N and g to the Client upon the Client connecting
        # send as 64-byte number in big-endian format
        conn.send(Nbytes)
        conn.send(gBytes)
        print("Server: Sending N <" + Nbytes.hex() + ">")
        print("Server: Sending g <" + gBytes.hex() + ">")
        sys.stdout.flush()

        # receive ('r', |I|, I, s, v) from Client
        rByte = conn.recv(1)
        r = rByte.decode('utf-8')
        iSize = conn.recv(4)
        iSize = int.from_bytes(iSize,'big')
        IBytes = conn.recv(iSize)
        I = IBytes.decode('utf-8')
        s = conn.recv(16)
        vBytes = conn.recv(64)
        v = int.from_bytes(vBytes, 'big')
        
        print("Server: r = " + r)
        print("Server: |I| = " + str(iSize))
        print("Server: I = '" + I + "'")
        print("Server: s = <" + s.hex() + ">")
        print("Server: v = " + str(v))
        sys.stdout.flush()

        # print message that this has succesfully completed
        print("Server:  Registration successful.")
        sys.stdout.flush()

        # close connection
        # conn.close()

        serv.listen(20)

        conn, addr = serv.accept()

        # send N and g to the Client upon the Client connecting
        # send as 64-byte number in big-endian format
        conn.send(Nbytes)
        conn.send(gBytes)
        print("Server: Sending N <" + Nbytes.hex() + ">")
        print("Server: Sending g <" + gBytes.hex() + ">")
        sys.stdout.flush()

        # receive ('p', |I|, I , A) from Client
        pByte = conn.recv(1)
        p = pByte.decode('utf-8')
        iSize = int.from_bytes(conn.recv(4), 'big')
        IBytes = conn.recv(iSize)
        I = IBytes.decode('utf-8')
        ABytes = conn.recv(64)
        A = int.from_bytes(ABytes, 'big')

        print("Server: flag = " + p)
        print("Server: |I| = " + str(iSize))
        print("Server: A = " + str(A))
        sys.stdout.flush()

        # choose 0 <= b <= N-2
        b = randbelow(N-1)
        print("Server: b = " + str(b))

        # compute B = kv + g^b (mod N)
        kv = pow(kDecimal * v, 1, N)
        gb = pow(g, b, N)
        kvgb = kv + gb
        B = pow(kvgb, 1, N)
        print("Server: B = " + str(B))


        # send tuple (s, B)
        BByte = B.to_bytes(64, 'big')
        conn.send(s)
        conn.send(BByte)
        print("Server: Sending s <" + s.hex() + ">")
        print("Server: Sending B <" + BByte.hex() + ">")
        sys.stdout.flush()

        # compute u = hash(A||B) (mod N)             
        ABytes = A.to_bytes(64, 'big')
        BBytes = B.to_bytes(64, 'big')
        tohash = b"".join([ABytes, BBytes])
        u = hashes.Hash(hashes.SHA256(), backend=default_backend())
        u.update(tohash)
        u = u.finalize()
        uDecimal = int.from_bytes(u, 'big')
        print("Server: u = " + str(uDecimal))
        sys.stdout.flush()

        # compute Kserver = (Av^u)^b (mod N)            
        vu = pow(v, uDecimal, N)
        Ainside = pow(A, 1, N)
        Ainside = Ainside * vu
        Kserver = pow(Ainside, b, N)
        print("Server: k_server = " + str(Kserver))
        sys.stdout.flush()

        # receive M1 from Client
        M1 = conn.recv(64)
        print("Server: M1 = <" + M1.hex() + ">")
        sys.stdout.flush()

        # compute hash(A||B||Kserver) and compare to M1
        # output string indicating success,  or output failure, close socket, and abort
        KserverBytes = Kserver.to_bytes(64, 'big')
        tohash = b"".join([ABytes, BBytes, KserverBytes])
        temp1 = hashes.Hash(hashes.SHA256(), backend=default_backend())
        temp1.update(tohash)
        temp1 = temp1.finalize()

        if temp1 == M1:
            print("Server: Negotiation successful")
        else:
            print("Server: Negotiation unsuccessful")
        sys.stdout.flush()

        # compute M2 = hash(A||M1||Kserver), if they match output string indicating
        # success
        tohash = ABytes + M1 + KserverBytes
        M2 = hashes.Hash(hashes.SHA256(), backend=default_backend())
        M2.update(tohash)
        M2 = M2.finalize()

        # send Client M2
        conn.send(M2)
        print("Server: Sending M2 <" + M2.hex() + ">")
        sys.stdout.flush()
        sys.exit(0)
