"""
Submitted by Jeremy Stuart (UCID: 00311644)
CPSC 418: Introduction to cryptography
Winter 2020, Prof. Scheidler

Note: Must be started after Server.py
"""

import socket
import time
import sys
import ast
import os
from secrets import *
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

HOST = "127.0.4.18"   
PORT = 31802

# prompt user for username (I) and password (p)
print("Enter username: ")
I = sys.stdin.readline()
I = I.strip('\n')
print("Enter password: ")
p = sys.stdin.readline()
p = p.strip('\n')
print("Client: I = '" + I + "'")
print("Client: p = " + p)

# connect to server
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as conn:
    #connect to server
    conn.connect((HOST, PORT))

    #receive N and g
    NBytes = conn.recv(64)
    gBytes = conn.recv(64)
    N = int.from_bytes(NBytes, 'big')
    g = int.from_bytes(gBytes, 'big')
    print("Client: N = " + str(N))
    print("Client: g = " + str(g))

    # compute k = hash(N||g)
    Nbytes = N.to_bytes(64, 'big')
    gBytes = g.to_bytes(64, 'big')
    tohash = b"".join([Nbytes,gBytes])

    k = hashes.Hash(hashes.SHA256(), backend=default_backend())
    k.update(tohash)
    k = k.finalize()
    print("Client: k = " + str(int.from_bytes(k, 'big')))

    # generate a random 16-byte salt (s)
    s = os.urandom(16)
    print("Client: s = <" + s.hex() + ">")

    # compute x = H(s||p)
    pBytes = p.encode('utf-8')
    tohash = b"".join([s, pBytes])

    x = hashes.Hash(hashes.SHA256(), backend=default_backend())
    x.update(tohash)
    x = x.finalize()
    xDecimal = int.from_bytes(x, 'big')
    print("Client: x = " + str(xDecimal))

    # compute v = g^x (mod N)
    v = pow(g,xDecimal,N)
    vByte = v.to_bytes(64, 'big')
    print("Client: v = " + str(v))

    # Transmit ('r',|I|,I,s,v) to the Server
    r = 'r'
    rByte = r.encode('utf-8')
    conn.send(rByte)
    iSize = len(I).to_bytes(4, 'big')
    conn.send(iSize)
    IBytes = I.encode('utf-8')
    conn.send(IBytes)
    conn.send(s)
    conn.send(vByte)
    print("Client: Sending r <" + rByte.hex() + ">")
    print("Client: Sending |I| <" + iSize.hex() + ">")
    print("Client: Sending I <" + IBytes.hex() + ">")
    print("Client: Sending v <" + vByte.hex() + ">")

    # dispose of x (del x)
    del(x)
    print("Client: Registration successful.")

    # close the socket
    conn.close()
    time.sleep(1)

# PROTOCOL
# reconnect to the Server
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as conn:
    #connect to server
    conn.connect((HOST, PORT))

    NBytes = conn.recv(64)
    gBytes = conn.recv(64)
    N = int.from_bytes(NBytes, 'big')
    g = int.from_bytes(gBytes, 'big')
    print("Client: N =", str(N))
    print("Client: g =", str(g))

    # compute k = hash(N||g)
    Nbytes = N.to_bytes(64, 'big')
    gBytes = g.to_bytes(64, 'big')
    tohash = b"".join([Nbytes, gBytes])

    k = hashes.Hash(hashes.SHA256(), backend=default_backend())
    k.update(tohash)
    k = k.finalize()
    print("Client: k = " + str(int.from_bytes(k, 'big')))

    # choose 0 <= a <= N-2
    a = randbelow(N-1)
    print("Client: a = " + str(a))


    # compute A = g^a (mod N)
    A = pow(g, a, N)
    ABytes = A.to_bytes(64, 'big')
    print("Client: A = " + str(A))

    # send ('p', |I|, I, A) to Server
    pflag = 'p'
    pByte = pflag.encode('utf-8')
    conn.send(pByte)
    iSize = len(I).to_bytes(4, 'big')
    conn.send(iSize)
    conn.send(IBytes)
    conn.send(ABytes)

    print("Client: Sending flag <" + pByte.hex() + ">")
    print("Client: Sending |I| <" + iSize.hex() + ">")
    print("Client: Sending I <" + IBytes.hex() + ">")
    print("Client: Sending A <" + ABytes.hex() + ">")

    # receive (s, B) from Server
    s = conn.recv(16)
    BBytes = conn.recv(64)
    B = int.from_bytes(BBytes, 'big')

    print("Client: s <" + s.hex() + ">")
    print("Client: B = " + str(B))

    # compute u = hash(A||B) (mod N)
    BBytes = B.to_bytes(64, 'big')
    
    tohash = b"".join([ABytes, BBytes])
    u = hashes.Hash(hashes.SHA256(), backend=default_backend())
    u.update(tohash)
    u = u.finalize()
    print("Client: u = " + str(int.from_bytes(u, 'big')))

    # compute Kclient = (B - kv) ^ (a + ux) (mod N)
    kDecimal = int.from_bytes(k, 'big')
    uDecimal = int.from_bytes(u, 'big')
    Binside = pow(B, 1, N)
    kv = pow(kDecimal * v, 1, N)
    Kclient = pow(Binside - kv, (a + uDecimal * xDecimal), N)
    print("Client: k_client = " + str(Kclient))

    # calculate M1 = hash(A||B||Kclient) and send to Server
    KclientBytes = Kclient.to_bytes(64, 'big')
    tohash = b"".join([ABytes, BBytes, KclientBytes])
    M1 = hashes.Hash(hashes.SHA256(), backend=default_backend())
    M1.update(tohash)
    M1 = M1.finalize()
    print("Client: M1 = <" + M1.hex() + ">")

    # SEND AND RECEIVE M1 AND M2 AS 32 BYTES
    conn.send(M1)

    # receive M2 from the Server
    M2 = conn.recv(64)
    print("Client: M2 = <" + M2.hex() + ">")

    # compute hash(A||M1||Kclient)
    tohash = b"".join([ABytes, M1, KclientBytes])
    temp2 = hashes.Hash(hashes.SHA256(), backend=default_backend())
    temp2.update(tohash)
    temp2 = temp2.finalize()

    if temp2 == M2:
        print("Client: Negotiation successful")
    else:
        print("Client: Negotiation unsuccessful")
