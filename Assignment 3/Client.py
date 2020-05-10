"""
Submitted by Jeremy Stuart (UCID: 00311644)
CPSC 418: Introduction to Cryptography
Winter 2020, Prof. Scheidler

Note: Must be started after Server.py
"""

from RSA import generateRSAKey
import socket
import time
import sys
import ast
import os
from secrets import *
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding

HOST = "127.0.4.18"
TTP_PORT = 31802   
SERVER_PORT = 31803

# prompt user for username (I) and password (p)
print("Enter username: ")
I = sys.stdin.readline()
I = I.strip('\n')
print("Enter password: ")
p = sys.stdin.readline()
p = p.strip('\n')
print("Client: I = '" + I + "'")
print("Client: p = " + p)

# generate RSA values
client_p, client_q, client_N, client_phiN, client_e, client_d = generateRSAKey()

client_Nbytes = client_N.to_bytes(128,'big')
client_ebytes = client_e.to_bytes(128, 'big')
client_PKbytes = b"".join([client_Nbytes, client_ebytes])
client_PK = int.from_bytes(client_PKbytes, 'big')

print("Client: Client_p = " + str(client_p))
print("Client: Client_q = " + str(client_q))
print("Client: Client_N = " + str(client_N))
print("Client: Client_e = " + str(client_e))
print("Client: Client_d = " + str(client_d))
print("Client: Client_PK = " + str(client_PK))

time.sleep(2)

# connect to TTP
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as serv:
    # connect to the TTP server
    serv.connect((HOST, TTP_PORT))

    # send REQUEST KEY
    request = "REQUEST KEY"
    print("Client: Sending 'REQUEST KEY'")
    request = request.encode('utf-8')
    serv.send(request)

    # receive TTP_N and TTP_SIG
    TTP_Nbytes = serv.recv(128)
    TTP_N = int.from_bytes(TTP_Nbytes,'big')
    print("Client: Receiving TTP_N = " + str(TTP_N))
    sys.stdout.flush()
    print("Client: TTP_N = " + str(TTP_N))
    sys.stdout.flush()
    TTP_ebytes = serv.recv(128)
    TTP_e = int.from_bytes(TTP_ebytes,'big')
    print("Client: Receiving TTP_e = " + str(TTP_e))
    sys.stdout.flush()
    print("Client: TTP_e = " + str(TTP_e))
    sys.stdout.flush()

    # close connection
    serv.close()



# REGISTRATION STEP
# connect to server
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as conn:
    #connect to server
    conn.connect((HOST, SERVER_PORT))

    # receive N and g
    NBytes = conn.recv(64)
    gBytes = conn.recv(64)
    N = int.from_bytes(NBytes, 'big')
    g = int.from_bytes(gBytes, 'big')
    print("Client: N = " + str(N))
    sys.stdout.flush()
    print("Client: g = " + str(g))
    sys.stdout.flush()

    # compute k = hash(N||g)
    Nbytes = N.to_bytes(64, 'big')
    gBytes = g.to_bytes(64, 'big')
    tohash = b"".join([Nbytes,gBytes])

    k = hashes.Hash(hashes.SHA3_256(), backend=default_backend())
    k.update(tohash)
    k = k.finalize()
    print("Client: k = " + str(int.from_bytes(k, 'big')))
    sys.stdout.flush()

    # generate a random 16-byte salt (s)
    s = os.urandom(16)
    print("Client: s = <" + s.hex() + ">")
    sys.stdout.flush()

    # compute x = H(s||p)
    pBytes = p.encode('utf-8')
    tohash = b"".join([s, pBytes])

    x = hashes.Hash(hashes.SHA3_256(), backend=default_backend())
    x.update(tohash)
    x = x.finalize()
    xDecimal = int.from_bytes(x, 'big')
    print("Client: x = " + str(xDecimal))
    sys.stdout.flush()

    # compute v = g^x (mod N)
    v = pow(g,xDecimal,N)
    vByte = v.to_bytes(64, 'big')
    print("Client: v = " + str(v))
    sys.stdout.flush()

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
    sys.stdout.flush()
    print("Client: Sending |I| <" + iSize.hex() + ">")
    sys.stdout.flush()
    print("Client: Sending I <" + IBytes.hex() + ">")
    sys.stdout.flush()
    print("Client: Sending v <" + vByte.hex() + ">")
    sys.stdout.flush()

    # dispose of x (del x)
    del(x)
    print("Client: Registration successful.")

    # close the socket
    conn.close()
    time.sleep(1)

# connect to server
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as conn:
    # reconnect to the Server
    conn.connect((HOST, SERVER_PORT))

    # receive N and g again
    NBytes = conn.recv(64)
    gBytes = conn.recv(64)
    N = int.from_bytes(NBytes, 'big')
    g = int.from_bytes(gBytes, 'big')
    print("Client: N = " + str(N))
    sys.stdout.flush()
    print("Client: g = " + str(g))
    sys.stdout.flush()

    # send 'p'||len(I)||I
    pflag = 'p'
    pByte = pflag.encode('utf-8')
    conn.send(pByte)
    iSize = len(I).to_bytes(4, 'big')
    conn.send(iSize)
    conn.send(IBytes)
    print("Client: Sending flag <" + pByte.hex() + ">")
    sys.stdout.flush()
    print("Client: Sending |I| <" + iSize.hex() + ">")
    sys.stdout.flush()
    print("Client: Sending I <" + IBytes.hex() + ">")
    sys.stdout.flush()

    # receive len(S)||S||server_N||server_e||TTP_SIG
    sSize = int.from_bytes(conn.recv(4), 'big')
    print("Client: |S| = " + str(sSize))
    sys.stdout.flush()

    Sbytes = conn.recv(sSize)
    S = Sbytes.decode('utf-8')
    print("Client: S = '" + str(S) + "'")
    sys.stdout.flush()

    server_Nbytes = conn.recv(128)
    server_N = int.from_bytes(server_Nbytes,'big')
    print("Client: Server_N = " + str(server_N))
    sys.stdout.flush()

    server_ebytes = conn.recv(128)
    server_e = int.from_bytes(server_ebytes, 'big')
    print("Client: Server_e = " + str(server_e))
    sys.stdout.flush()

    TTP_SIGbytes = conn.recv(256)
    TTP_SIG = int.from_bytes(TTP_SIGbytes, 'big')
    print("Client: TTP_SIG = " + str(TTP_SIG))
    sys.stdout.flush()
    

    # VERIFY TTP_SIG
    # join Server_N and Server_e to form Server_PK
    server_PKbytes = b"".join([server_Nbytes, server_ebytes])

    #join server_S and server_PK to prepare for hasing
    toHash = b"".join([Sbytes, server_PKbytes])

    # hash  (Server_N||server_PK) to get t
    t = hashes.Hash(hashes.SHA3_512(), backend=default_backend())
    t.update(toHash)
    tbytes = t.finalize()

    # hash tbytes to get tprimebytes
    tprime = hashes.Hash(hashes.SHA3_512(), backend=default_backend())
    tprime.update(tbytes)
    tprimebytes = tprime.finalize()

    # concatenate t and t prime (tconcnattprime)
    tconcattprime = b"".join([tbytes, tprimebytes])

    # turn it back into an int and mod by TTP_N
    ttprimeint = int.from_bytes(tconcattprime,'big')
    ttprimeint = ttprimeint % TTP_N

    # compute SIG_CHECK = pow(TTP_SIG, TTP_e, TTP_N)
    SIG_CHECK = pow(TTP_SIG, TTP_e, TTP_N)

    # check verification
    if (SIG_CHECK == ttprimeint):
        print("Server signature verified")
        sys.stdout.flush()
    else:
        print("Server signature does not match. Aborting!")
        sys.stdout.flush()
        sys.exit()

    # choose 0 <= a <= N-2
    a = randbelow(N-1)
    print("Client: a = " + str(a))
    sys.stdout.flush()

    # compute A = g^a (mod N)
    A = pow(g, a, N)
    ABytes = A.to_bytes(64, 'big')
    print("Client: A = " + str(A))
    sys.stdout.flush()

    # encrypt A
    encA = pow(A, server_e, server_N)

    #send encA
    encAbytes = encA.to_bytes(128,'big')
    conn.send(encAbytes)
    print("Client: Sending Enc(A) <" + encAbytes.hex() + ">")
    sys.stdout.flush()


    ##################
    # CONTINUE AS A2 #
    ##################


    # receive (s, B) from Server
    s = conn.recv(16)
    BBytes = conn.recv(64)
    B = int.from_bytes(BBytes, 'big')

    print("Client: s <" + s.hex() + ">")
    sys.stdout.flush()
    print("Client: B = " + str(B))
    sys.stdout.flush()

    # compute u = hash(A||B) (mod N)
    BBytes = B.to_bytes(64, 'big')
    
    tohash = b"".join([ABytes, BBytes])
    u = hashes.Hash(hashes.SHA3_256(), backend=default_backend())
    u.update(tohash)
    u = u.finalize()
    print("Client: u = " + str(int.from_bytes(u, 'big')))
    sys.stdout.flush()

    # compute Kclient = (B - kv) ^ (a + ux) (mod N)
    kDecimal = int.from_bytes(k, 'big')
    uDecimal = int.from_bytes(u, 'big')
    Binside = pow(B, 1, N)
    kv = pow(kDecimal * v, 1, N)
    Kclient = pow(Binside - kv, (a + uDecimal * xDecimal), N)
    print("Client: k_client = " + str(Kclient))
    sys.stdout.flush()

    # calculate M1 = hash(A||B||Kclient) and send to Server
    KclientBytes = Kclient.to_bytes(64, 'big')
    tohash = b"".join([ABytes, BBytes, KclientBytes])
    M1 = hashes.Hash(hashes.SHA3_256(), backend=default_backend())
    M1.update(tohash)
    M1 = M1.finalize()
    print("Client: M1 = <" + M1.hex() + ">")
    sys.stdout.flush()

    # SEND AND RECEIVE M1 AND M2 AS 32 BYTES
    conn.send(M1)

    # receive M2 from the Server
    M2 = conn.recv(64)
    print("Client: M2 = <" + M2.hex() + ">")
    sys.stdout.flush()

    # compute hash(A||M1||Kclient)
    tohash = b"".join([ABytes, M1, KclientBytes])
    temp2 = hashes.Hash(hashes.SHA3_256(), backend=default_backend())
    temp2.update(tohash)
    temp2 = temp2.finalize()

    if temp2 == M2:
        print("Client: Negotiation successful")
        sys.stdout.flush()
    else:
        print("Client: Negotiation unsuccessful")
        sys.stdout.flush()


    ##########################
    # FILE TRANSFER PROTOCOL #
    ##########################

    #generate random 16 byte IV
    iv = os.urandom(16)
    print("Client: iv = <" + iv.hex() + ">")
    sys.stdout.flush()

    # open the file to be encrypted
    fileName = sys.argv[1]
    f = open(fileName, "r")
    plaintext = f.read()
    f.close()

    #convert to bytearray
    plaintextBytes = plaintext.encode('utf-8')

    # encrypt Kclient under SHA3-256 - THIS IS THE CLIENT KEY
    encKclientbytes = hashes.Hash(hashes.SHA3_256(), backend=default_backend())
    encKclientbytes.update(KclientBytes)
    encKclientbytes = encKclientbytes.finalize()
    print("Client: key = <" + encKclientbytes.hex() + ">")
    sys.stdout.flush()

    # Tag = HMAC(key, plaintext)
    tag = hmac.HMAC(encKclientbytes, hashes.SHA3_256(), backend=default_backend())
    tag.update(plaintextBytes)
    tag = tag.finalize()

    tag = hashes.Hash(hashes.SHA3_256(), backend=default_backend())
    tag.update(plaintextBytes)
    tag = tag.finalize()

    # encrypt plaintext||tag
    encText = b"".join([plaintextBytes, tag])

    # pad encText using PKCS7
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(encText)
    padded_data = padded_data + padder.finalize()

    # Encrypt padded_data with AES-256 in CBC mode
    cipher_ob = Cipher(algorithms.AES(encKclientbytes), modes.CBC(iv), backend=default_backend())
    encryptor = cipher_ob.encryptor()
    encrypted = encryptor.update(padded_data) + encryptor.finalize()

    #ciphertext = IV||enc(plaintext||tag)
    ciphertext = b"".join([iv, encrypted])

    #send the file
    lenCipher = len(ciphertext).to_bytes(4,'big')
    print("Client: Sending len(PXTX)" + "<" + lenCipher.hex() + ">")
    sys.stdout.flush()
    conn.send(lenCipher)
    conn.send(ciphertext)

    print("Client: File " + str(fileName) + " sent.")
    sys.stdout.flush()