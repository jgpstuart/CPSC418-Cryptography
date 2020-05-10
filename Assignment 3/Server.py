"""
Submitted by Jeremy Stuart (UCID: 00311644)
CPSC 418: Introduction to Cryptography
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
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from sympy import *
from secrets import *
from RSA import generateRSAKey

HOST = '127.0.4.18'
TTP_PORT = 31802
CLIENT_PORT = 31803

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

# prompt Server for name (S)
print("Enter username: ")
S = sys.stdin.readline()
S = S.strip('\n')

# generate RSA values
server_p, server_q, server_N, server_phiN, server_e, server_d = generateRSAKey()

server_Nbytes = server_N.to_bytes(128,'big')
server_ebytes = server_e.to_bytes(128, 'big')
server_PKbytes = b"".join([server_Nbytes, server_ebytes])
server_PK = int.from_bytes(server_PKbytes, 'big')

print("Server: Server_p = " + str(server_p))
sys.stdout.flush()
print("Server: Server_q = " + str(server_q))
sys.stdout.flush()
print("Server: Server_N = " + str(server_N))
sys.stdout.flush()
print("Server: Server_e = " + str(server_e))
sys.stdout.flush()
print("Server: Server_d = " + str(server_d))
sys.stdout.flush()
print("Server: Server_PK = " + str(server_PK))
sys.stdout.flush()



# connect to TTP
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as conn:

    #connect to TTP
    conn.connect((HOST, TTP_PORT))

    request = "REQUEST SIGN"
    print("Server: Sending 'REQUEST SIGN'")
    sys.stdout.flush()
    request = request.encode('utf-8')
    conn.send(request)
    Slenbytes = len(S).to_bytes(4,'big')
    print("Server: Sending len(S) = " + str(len(S)))
    sys.stdout.flush()
    conn.send(Slenbytes)
    Sbytes = S.encode('utf-8')
    conn.send(Sbytes)
    print("Server: Sending S = " + str(S))
    sys.stdout.flush()
    server_Nbytes = server_N.to_bytes(128,'big')
    print("Server: Sending Server_N = " + str(server_N))
    sys.stdout.flush()
    server_ebytes = server_e.to_bytes(128,'big')
    conn.send(server_Nbytes)
    conn.send(server_ebytes)
    print("Server: Sending Server_e = " + str(server_e))
    sys.stdout.flush()
    TTP_Nbytes = conn.recv(128)
    TTP_SIGbytes = conn.recv(128)
    TTP_N = int.from_bytes(TTP_Nbytes, 'big')
    TTP_SIG = int.from_bytes(TTP_SIGbytes, 'big')
    print("Server: Receiving TTP_N = " + str(TTP_N))
    sys.stdout.flush()
    print("Server: Receiving TTP_SIG = " + str(TTP_SIG))
    sys.stdout.flush()
    conn.close()






#REGISTER CLIENT
# generate N and g
N, g = generateNg()
sys.stdout.flush()
print("Server: N = " + str(N))
sys.stdout.flush()
print("Server: g = " + str(g))
sys.stdout.flush()

# compute k = hash(N||g)
Nbytes = N.to_bytes(64, 'big')
gBytes = g.to_bytes(64, 'big')
tohash = b"".join([Nbytes, gBytes])

k = hashes.Hash(hashes.SHA3_256(), backend=default_backend())
k.update(tohash)
kBytes = k.finalize()
kDecimal = int.from_bytes(kBytes, 'big')
print("Server: k = " + str(kDecimal))
sys.stdout.flush()


with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as serv:

    serv.bind((HOST, CLIENT_PORT))
    print('Server listening...')
    sys.stdout.flush()

    serv.listen(20)

    conn, addr = serv.accept()

    ## conn is a new socket which is used to communicate with the client
    with conn:

        # send N and g to the Client upon the Client connecting
        # send as 64-byte number in big-endian format
        conn.send(Nbytes)
        conn.send(gBytes)
        print("Server: Sending N <" + Nbytes.hex() + ">")
        sys.stdout.flush()
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
        sys.stdout.flush()
        print("Server: |I| = " + str(iSize))
        sys.stdout.flush()
        print("Server: I = '" + I + "'")
        sys.stdout.flush()
        print("Server: s = <" + s.hex() + ">")
        sys.stdout.flush()
        print("Server: v = " + str(v))
        sys.stdout.flush()

        # print message that this has succesfully completed
        print("Server:  Registration successful.")
        sys.stdout.flush()

        # listen for Client to reconnect
        serv.listen(20)
        conn, addr = serv.accept()

        # send N and g again
        conn.send(Nbytes)
        conn.send(gBytes)
        print("Server: Sending N <" + Nbytes.hex() + ">")
        sys.stdout.flush()
        print("Server: Sending g <" + gBytes.hex() + ">")
        sys.stdout.flush()

        # receive ('p', |I|, I) from Client
        pByte = conn.recv(1)
        p = pByte.decode('utf-8')
        iSize = int.from_bytes(conn.recv(4), 'big')
        IBytes = conn.recv(iSize)
        I = IBytes.decode('utf-8')
        print("Server: flag = " + p)
        sys.stdout.flush()
        print("Server: |I| = " + str(iSize))
        sys.stdout.flush()
        print("Server: I = " + str(I))
        sys.stdout.flush()


        # send len(S)||S||server_N||server_e||TTP_SIG
        Slenbytes = len(S).to_bytes(4,'big')
        print("Server: Sending len(S) <" + Slenbytes.hex() + ">")
        sys.stdout.flush()
        conn.send(Slenbytes)

        Sbytes = S.encode('utf-8')
        conn.send(Sbytes)
        print("Server: Sending S <" + Sbytes.hex() + ">")
        sys.stdout.flush()

        server_Nbytes = server_N.to_bytes(128,'big')
        conn.send(server_Nbytes)
        print("Server: Sending Server_N <" + server_Nbytes.hex() + ">")
        sys.stdout.flush()
        
        server_ebytes = server_e.to_bytes(128,'big')
        conn.send(server_ebytes)
        print("Server: Sending Server_e <" + server_ebytes.hex() + ">")
        sys.stdout.flush()

        conn.send(TTP_SIGbytes)
        print("Server: Sending TTP_SIG <" + TTP_SIGbytes.hex() + ">")
        sys.stdout.flush()

        # receive Enc(A)
        encAbytes = conn.recv(128)
        encA = int.from_bytes(encAbytes, 'big')
        print("Server: Receiving Enc(A) = " + str(encA))
        sys.stdout.flush()
        print("Server: Enc(A) = " + str(encA))
        sys.stdout.flush()

        # decrypt Enc(A)
        A = pow(encA, server_d, server_N)
        print("Server: A = " + str(A))


        ##################
        # CONTINUE AS A2 #
        ##################


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
        u = hashes.Hash(hashes.SHA3_256(), backend=default_backend())
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
        temp1 = hashes.Hash(hashes.SHA3_256(), backend=default_backend())
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
        M2 = hashes.Hash(hashes.SHA3_256(), backend=default_backend())
        M2.update(tohash)
        M2 = M2.finalize()

        # send Client M2
        conn.send(M2)
        print("Server: Sending M2 <" + M2.hex() + ">")
        sys.stdout.flush()


        ##########################
        # FILE TRANSFER PROTOCOL #
        ##########################

        # encrypt Kserver under SHA3-256 - THIS IS THE SERVER KEY
        encKserverbytes = hashes.Hash(hashes.SHA3_256(), backend=default_backend())
        encKserverbytes.update(KserverBytes)
        encKserverbytes = encKserverbytes.finalize()
        print("Server: key = <" + encKserverbytes.hex() + ">")

        # receive the len(ciphertext)
        lenCipherbytes = conn.recv(4)
        lenCipher = int.from_bytes(lenCipherbytes, 'big')
        print("Server: receiving len(ciphertext) = <" + lenCipherbytes.hex() + ">")

        # receive ciphertext
        ciphertext = conn.recv(lenCipher)

        # slice iv
        iv = ciphertext[:16]
        print("Server: iv = <" + iv.hex() + ">")
        sys.stdout.flush()

        # slice ciphertext
        ciphertext = ciphertext[16:]
         
        # decrypt ciphertext with IV and guessed password
        cipher = Cipher(algorithms.AES(encKserverbytes), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        plainbytes = decryptor.update(ciphertext) + decryptor.finalize()

        # remove padding
        unpadder = padding.PKCS7(128).unpadder()
        plainbytes = unpadder.update(plainbytes)
        plainbytes = plainbytes + unpadder.finalize()

        # separate plaintext and tag
        plaintextBytes = plainbytes[:-32]
        clientTag = plainbytes[len(plaintextBytes):]

        # serverTag = HMAC(key, plaintext)
        serverTag = hmac.HMAC(encKserverbytes, hashes.SHA3_256(), backend=default_backend())
        serverTag.update(plaintextBytes)
        serverTag = serverTag.finalize()

        serverTag = hashes.Hash(hashes.SHA3_256(), backend=default_backend())
        serverTag.update(KserverBytes)
        serverTag = serverTag.finalize()

        if(serverTag == clientTag):
            print("File transfered successfully")
        else:
            print("Someone set up us the bomb!")

        fileName = sys.argv[1]
        writer = open(fileName, 'wb+')
        writer.write(plaintextBytes)
        writer.close()

        conn.close()

