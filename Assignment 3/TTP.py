from RSA import generateRSAKey
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

def requestSign():
    print("TTP: Receiving 'REQUEST SIGN'")
    sys.stdout.flush()

    # receive len(S)
    lenS = conn.recv(4)
    lenS = int.from_bytes(lenS,'big')
    print("TTP: Receiving len(S) = " + str(lenS))
    sys.stdout.flush()

    # receive S
    Sbytes = conn.recv(lenS)
    S = Sbytes.decode('utf-8')
    print("TTP: Receiving S = '" + S + "'")
    sys.stdout.flush()
    print("TTP: S = '" + S + "'")
    sys.stdout.flush()

    # receive Server_N and Server_e
    serverNbytes = conn.recv(128)
    serverebytes = conn.recv(128)
    serverN = int.from_bytes(serverNbytes,'big')
    servere = int.from_bytes(serverebytes,'big')
    print("TTP: Receiving Server_N = " + str(serverN))
    sys.stdout.flush()
    print("TTP: Receiving Server_e = " + str(servere))
    sys.stdout.flush()
    print("TTP: Server_N = " + str(serverN))
    sys.stdout.flush()
    print("TTP: Server_e = " + str(servere))
    sys.stdout.flush()

    # join Server_N and Server_e to form Server_PK
    server_PKbytes = b"".join([serverNbytes, serverebytes])

    #join server_S and server_PK to prepare for hasing
    toHash = b"".join([Sbytes, server_PKbytes])

    # hash  (Server_S||server_PK) to get t
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

    # create RSA signature
    TTP_SIG = pow(ttprimeint, TTP_d, TTP_N)
    print("TTP: TTP_SIG = " + str(TTP_SIG))
    sys.stdout.flush()

    # send TTP_N  and RSA signature back 
    TTP_Nbytes = TTP_N.to_bytes(128,'big')
    TTP_SIGbytes = TTP_SIG.to_bytes(128, 'big')
    print("TTP: Sending TTP_N <" + TTP_Nbytes.hex() + ">")
    sys.stdout.flush()
    print("TTP: Sending TTP_SIG <" + TTP_SIGbytes.hex() + ">")
    sys.stdout.flush()
    conn.send(TTP_Nbytes)
    conn.send(TTP_SIGbytes)

def requestKey():
    print("TTP: Receiving 'REQUEST KEY'")
    sys.stdout.flush()
    TTP_Nbytes = TTP_N.to_bytes(128,'big')
    conn.send(TTP_Nbytes)
    print("TTP: Sending TTP_N <" + TTP_Nbytes.hex() + ">")
    sys.stdout.flush()
    TTP_ebytes = TTP_e.to_bytes(128,'big')
    conn.send(TTP_ebytes)
    print("TTP: Sending TTP_e <" + TTP_ebytes.hex() + ">")
    sys.stdout.flush()



TTP_p,TTP_q,TTP_N,TTP_phiN,TTP_e,TTP_d = generateRSAKey()
TTP_Nbytes = TTP_N.to_bytes(128,'big')
TTP_ebytes = TTP_e.to_bytes(128, 'big')
TTP_PKbytes = b"".join([TTP_Nbytes, TTP_ebytes])
TTP_PK = int.from_bytes(TTP_PKbytes,'big')

print("TTP: TTP_p = " + str(TTP_p))
sys.stdout.flush()
print("TTP: TTP_q = " + str(TTP_q))
sys.stdout.flush()
print("TTP: TTP_N = " + str(TTP_N))
sys.stdout.flush()
print("TTP: TTP_e = " + str(TTP_e))
sys.stdout.flush()
print("TTP: TTP_d = " + str(TTP_d))
sys.stdout.flush()

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as serv:

    serv.bind((HOST, PORT))
    print('TTP: TTP is listening...')
    sys.stdout.flush()

    while True:

        serv.listen()
        serv.settimeout(60)
        conn, addr = serv.accept()

        # conn is a new socket which is used to communicate with the client
        with conn:

            try:
                conn.settimeout(15)
                test = conn.recv(11)
                teststr = test.decode('utf-8')
                if teststr == "REQUEST SIG":
                    conn.recv(1)
                    requestSign()
                else:
                    requestKey()
            
            except:
                print( "Exception caught: {}: {}".format( *sys.exc_info()[:2] ) )
            finally:
                sys.stdout.flush()
                conn.shutdown( socket.SHUT_RDWR )
                conn.close()
    
