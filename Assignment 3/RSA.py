import socket
import sys
import os
import ast
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from sympy import *
from secrets import *
from random import *
from math import *

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
def generateSafePrime():
    while True:
        q = generateq()
        N = (q * 2) + 1
        if isprime(N) == True:
            return N
        else:
            continue

def xgcd(a, b):
    """return (g, x, y) such that a*x + b*y = g = gcd(a, b)"""
    x0, x1, y0, y1 = 0, 1, 1, 0
    while a != 0:
        (q, a), b = divmod(b, a), a
        y0, y1 = y1, y0 - q * y1
        x0, x1 = x1, x0 - q * x1
    return b, x0, y0

def modinv(a, b):
    """return x such that (x * a) % b == 1"""
    g, x, _ = xgcd(a, b)
    if g != 1:
        raise Exception('gcd(a, b) != 1')
    return x % b

def generateRSAKey():
    p = generateSafePrime()
    q = generateSafePrime()
    N = p * q
    phiN = (p-1) * (q-1)
    e = randrange(1,N)
    while gcd(e, phiN) != 1:
        e = randrange(1,N)
    d = modinv(e, phiN)
    return p,q,N,phiN,e,d