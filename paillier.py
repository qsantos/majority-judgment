#!/usr/bin/env python
import random

import util


def generate_paillier_keypair(n_bits=2048, safe_primes=True):
    p = util.genprime(n_bits // 2, safe_primes)
    q = util.genprime(n_bits - n_bits // 2, safe_primes)
    g = 1 + p*q
    sk = PaillierSecretKey(p, q, g)
    return sk.public_key, sk


class PaillierPublicKey:
    def __init__(self, n, g):
        self.n = n
        self.nsquare = n * n
        self.g = g

        # cache
        self.inverts = {}

    def encrypt(self, m, randomize=True):
        n2 = self.nsquare

        if self.g == 1 + self.n:
            raw_value = (1 + self.n * m) % n2
        else:
            raw_value = util.powmod(self.g, m, n2)

        if randomize:
            r = random.SystemRandom().randrange(self.n)
            raw_value = raw_value * util.powmod(r, self.n, n2) % n2
        return PaillierCiphertext(self, raw_value)


class PaillierSecretKey:
    def __init__(self, p, q, g):
        self.p = p
        self.q = q
        self.public_key = pk = PaillierPublicKey(p*q, g)

        # pre-computations
        self.hp = util.invert(self.L(util.powmod(pk.g, p-1, p*p), p), p)
        self.hq = util.invert(self.L(util.powmod(pk.g, q-1, q*q), q), q)

    def L(self, u, n):
        return (u - 1) // n

    def decrypt(self, ciphertext, relative=True):
        pk = self.public_key
        p, q = self.p, self.q
        ciphertext = ciphertext.raw_value
        m_mod_p = self.L(util.powmod(ciphertext, p-1, p*p), p) * self.hp % p
        m_mod_q = self.L(util.powmod(ciphertext, q-1, q*q), q) * self.hq % q
        plaintext = util.crt([m_mod_p, m_mod_q], [p, q])
        if relative and plaintext >= pk.n//2:
            plaintext -= pk.n
        return int(plaintext)


class PaillierCiphertext:
    def __init__(self, public_key, raw_value):
        self.public_key = public_key
        self.raw_value = raw_value

    def __add__(a, b):
        pk = a.public_key
        if not isinstance(b, PaillierCiphertext):
            b = pk.encrypt(b, randomize=False)
        elif b.public_key != pk:
            raise ValueError('cannot sum values under different public keys')
        return PaillierCiphertext(pk, a.raw_value * b.raw_value % pk.nsquare)

    def __radd__(a, b):
        return a + b

    def __neg__(a):
        return a * -1

    def __sub__(a, b):
        return a + -b

    def __rsub__(a, b):
        return b + -a

    def __mul__(a, b):
        if isinstance(b, PaillierCiphertext):
            raise NotImplementedError('Have a look at TFHE ;-)')
        pk = a.public_key
        a = a.raw_value
        b %= pk.n

        if b > pk.n // 2:
            # small negatives values are common and it is faster to compute an
            # invert than an exponentiation to a value close to n
            b = pk.n - b
            a = util.invert(a, pk.nsquare)

        return PaillierCiphertext(pk, util.powmod(a, b, pk.nsquare))

    def __rmul__(a, b):
        return a * b

    def __truediv__(a, b):
        if isinstance(b, PaillierCiphertext):
            raise NotImplementedError('Have a look at TFHE ;-)')
        pk = a.public_key
        if b not in pk.inverts:
            pk.inverts[b] = util.invert(b, pk.n)
        return a * pk.inverts[b]
