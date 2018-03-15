#!/usr/bin/env python
import random

import gmpy2


def powmod(x, y, m):
    if x == 1:
        return 1
    else:
        return gmpy2.powmod(x, y, m)


def invert(x, m):
    return gmpy2.invert(x, m)


def is_prime(x):
    return gmpy2.is_prime(x)


def genprime(n_bits, safe_prime=False):
    if safe_prime:
        # q of the form 2*p + 1 such that p is prime as well
        while True:
            p = genprime(n_bits - 1)
            q = 2*p + 1
            if is_prime(q):
                return q
    # just a random prime
    n = random.SystemRandom().randrange(2**(n_bits-1), 2**n_bits) | 1
    return gmpy2.next_prime(n)


def crt(residues, modulos):
    redidues = list(residues)
    product = 1
    for modulo in modulos:
        product *= modulo
    r = 0
    for residue, modulo in zip(residues, modulos):
        NX = product // modulo
        r += residue * NX * invert(NX, modulo)
        r %= product
    return r


def prod(elements_iterable, modulus=None):
    elements_iterator = iter(elements_iterable)
    product = next(elements_iterator)
    for element in elements_iterator:
        product *= element
        if modulus is not None:
            product %= modulus
    return product
