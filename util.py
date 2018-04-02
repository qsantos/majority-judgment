#!/usr/bin/env python3
"""Some utilities (mostly arithmetic)"""
import random

import gmpy2


def powmod(x, y, m):
    """Computes `x^y mod m`

    The method `powmod()` from `gmpy2` is faster than Python's builtin
    `powmod()`. However, it does add some overhead which should be skipped for
    `x = 1`.

    Arguments:
        x (int): base of the exponentiation
        y (int): exponent
        m (int): modulus

    Returns:
        int: the result of `x^y mod m`
    """
    if x == 1:
        return 1
    elif y < 0:
        return invert(powmod(x, -y, m), m)
    else:
        return int(gmpy2.powmod(x, y, m))


def invert(x, m):
    """Computes the invert of `x` modulo `m`

    This is a wrapper for `invert() from `gmpy2`.

    Arguments:
        x (int): element to be inverted
        m (int): modulus

    Returns:
        int: y such that `x × y = 1 mod m`
    """
    return int(gmpy2.invert(x, m))


def is_prime(x):
    """Tests whether `x` is probably prime

    This is a wrapper for `is_prime() from `gmpy2`.

    Arguments:
        x (int): the candidate prime

    Returns:
        bool: `True` if `x` is probably prime else `False`
    """
    return int(gmpy2.is_prime(x))


def genprime(n_bits, safe_prime=False):
    """Generate a probable prime number of n_bits

    This method is based on `next_prime()` from `gmpy2` and adds the safe prime
    feature.

    Arguments:
        n_bits (int): the size of the prime to be generated, in bits
        safe_prime (bool): whether the returned value should be a safe prime a
            just a common prime

    Returns:
        int: a probable prime `x` from `[2^(n_bits-1), 2^n_bits]`

        Is `safe_prime` is `True`, then `x` is also a probable safe prime
    """
    if safe_prime:
        # q of the form 2*p + 1 such that p is prime as well
        while True:
            p = genprime(n_bits - 1)
            q = 2*p + 1
            if is_prime(q):
                return q
    # just a random prime
    n = random.SystemRandom().randrange(2**(n_bits-1), 2**n_bits) | 1
    return int(gmpy2.next_prime(n))


def crt(residues, moduli):
    """Applies the Chinese Remainder Theorem on given residues

    Arguments:
        residues (list): the residues (int)
        moduli (list): the corresponding modulis (int) in the same order

    Returns:
        int: `x` such that `x < ∏ moduli` and `x % modulus = residue` for
        residue, modulus in `zip(moduli, redidues)`
    """
    redidues = list(residues)
    product = prod(moduli)
    r = 0
    for residue, modulus in zip(residues, moduli):
        NX = product // modulus
        r += residue * NX * invert(NX, modulus)
        r %= product
    return r


def prod(elements_iterable, modulus=None):
    """Computes the product of the given elements

    Arguments:
        elements_iterable (iterable): values (int) to be multiplied together
        modulus (int): if provided, the result will be given modulo this value

    Returns:
        int: the product of the elements from elements_iterable

        If modulus is not None, then the result is reduced modulo the provided
        value.
    """
    elements_iterator = iter(elements_iterable)
    product = next(elements_iterator)
    for element in elements_iterator:
        product *= element
        if modulus is not None:
            product %= modulus
    return product


def random_numbers_totaling(total, count):
    """Generate random numbers of given sum

    Arguments:
        total (int): the value the random numbers should sum to
        count (int): the number of random numbers to generate

    Returns:
        list: l, random numbers (int) such that `sum(l) == total` and `len(l)
        == count`
    """
    # inspired from <http://umusebo.com/generate-n-random-numbers-whose>
    # divide [0, total] in count random subranges
    fenceposts = sorted(random.choice(range(total+1)) for _ in range(count-1))
    # return the lengths of these subranges
    return [b - a for a, b in zip([0] + fenceposts, fenceposts + [total])]
