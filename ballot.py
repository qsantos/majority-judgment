#!/usr/bin/env python
import random

from util import powmod, H
import paillier


def encrypt_among(pk, plaintext, values):
    n2 = pk.nsquare
    raw_ciphertext, r = pk.raw_multiply(pk.g, plaintext)
    ciphertext = paillier.PaillierCiphertext(pk, raw_ciphertext)

    omega = random.SystemRandom().randrange(pk.n)
    e = [random.SystemRandom().randrange(2 << (2*1023)) for _ in values]
    z = [random.SystemRandom().randrange(pk.n) for _ in values]
    a = [
        powmod(omega, pk.n, n2) if plaintext == value else
        powmod(z[i], pk.n, n2) * powmod(raw_ciphertext * powmod(pk.g, value, n2), -e[i], n2) % n2
        for i, value in enumerate(values)
    ]

    e_challenge = H(a)
    i = values.index(plaintext)
    e[i] = e_challenge - (sum(e) + e[i])
    z[i] = omega * powmod(r, e[i], pk.n) % pk.n
    proof = a, e, z
    return ciphertext, r, proof


def prepare_ballot(pk, n_choices, n_candidates):
    n2 = pk.nsquare

    ballot = []
    for _ in range(n_candidates):
        # values provided (ciphertexts and corresponding proofs of validity)
        ciphertexts = []
        proofs = []

        # product of ciphertexts of the raw (ciphertext and randomization)
        row_c = 1
        row_r = 1

        plaintexts = [1] + [0]*(n_choices-1)
        for plaintext in plaintexts:
            ciphertext, r, proof = encrypt_among(pk, plaintext, [0, 1])
            ciphertexts.append(ciphertext)
            proofs.append(proof)

            row_c = row_c * ciphertext.raw_value % n2
            row_r = row_r * r % pk.n

        # prove that row_c is an encryption of 1
        omega = random.SystemRandom().randrange(pk.n)
        a = powmod(omega, pk.n, n2)
        e = H(a)
        z = omega * powmod(row_r, e, pk.n)
        row_proof = a, z
        row_proof = None

        row = (ciphertexts, proofs, row_proof)
        ballot.append(row)
    return ballot


''' without proofs
def prepare_ballot(pk, n_choices, n_candidates):
    ballot = []
    for _ in range(n_candidates):
        one = pk.encrypt(1)

        zeros = [pk.encrypt(0) for _ in range(n_choices - 1)]
        row = [one] + zeros


        ballot.append(row)
    return ballot
'''
