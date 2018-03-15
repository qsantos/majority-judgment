#!/usr/bin/env python
import random

import util


def generate_paillier_keypair(n_bits=2048, safe_primes=True):
    p = util.genprime(n_bits // 2, safe_primes)
    q = util.genprime(n_bits - n_bits // 2, safe_primes)
    g = 1 + p*q
    sk = PaillierSecretKey(p, q, g)
    return sk.public_key, sk


def generate_paillier_keypair_shares(n_shares, n_bits=2048, safe_primes=True):
    pk, sk = generate_paillier_keypair(n_bits, safe_primes)
    lambda_ = (sk.p-1)*(sk.q-1) // 2  # λ(n) = lcm(p-1, q-1); p, q safe primes
    exponent = util.crt([0, 1], [lambda_, pk.n])

    # the base must be a quadratic residue
    pk.verification_base = random.randrange(pk.nsquare)**2 % pk.nsquare

    # split the secret exponent into required number of shares
    key_shares = [
        random.randrange(pk.n * lambda_)
        for _ in range(n_shares-1)
    ]
    key_shares.append((exponent - sum(key_shares)) % (pk.n * lambda_))

    # compute corresponding verification elements
    verifications = [
        util.powmod(pk.verification_base, key_share, pk.nsquare)
        for key_share in key_shares
    ]

    # create public and private key shares
    pk_shares = [
        PaillierPublicKeyShare(pk, verification)
        for verification in verifications
    ]
    sk_shares = [
        PaillierSecretKeyShare(pk, key_share)
        for key_share in key_shares
    ]

    return pk, pk_shares, sk_shares


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


class InvalidProof(Exception):
    pass


class PaillierPublicKeyShare:
    def __init__(self, public_key, verification):
        self.public_key = public_key  # Paillier public key
        self.verification = verification  # v_i = v^{s_i}

    def verify_knowledge(self):
        pk = self.public_key

        # run Schnorr protocol
        commitment = yield
        challenge = random.SystemRandom().randrange(2**80)
        proof = yield challenge

        # verify proof
        if util.powmod(pk.verification_base, proof, pk.nsquare) != \
                commitment * util.powmod(self.verification, challenge, pk.nsquare) % pk.nsquare:
            raise InvalidProof

    def verify_decrypt(self, ciphertext):
        pk = self.public_key

        # run Chaum-Pedersen protocol
        plaintext, left_commitment, right_commitment = yield
        challenge = random.SystemRandom().randrange(2**80)
        proof = yield challenge  # proof is usually noted s

        # verify proof
        # check that v^s = t_1 * v_i^c
        if util.powmod(pk.verification_base, proof, pk.nsquare) != \
                left_commitment * util.powmod(self.verification, challenge, pk.nsquare) % pk.nsquare:
            raise InvalidProof
        # check that x^s = t_2 * m^c
        if util.powmod(ciphertext.raw_value, proof, pk.nsquare) != \
                right_commitment * util.powmod(plaintext, challenge, pk.nsquare) % pk.nsquare:
            raise InvalidProof

        return plaintext

    def verify_decrypt_batched(self, ciphertexts):
        pk = self.public_key

        # generate random λ_i *after* the plaintexts have been provided
        plaintexts = yield
        lambdas = [
            random.SystemRandom().randrange(2**80)
            for _ in ciphertexts
        ]

        # run Chaum-Pedersen protocol
        left_commitment, right_commitment = yield lambdas
        challenge = random.SystemRandom().randrange(2**80)
        proof = yield challenge  # proof is usually noted s

        # compute combined plaintext and ciphertext for verification
        combined_plaintext = util.prod(
            util.powmod(plaintext, lambda_, pk.nsquare)
            for plaintext, lambda_ in zip(plaintexts, lambdas)
        )
        combined_ciphertext = util.prod(
            util.powmod(ciphertext.raw_value, lambda_, pk.nsquare)
            for ciphertext, lambda_ in zip(ciphertexts, lambdas)
        )

        # verify proof
        # check that v^s = t_1 * v_i^c
        if util.powmod(pk.verification_base, proof, pk.nsquare) != \
                left_commitment * util.powmod(self.verification, challenge, pk.nsquare) % pk.nsquare:
            raise InvalidProof
        # check that x^s = t_2 * m^c
        if util.powmod(combined_ciphertext, proof, pk.nsquare) != \
                right_commitment * util.powmod(combined_plaintext, challenge, pk.nsquare) % pk.nsquare:
            raise InvalidProof

        return plaintexts

    @staticmethod
    def L(u, n):
        return (u - 1) // n

    @staticmethod
    def assemble_decryption_shares(shares, decryption_shares, relative=True):
        pk = shares[0].public_key
        plaintext = PaillierPublicKeyShare.L(util.prod(decryption_shares, pk.nsquare), pk.n)
        if relative and plaintext >= pk.n // 2:
            plaintext -= pk.n
        return int(plaintext)


class PaillierSecretKeyShare:
    def __init__(self, public_key, key_share):
        self.public_key = public_key
        self.key_share = key_share

    def prove_knowledge(self):
        pk = self.public_key
        r = random.SystemRandom().randrange(pk.nsquare)  # TODO: range
        commitment = util.powmod(pk.verification_base, r, pk.nsquare)
        challenge = yield commitment
        yield r + challenge * self.key_share

    def decrypt(self, ciphertext):
        pk = self.public_key
        return util.powmod(ciphertext.raw_value, self.key_share, pk.nsquare)

    def prove_decrypt(self, ciphertext):
        pk = self.public_key
        plaintext = self.decrypt(ciphertext)

        # prove knowledge of key_share such that:
        #   * v_i = v**key_share
        #   * plaintext = ciphertext**key_share
        r = random.SystemRandom().randrange(pk.nsquare)  # TODO: range
        left_commitment = util.powmod(pk.verification_base, r, pk.nsquare)
        right_commitment = util.powmod(ciphertext.raw_value, r, pk.nsquare)
        challenge = yield plaintext, left_commitment, right_commitment
        yield r + challenge * self.key_share

    def prove_decrypt_batched(self, ciphertexts):
        pk = self.public_key
        plaintexts = [self.decrypt(ciphertext) for ciphertext in ciphertexts]

        # to aggregate ZKPs, the verifier provides λ_i *after* the plaintexts
        # have been provided; then combined_ciphertext = ∏ ciphertext^{λ_i}
        # and combined_plaintext = ∏ m^{λ_i} (not needed for prover)
        lambdas = yield plaintexts
        combined_ciphertext = util.prod(
            util.powmod(ciphertext.raw_value, lambda_, pk.nsquare)
            for ciphertext, lambda_ in zip(ciphertexts, lambdas)
        )

        # prove knowledge of key_share such that:
        #   * v_i = v**key_share
        #   * combined_plaintext = combined_ciphertext**key_share
        r = random.SystemRandom().randrange(pk.nsquare)  # TODO: range
        left_commitment = util.powmod(pk.verification_base, r, pk.nsquare)
        right_commitment = util.powmod(combined_ciphertext, r, pk.nsquare)
        challenge = yield left_commitment, right_commitment
        yield r + challenge * self.key_share


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
