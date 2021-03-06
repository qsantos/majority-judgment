#!/usr/bin/env python3
"""Implementation of the Paillier cryptosystem

The Paillier cryptosystem is a public key encryption system with the property
of being partially homomorphic for addition (i.e. we can combine the
ciphertexts of two messages to obtain a ciphertext of the sum of these two
messages).

The main entry points of this module are `generate_paillier_keypair()` and
`generate_paillier_keypair_shares()`.
"""
import random

import util

# the DDH is not hard in Z_n², only in Q_n², the subgroup of the quadratic
# residues modulo n²; so, to ensure that publishing c^s does not leak
# information about s, the prover first squares c; this protects the prover
_QR = 1

# Shoup only proved the soudness of Chaum-Pedersen proofs in the RSA setting
# for bases in the cyclic group; thus, the verifier squares both hands of the
# equation when to ensure to be working in Q_n; this protects the verifier
_CP = 1

# Notations for proofs
#   * t, t1, t2: commitment
#   * h: challenge (= H(…))
#   * w: witness (exponent applied to the generator)


def generate_paillier_keypair(n_bits=2048, safe_primes=True):
    """Generate a pair of keys for the Paillier cryptosystem

    Arguments:
        n_bits (int, optional): the number of bits for the parameter n; they
            security corresponds to the difficulty of factoring `n` (as in
            RSA); as of 2018, NIST and ANSSI recommend at least 2048 bits and
            NSA 3072 bits
        safe_primes (bool, optional): safe primes are required for the security
            of the cryptosystems; however, generating safe primes takes much
            more time (generating a 2048 bit keypair takes one minute with safe
            primes, but a fraction of a second without); disabling the use of
            safe primes can be useful when security is not important (e.g.
            benchmarking)
            DO NOT SET TO FALSE IN PRODUCTION

    Returns:
        tuple: pair of two elements, usually named respectively `pk`
            (`PaillierPublicKey`), and `sk` (`PaillierSecretKey`)

        The public key (`pk`) allows to encrypt messages (relative integers);
        the secret key (`sk`) allows to decrypt ciphertexts generated using
        that public key (but not using another).
    """
    p = util.genprime(n_bits // 2, safe_primes)
    q = util.genprime(n_bits - n_bits // 2, safe_primes)
    g = 1 + p*q
    sk = PaillierSecretKey(p, q, g)
    return sk.public_key, sk


def share_paillier_keypair(pk, sk, n_shares):
    """Share an existing keypair for the Paillier cryptosystem

    Arguments:
        pk (PaillierPublicKey): public part of the keypair to be shared
        sk (PaillierSecretKey): secret part of the keypair to be shared
        n_shares (int): the number of shares into which to split the keypair

    Returns:
        tuple: pair of two elements, usually named respectively `pk_shares`
            (`list` of `PaillierPublicKeyShare`) and `sk_shares` (`list` of
            `PaillierSecretKeyShare`).

        When used together, the secret key shares (`sk_shares`) allow to
        decrypt ciphertexts generated using the given public key (but not using
        another), using the method `assemble_decryption_shares()` from
        `PaillierPublicKeyShare`. The public key shares (`pk_shares`) can be
        used to verify that each secret key share was used correctly (usually
        one share would be given to each party, and decryption would imply that
        each party correctly processes the ciphertext using their secret key
        share).
    """
    m = (sk.p-1)*(sk.q-1)
    exponent = util.invert(pk.n, m)

    # the verification base must generate the quadratic residues; which happens
    # with overwhelming probability for a random square
    verification_base = random.SystemRandom().randrange(pk.nsquare)**2 % pk.n

    # split the secret exponent into required number of shares
    key_shares = [
        random.SystemRandom().randrange(m)
        for _ in range(n_shares-1)
    ]
    key_shares.append((exponent - sum(key_shares)) % (m))

    # compute corresponding verification elements
    verifications = [
        util.powmod(verification_base, key_share, pk.nsquare)
        for key_share in key_shares
    ]

    # create public and private key shares
    pk_shares = [
        PaillierPublicKeyShare(pk, verification_base, verification)
        for verification in verifications
    ]
    sk_shares = [
        PaillierSecretKeyShare(pk, verification_base, key_share)
        for key_share in key_shares
    ]

    return pk_shares, sk_shares


def generate_paillier_keypair_shares(n_shares, n_bits=2048, safe_primes=True):
    """Generate shares of keys for the Paillier cryptosystem

    This just calls `generate_paillier_keypair()` and then
    `share_paillier_keypair()` on the result. See their respective
    documentation for more information.

    Arguments:
        n_shares (int): the number of shares into which to split the keypair
        n_bits (int, optional): the number of bits for the parameter n; they
            security corresponds to the difficulty of factoring `n` (as in
            RSA); as of 2018, NIST and ANSSI recommend at least 2048 bits and
            NSA 3072 bits
        safe_primes (bool, optional): safe primes are required for the security
            of the cryptosystems; however, generating safe primes takes much
            more time (generating a 2048 bit keypair takes one minute with safe
            primes, but a fraction of a second without); disabling the use of
            safe primes can be useful when security is not important (e.g.
            benchmarking)
            DO NOT SET TO FALSE IN PRODUCTION

    Returns:
        tuple: triplet of three elements, `pk`, `pk_shares` and `sk_shares`
    """
    pk, sk = generate_paillier_keypair(n_bits, safe_primes)
    pk_shares, sk_shares = share_paillier_keypair(pk, sk, n_shares)
    return pk, pk_shares, sk_shares


class PaillierPublicKey:
    """Public key for the Paillier cryptosystem

    Attributes:
        n (int): parameter `n` from the Paillier cryptosystem, should be the
            product of large safe primes (as large as possible, so ideally two
            primes of the same size)
        g (int): parameter `g` from the Paillier cryptsystem, should an
            invertible element of Z_n² whose order is a positive multiple of
            λ(n) where λ is the Carmichael function; in
            `generate_paillier_keypair()`, `g` is set to `1 + n`
        security_parameter (int): required level of security in bits, used for
            various protocols
        nsquare (int): cached value of `n × n`, used in operations on the
            ciphertext (probably insignificant gains and could be removed)
    """

    def __init__(self, n, g):
        """Constructor

        Arguments:
            n (int): parameter from the Paillier cryptosystem
            g (int): parameter from the Paillier cryptosystem
            security_parameter (int): required level of security
        """
        self.n = n
        self.nsquare = n * n
        self.g = g
        self.security_parameter = 80

        # cache
        self.inverts = {}

    def precompute_proofs(self, plaintexts):
        """Precompute and cache some values used in the proofs

        Using this function does not decreases (nor increases, assuming the
        exact value for `n_uses` is provided) the total execution time.
        However, it can be useful to perform some computation in advance, so
        that the actual use of the secret shares does not take as much time
        (i.e. when the inputs to the protocol are known).

        Arguments:
            plaintexts (list): the plaintext that will be multiplied to the
                ciphertexts
        """
        randoms = [
            random.SystemRandom().randrange(self.n)
            for _ in plaintexts
        ]
        # note: we reverse the list of plaintext so that they can be given in
        # the intuitive order of use, but proofs will simply pop values
        self.precomputed_values = [
            (x, self.raw_multiply(self.g, x), u, self.raw_multiply(self.g, u))
            for x, u in zip(reversed(plaintexts), randoms)
        ]

    def encrypt(self, m, randomize=True):
        """Encrypt a message m into a ciphertext

        Arguments:
            m (int): the message to be encrypted; note that values will be
                reduced modulo `n`
            randomize (bool): every ciphertext should be (re)randomized when
                shared with the world; however, this operation is not always
                strictly necessary; if you are not sure whether to randomize,
                just leave it to its default (True)

        Returns:
            PaillierCiphertext: a ciphertext for the given integer `m` it can
                be decrypted using the secret key corresponding to this public
                key
        """
        raw_value, _ = self.raw_multiply(self.g, m, None if randomize else 1)
        return PaillierCiphertext(self, raw_value)

    def raw_multiply(self, a, b, randomization=None):
        """Multiply a raw ciphertext with a plaintext

        Arguments:
            a (int): a ciphertext for this Paillier public key
            b (int): a plaintext
            randomization (int, optional): the randomization factor; if not
                provided, a secure-random value is chosen

        Returns:
            tuple: a pair of integers, corresponding to the raw ciphertext
            encrypting the product of the value encrypted by `a` and the value
            `b`, and the randomization used
        """
        n2 = self.nsquare

        # explicitely reduces to avoid large exponents
        b %= self.n
        if b > self.n // 2:
            b -= self.n

        # if a is of the form (1+n)^q, then we can avoid the exponentiation
        q, r = divmod(a-1, self.n)
        if r == 0:
            raw_value = (1 + self.n * q * b) % n2
        else:
            raw_value = util.powmod(a, b, n2)

        # apply randomization
        if randomization is None:
            randomization = random.SystemRandom().randrange(self.n)
        raw_value = raw_value * util.powmod(randomization, self.n, n2) % n2

        return raw_value, randomization

    def prove_private_multiply(self, x, cy):
        """Multiply a ciphertext with a plaintext in a verifiable manner

        Arguments:
            x (int): the clear operand
            cy (PaillierCiphertext): the encrypted operand

        Returns:
            tuple: `cx`, `cz`, `proof` where `cx` is an encryption
            (PaillierCiphertext) of x, `cz` is an encryption
            (PaillierCiphertext) of x*y and `proof` is a proof (int)
            that z = x * y
        """
        n2 = self.nsquare

        # precomputable values
        try:
            # raises IndexError if not enough precomputations were forecast
            x_, (cx, rx), u, (cu, ru) = self.precomputed_values.pop()
        except AttributeError:
            # no pre-computations
            u = random.SystemRandom().randrange(self.n)
            cx, rx = self.raw_multiply(self.g, x)  # ⟦x⟧
            cu, ru = self.raw_multiply(self.g, u)  # ⟦u⟧
        else:
            # ensure consistency with arguments
            if x is None:
                x = x_
            elif x != x_:
                raise ValueError

        # other encrypted values
        cz, rz = self.raw_multiply(cy, x)  # ⟦z⟧ = ⟦xy⟧
        cyu, ryu = self.raw_multiply(cy, u)  # ⟦yu⟧

        # run protocol in the Fiat-Shamir heuristic
        h = util.H([cx, cy, cz, cu, cyu])
        rs = ru * util.powmod(rx, h, self.n) % self.n
        rys = ryu * util.powmod(rz, h, self.n) % self.n
        w = u + x*h
        proof = cu, cyu, w, rs, rys

        return cx, cz, proof

    def verify_private_multiply(self, cx, cy, cz, proof):
        """Check the proof of multiplication of a ciphertext with a plaintext

        Arguments:
            cx (int): the encrypted left operand
            cy (int): the encrypted right operand
            cz (int): the encrypted result
            proof (int): a proof that z = x*y
        """
        n2 = self.nsquare

        # run protocol in the Fiat-Shamir heuristic
        cu, cyu, w, rs, rys = proof
        h = util.H([cx, cy, cz, cu, cyu])

        # verify proofs
        cs, _ = self.raw_multiply(self.g, w, rs)  # ⟦s⟧ = ⟦u + xe⟧
        cys, _ = self.raw_multiply(cy, w, rys)  # ⟦ys⟧ = ⟦y(u + xe)⟧
        # ⟦u⟧ * ⟦x⟧**e = ⟦u + xe⟧ = ⟦s⟧
        if cs != cu * util.powmod(cx, h, n2) % n2:
            raise InvalidProof
        # ⟦yu⟧ * ⟦z⟧**e = ⟦yu + yxe⟧ = ⟦ys⟧
        if cys != cyu * util.powmod(cz, h, n2) % n2:
            raise InvalidProof

    def prove_private_multiply_batched(self, x, cy_list):
        """Multiply a secret with several ciphertexts in a verifiable manner

        Arguments:
            x (int): the secret operand (plaintext)
            cy_list (list): the list of encrypted operands (PaillierCiphertext)

        Returns:
            tuple: `cx`, `cz_list`, `proof` where `cx` is an encryption
            (PaillierCiphertext) of x, `cz_list` is a list of encryptions
            (PaillierCiphertext) of x*y for each y in `cy_list`, and `proof`
            (int) is a proof that z = x*y for each y, z in cy_list, cz_list
        """
        n2 = self.nsquare

        # precomputable values
        try:
            # raises IndexError if not enough precomputations were forecast
            x_, (cx, rx), u, (cu, ru) = self.precomputed_values.pop()
        except AttributeError:
            # no pre-computations
            u = random.SystemRandom().randrange(self.n)
            cx, rx = self.raw_multiply(self.g, x)  # ⟦x⟧
            cu, ru = self.raw_multiply(self.g, u)  # ⟦u⟧
        else:
            # ensure consistency with arguments
            if x is None:
                x = x_
            elif x != x_:
                raise ValueError

        # encrypted result
        cz_rz_list = [self.raw_multiply(cy, x) for cy in cy_list]  # ⟦z⟧ = ⟦xy⟧
        cz_list = [cz for cz, rz in cz_rz_list]
        rz_list = [rz for cz, rz in cz_rz_list]

        lambda_list = [util.H([cx, cy, cz]) for cy, cz in zip(cy_list, cz_list)]

        # compute combined ciphertexts
        cy = util.prod(
            util.powmod(cy, lambda_, self.nsquare)
            for cy, lambda_ in zip(cy_list, lambda_list)
        )
        cz = util.prod(
            util.powmod(cz, lambda_, self.nsquare)
            for cz, lambda_ in zip(cz_list, lambda_list)
        )
        rz = util.prod(
            util.powmod(rz, lambda_, self.n)
            for rz, lambda_ in zip(rz_list, lambda_list)
        )

        # other encrypted values
        cyu, ryu = self.raw_multiply(cy, u)  # ⟦yu⟧

        # run private multiply protocol in the Fiat-Shamir heuristic
        h = util.H([cx, cy, cz, cu, cyu])
        rs = ru * util.powmod(rx, h, self.n) % self.n
        rys = ryu * util.powmod(rz, h, self.n) % self.n
        w = u + x*h
        proof = cu, cyu, w, rs, rys

        return cx, cz_list, proof

    def verify_private_multiply_batched(self, cx, cy_list, cz_list, proof):
        """Check the proof of multiplication of a ciphertext with a plaintext

        Arguments:
            cx (PaillierCiphertext): the encrypted left operand
            cy_list (list): the encrypted right operands (PaillierCiphertext)
            cz_list (list): the encrypted products (PaillierCiphertext) of x*y
                for each y in `cy_list`
            proof (int): a proof that z = x*y for each y, z in cy_list, cz_list
        """
        n2 = self.nsquare

        # generate random λ_i *after* ciphertexts have been provided
        cu, cyu, w, rs, rys = proof
        lambda_list = [util.H([cx, cy, cz]) for cy, cz in zip(cy_list, cz_list)]

        # compute combined ciphertexts
        cy = util.prod(
            util.powmod(cy, lambda_, self.nsquare)
            for cy, lambda_ in zip(cy_list, lambda_list)
        )
        cz = util.prod(
            util.powmod(cz, lambda_, self.nsquare)
            for cz, lambda_ in zip(cz_list, lambda_list)
        )

        # run private multiply protocol in the Fiat-Shamir heuristic
        h = util.H([cx, cy, cz, cu, cyu])

        # verify proofs
        cs, _ = self.raw_multiply(self.g, w, rs)  # ⟦s⟧ = ⟦u + xe⟧
        cys, _ = self.raw_multiply(cy, w, rys)  # ⟦ys⟧ = ⟦y(u + xe)⟧
        # ⟦u⟧ * ⟦x⟧**e = ⟦u + xe⟧ = ⟦s⟧
        if cs != cu * util.powmod(cx, h, n2) % n2:
            raise InvalidProof
        # ⟦yu⟧ * ⟦z⟧**e = ⟦yu + yxe⟧ = ⟦ys⟧
        if cys != cyu * util.powmod(cz, h, n2) % n2:
            raise InvalidProof

    @staticmethod
    def L(u, n):
        """As defined in the Paillier cryptosystem

        Used for decryption operations.

        Arguments:
            u (int): ciphertext (or g) to a secret exponent
            n (int): modulus currently in use
        """
        return (u - 1) // n


class PaillierSecretKey:
    """Secret key for the Paillier cryptsystem

    Attributes:
        p (int): first prime in the factorization of `n`
        q (int): second prime in the factorization of `n`
        public_key (PaillierPublicKey): the corresponding public key
        hp (int): cached value used during decryption
        hq (int): cached value used during decryption
    """
    def __init__(self, p, q, g):
        """Constructor

        Arguments:
            p (int): parameter from the Paillier cryptosystem
            q (int): parameter from the Paillier cryptosystem
            g (int): parameter from the Paillier cryptosystem
        """

        self.p = p
        self.q = q
        self.public_key = pk = PaillierPublicKey(p*q, g)

        # pre-computations
        self.hp = util.invert(pk.L(util.powmod(pk.g, p-1, p*p), p), p)
        self.hq = util.invert(pk.L(util.powmod(pk.g, q-1, q*q), q), q)

    def decrypt(self, ciphertext, relative=True):
        """Decrypt a ciphertext

        Arguments:
            ciphertext (int or PaillierCiphertext): the ciphertext
            relative (bool): whether the result should be interpreted as a
                relative integer (i.e. in [-n/2, n/2] rather than in [0, n])

        Returns:
            int: the message represented in the ciphertext

            If no transformation other than (re)randomization has been
            performed on the ciphertext, then the original message should be
            returned. If homomorphic operations have been performed, then the
            result of these operations on the original messages should be
            returned.

            If relative is set to `True`, then the returned value is a relative
            integer between `-n/2` and `n/2`. Otherwise, it is a non-negative
            integer lower than `n`.
        """
        pk = self.public_key
        p, q = self.p, self.q
        if isinstance(ciphertext, PaillierCiphertext):
            ciphertext = ciphertext.raw_value
        m_mod_p = pk.L(util.powmod(ciphertext, p-1, p*p), p) * self.hp % p
        m_mod_q = pk.L(util.powmod(ciphertext, q-1, q*q), q) * self.hq % q
        plaintext = util.crt([m_mod_p, m_mod_q], [p, q])
        if relative and plaintext >= pk.n//2:
            plaintext -= pk.n
        return plaintext


class InvalidProof(Exception):
    """Raised when the verification of a cryptographic proof fails"""


class PaillierPublicKeyShare:
    """Public key share of the Paillier cryptosystem

    Technically, it is just a single element used to verify the corresponding
    secret key share. However, this naming helps keeping the symmetry.

    Attributes:
        public_key (PaillierPublicKey): the non-shared public key

        verification_base (int): element from Q_n (quadratic residues of Z_n²);
            used as a base for cryptographic proofs
        verification (int): `verification_base^key_share` with `key_share` from
            the corresponding `PaillierSecretKeyShare`; this value is used in
            cryptographic proofs to check that the correct exponent was used in
            computations
    """
    def __init__(self, public_key, verification_base, verification):
        """Constructor

        Arguments:
            public_key (PaillierPublicKey): the non-shared Paillier public key
            verification_base (int): parameter v in shared Paillier
            verification (int): parameter v_i in shared Paillier
        """
        self.public_key = public_key
        self.verification_base = verification_base
        self.verification = verification  # v_i = v^{s_i}

    def verify_knowledge(self, proof):
        """Check the proof of knowledge of the corresponding secret key

        Arguments:
            proof (int): a proof of knowledge of the secret key
        """
        pk = self.public_key

        # run Schnorr protocol in the Fiat-Shamir heuristic
        t, w = proof
        h = util.H([self.verification_base, self.verification, t])

        # verify proof
        if util.powmod(self.verification_base, w, pk.n) != \
                t * util.powmod(self.verification, h, pk.n) % pk.n:
            raise InvalidProof

    def verify_decrypt(self, ciphertext, partial_decryption, proof):
        """Check the proof of decryption of the corresponding secret key

        Arguments:
            ciphertext (PaillierCiphertext): the ciphertext to be decrypted in
                a verifiable manner
            partial_decryption (int): the corresponding partial decryption
            proof (int): a proof that `partial_decryption` is indeed a partial
                decryption of `ciphertext` under the corresponding secret key
        """

        pk = self.public_key

        # run Chaum-Pedersen protocol in the Fiat-Shamir heuristic
        t1, t2, w = proof
        h = util.H([
            ciphertext.raw_value, partial_decryption, t1,
            self.verification_base, self.verification, t2,
        ])

        # verify proof
        # check that v^s = t_1 * v_i^c
        if util.powmod(self.verification_base, w, pk.n) != \
                t1 * util.powmod(self.verification, h, pk.n) % pk.n:
            raise InvalidProof
        # check that (x^2)^s = t_2 * (m^2)^c
        if util.powmod(ciphertext.raw_value, _CP*_QR*w, pk.n) != \
                t2 * util.powmod(partial_decryption, _CP*h, pk.n) % pk.n:
            raise InvalidProof

    def verify_decrypt_batched(self, ciphertext_batch, partial_decryption_batch, proof):
        """Batched version of `verify_decrypt()`

        Arguments:
            ciphertext_batch (list): the ciphertexts (PaillierCiphertext) to be
                decrypted in a verifiable manner
            partial_decryption_batch (list): the corresponding partial
                decryptions (int)
            proof: a proof that each element of `partial_decryption_batch` is
                indeed a partial decryption of the corresponding element in
                `ciphertext_batch` under the secret key corresponding to self
        """
        pk = self.public_key

        # run protocol in the Fiat-Shamir heuristic
        t1, t2, w = proof

        # generate random λ_i *after* decryption shares have been provided
        lambda_batch = [
            util.H([ciphertext.raw_value, partial_decryption])
            for ciphertext, partial_decryption in zip(ciphertext_batch, partial_decryption_batch)
        ]

        # compute combined plaintext and ciphertext for verification
        combined_plaintext = util.prod(
            util.powmod(plaintext, lambda_, pk.n)
            for plaintext, lambda_ in zip(partial_decryption_batch, lambda_batch)
        )
        combined_ciphertext = util.prod(
            util.powmod(ciphertext.raw_value, lambda_, pk.n)
            for ciphertext, lambda_ in zip(ciphertext_batch, lambda_batch)
        )
        h = util.H([
            combined_ciphertext, combined_plaintext, t1,
            self.verification_base, self.verification, t2,
        ])

        # verify proof
        # check that v^s = t_1 * v_i^c
        if util.powmod(self.verification_base, w, pk.n) != \
                t1 * util.powmod(self.verification, h, pk.n) % pk.n:
            raise InvalidProof
        # check that (x^2)^s = t_2 * (m^2)^c
        if util.powmod(combined_ciphertext, _CP*_QR*w, pk.n) != \
                t2 * util.powmod(combined_plaintext, _CP*h, pk.n) % pk.n:
            raise InvalidProof

    @staticmethod
    def assemble_decryption_shares(ciphertext, shares, decryption_shares, relative=True):
        """Assemble decryptions share in a complete decryption

        Arguments:
            shares (list): the public key shares (PaillierPublicKeyShare)
                corresponding to the secret key shares used to decrypt the
                ciphertext
            decryption_shares (list): the decryption shares (int) resulting
                from the (partial) decryptions by the secret key shares
            relative (bool): whether the result should be interpreted as a
                relative integer (i.e. in [-n/2, n/2] rather than in [0, n])

        Returns:
            int: the message represented in the ciphertext

            If no transformation other than (re)randomization has been
            performed on the ciphertext, then the original message should be
            returned. If homomorphic operations have been performed, then the
            result of these operations on the original messages should be
            returned.

            If relative is set to `True`, then the returned value is a relative
            integer between `-n/2` and `n/2`. Otherwise, it is a non-negative
            integer lower than `n`.
        """
        pk = shares[0].public_key
        C = ciphertext.raw_value
        R = util.prod(decryption_shares, pk.n)
        plaintext = ((C*util.powmod(R, -pk.n, pk.nsquare) % pk.nsquare) - 1) // pk.n
        # TODO:  _QR
        if relative and plaintext >= pk.n // 2:
            plaintext -= pk.n
        return plaintext


class PaillierSecretKeyShare:
    """Secret key share of the Paillier cryptsystem

    Attributes:
        public_key (PaillierPublicKey): the non-shared public key
        verification_base (int): element from Q_n (quadratic residues of Z_n²);
            used as a base for cryptographic proofs
        key_share (int): the share of the secret exponent used for decryption
    """
    def __init__(self, public_key, verification_base, key_share):
        """Constructor

        Arguments:
            public_key (PaillierPublicKey): the non-shared Paillier public key
            key_share (int): parameter s_i in shared Paillier
        """
        self.public_key = public_key
        self.verification_base = verification_base
        self.key_share = key_share
        n2 = public_key.nsquare
        self.verification = util.powmod(verification_base, key_share, n2)

    def precompute_proofs(self, n_uses):
        """Precompute and cache some values used in the proofs

        Using this function does not decreases (nor increases, assuming the
        exact value for `n_uses` is provided) the total execution time.
        However, it can be useful to perform some computation in advance, so
        that the actual use of the secret shares does not take as much time
        (i.e. when the inputs to the protocol are known).

        Arguments:
            n_uses (int): upper-bound on the number of proofs that will be
                performed (the larger the value, the longer this step takes)
        """
        pk = self.public_key
        randoms = [
            random.SystemRandom().randrange(pk.n << (2*pk.security_parameter))
            for _ in range(n_uses)
        ]
        self.precomputed_values = [
            (r, util.powmod(self.verification_base, r, pk.n))
            for r in randoms
        ]

    def prove_knowledge(self):
        """Proves knowldege of the secret key share

        Returns:
            int: the proof
        """
        pk = self.public_key

        try:
            # raises IndexError if not enough precomputations were forecast
            r, t = self.precomputed_values.pop()
        except AttributeError:
            # no pre-computations
            r = random.SystemRandom().randrange(pk.n << (2*pk.security_parameter))
            t = util.powmod(self.verification_base, r, pk.n)

        # run Schnorr protocol in the Fiat-Shamir heuristic
        h = util.H([self.verification_base, self.verification, t])
        w = r + h * self.key_share
        proof = t, w
        return proof

    def decrypt(self, ciphertext):
        """(Partially) decrypt a ciphertext

        Arguments:
            ciphertext (PaillierCiphertext): the ciphertext to be decrypted

        Returns:
            int: the decryption share of the ciphertext corresponding to this
                secret key share
        """
        pk = self.public_key
        return util.powmod(ciphertext.raw_value, _QR*self.key_share, pk.n)

    def prove_decrypt(self, ciphertext):
        """(Partially) decrypt a ciphertext in a verifiable manner

        Arguments:
            ciphertext (PaillierCiphertext): the ciphertext to be decrypted

        Returns:
            tuple: `partial_decryption`, `proof` where `partial_decryption` is
            the partial decryption (int) of the ciphertext, and `proof` is a
            proof (int) that it is indeed so
        """
        pk = self.public_key
        partial_decryption = self.decrypt(ciphertext)

        try:
            # raises IndexError if not enough precomputations were forecast
            r, t1 = self.precomputed_values.pop()
        except AttributeError:
            # no pre-computations
            r = random.SystemRandom().randrange(pk.n << (2*pk.security_parameter))
            t1 = util.powmod(self.verification_base, r, pk.n)

        # prove knowledge of key_share such that:
        #   * v_i = v**key_share
        #   * (partial_decryption**2) = (ciphertext**2)**(2*key_share)
        t2 = util.powmod(ciphertext.raw_value, _CP*_QR*r, pk.n)

        # run Chaum-Pedersen protocol in the Fiat-Shamir heuristic
        h = util.H([
            ciphertext.raw_value, partial_decryption, t1,
            self.verification_base, self.verification, t2,
        ])
        w = r + h * self.key_share
        proof = t1, t2, w
        return partial_decryption, proof

    def prove_decrypt_batched(self, ciphertext_batch):
        """Batched version of `prove_decrypt()`

        Arguments:
            ciphertext_batch (list): the ciphertexts (PaillierCiphertext) to be
                decrypted in a verifiable manner

        Returns:
            tuple: `partial_decryption_batch`, `proof` where
            `partial_decryption_batch` is a list of the partial decryptions
            (int) of the ciphertexts, and `proof` is a proof (int) that they
            are indeed so
        """
        pk = self.public_key
        partial_decryption_batch = [
            self.decrypt(ciphertext)
            for ciphertext in ciphertext_batch
        ]

        # run protocol in the Fiat-Shamir heuristic

        # to aggregate ZKPs, the verifier provides λ_i *after* the plaintexts
        # have been provided; then combined_ciphertext = ∏ ciphertext^{λ_i}
        # and combined_plaintext = ∏ m^{λ_i} (not needed for prover)
        lambda_batch = [
            util.H([ciphertext.raw_value, partial_decryption])
            for ciphertext, partial_decryption in zip(ciphertext_batch, partial_decryption_batch)
        ]
        combined_plaintext = util.prod(
            util.powmod(plaintext, lambda_, pk.n)
            for plaintext, lambda_ in zip(partial_decryption_batch, lambda_batch)
        )
        combined_ciphertext = util.prod(
            util.powmod(ciphertext.raw_value, lambda_, pk.n)
            for ciphertext, lambda_ in zip(ciphertext_batch, lambda_batch)
        )

        try:
            # raises IndexError if not enough precomputations were forecast
            r, t1 = self.precomputed_values.pop()
        except AttributeError:
            # no pre-computations
            r = random.SystemRandom().randrange(pk.n << (2*pk.security_parameter))
            t1 = util.powmod(self.verification_base, r, pk.n)

        # prove knowledge of key_share such that:
        #   * v_i = v**key_share
        #   * combined_plaintext**2 = (combined_ciphertext**2)**(2*key_share)
        t2 = util.powmod(combined_ciphertext, _CP*_QR*r, pk.n)
        h = util.H([
            combined_ciphertext, combined_plaintext, t1,
            self.verification_base, self.verification, t2,
        ])
        w = r + h * self.key_share
        proof = t1, t2, w
        return partial_decryption_batch, proof


class PaillierCiphertext:
    """Ciphertext from the Paillier cryptosystem

    Attributes:
        public_key (PaillierPublicKey): the Paillier public key used to
            generate this ciphertext
        raw_value (int): an element of Z_n², that should equals to `g^m r^n`
            where `n` and `g` are the attributes of the public key, `m` is the
            message which was encrypted and `r` is a random element of Z_n
    """
    def __init__(self, public_key, raw_value):
        """Constructor

        Arguments:
            public_key (PaillierPublicKey): the Paillier public key
            raw_value (int): the actual ciphertext as an element of Z_n²
        """
        self.public_key = public_key
        self.raw_value = raw_value

    def __add__(a, b):
        """Homomorphically add two Paillier ciphertexts together

        Arguments:
            a (PaillierCiphertext): left operand
            b (PaillierCiphertext or int): right operand

        Returns:
            PaillierCiphertext: decrypting this ciphertext should yield the sum
                of the values obtained by decrypting the ciphertexts `a` and
                `b` (or `b` itself)
        """
        pk = a.public_key
        if not isinstance(b, PaillierCiphertext):
            b, _ = pk.raw_multiply(pk.g, b, randomization=1)
        elif b.public_key != pk:
            raise ValueError('cannot sum values under different public keys')
        else:
            b = b.raw_value
        return PaillierCiphertext(pk, a.raw_value * b % pk.nsquare)

    def __radd__(a, b):
        """Homomorphically add two Paillier ciphertexts together

        Arguments:
            a (PaillierCiphertext): right operand
            b (PaillierCiphertext or int): left operand

        Returns:
            PaillierCiphertext: decrypting this ciphertext should yield the sum
                of the values obtained by decrypting the ciphertexts `a` and
                `b` (or `b` itself)
        """
        return a + b

    def __neg__(a):
        """Homomorphically negate a Paillier ciphertext

        Arguments:
            a (PaillierCiphertext): operand

        Returns:
            PaillierCiphertext: decrypting this ciphertext should yield the
                opposite of the value obtained by decrypting the ciphertext `a`
        """
        return a * -1

    def __sub__(a, b):
        """Homomorphically subtract two Paillier ciphertexts

        Arguments:
            a (PaillierCiphertext): left operand
            b (PaillierCiphertext or int): right operand

        Returns:
            PaillierCiphertext: decrypting this ciphertext should yield the
                the value obtained by decrypting the ciphertext `a` minus the
                value obtained by decrypted the ciphertext `b` (or `b` itself)
        """
        return a + -b

    def __rsub__(a, b):
        """Homomorphically subtract two Paillier ciphertexts

        Arguments:
            a (PaillierCiphertext): right operand
            b (PaillierCiphertext or int): left operand

        Returns:
            PaillierCiphertext: decrypting this ciphertext should yield the
                the value obtained by decrypting the ciphertext `b` (or `b`
                itself) minus the value obtained by decrypted the ciphertext
                `a`
        """
        return b + -a

    def __mul__(a, b):
        """Homomorphically multiply a Paillier ciphertext by an integer

        Note that it is not possible to perform this operation between two
        Paillier ciphertexts. This is because the Paillier cryptosystem is only
        partially homomorphic, and not fully homomorphic. For an implementation
        of a fully homomorphic cryptosystem, search for TFHE.

        Arguments:
            a (PaillierCiphertext): left operand
            b (int): right operand

        Returns:
            PaillierCiphertext: decrypting this ciphertext should yield the
                product of the value obtained by decrypting the ciphertext `a`
                with the integer `b`
        """
        if isinstance(b, PaillierCiphertext):
            raise NotImplementedError('Have a look at TFHE ;-)')
        pk = a.public_key
        raw_value, _ = pk.raw_multiply(a.raw_value, b, randomization=1)
        return PaillierCiphertext(pk, raw_value)

    def __rmul__(a, b):
        """Homomorphically multiply a Paillier ciphertext by an integer

        Note that it is not possible to perform this operation between two
        Paillier ciphertexts. This is because the Paillier cryptosystem is only
        partially homomorphic, and not fully homomorphic. For an implementation
        of a fully homomorphic cryptosystem, search for TFHE.

        Arguments:
            a (PaillierCiphertext): right operand
            b (int): left operand

        Returns:
            PaillierCiphertext: decrypting this ciphertext should yield the
                product of the value obtained by decrypting the ciphertext `a`
                with the integer `b`
        """
        return a * b

    def __truediv__(a, b):
        """Homomorphically divide a Paillier ciphertext by an integer

        Note that it is not possible to perform this operation between two
        Paillier ciphertexts. This is because the Paillier cryptosystem is only
        partially homomorphic, and not fully homomorphic. For an implementation
        of a fully homomorphic cryptosystem, search for TFHE.

        Also note that his is an exact division modulo `n`. Thus, the result is
        itself an integer `q` such that `q × b = a mod n`.

        Arguments:
            a (PaillierCiphertext): left operand
            b (int): right operand

        Returns:
            PaillierCiphertext: decrypting this ciphertext should yield the
                division modulo `n` of the value obtained by decrypting the
                ciphertext `a` with the integer `b`
        """
        if isinstance(b, PaillierCiphertext):
            raise NotImplementedError('Have a look at TFHE ;-)')
        pk = a.public_key
        if b not in pk.inverts:
            pk.inverts[b] = util.invert(b, pk.n)
        return a * pk.inverts[b]
