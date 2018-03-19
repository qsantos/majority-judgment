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


def generate_paillier_keypair_shares(n_shares, n_bits=2048, safe_primes=True):
    """Generate shares of keys for the Paillier cryptosystem

    It adds an attribute `verification_base` to `pk` (the value returned of
    type `PaillierPublicKey`). It is an element from Q_n, the subgroup of the
    squares of Z_n²^* (i.e. the quadratic residues of Z_n²). This value is used
    as a base for each verification in a public key share (attribute
    `verification` of `PaillierPublicKeyShare`).

    Arguments:
        n_shares (int): the number of shares into which the secret key should
            be split
        n_bits (int, optional): the number of bits for the parameter `n`; they
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
        tuple: triplet of three elements, usually named respectively `pk`
            (`PaillierPublicKey`), `pk_shares` (`list` of
            `PaillierPublicKeyShare`) and `sk_shares` (`list` of
            `PaillierSecretKeyShare`).

        The public key (`pk`) allows to encrypt messages (relative integers).
        When used together, the secret key shares (`sk_shares`) allow to
        decrypt ciphertexts generated using that public key (but not using
        another), using the method `assemble_decryption_shares()` from
        `PaillierPublicKeyShare`. The public key shares (`pk_shares`) can be
        used to verify that each secret key share was used correctly (usually
        one share would be given to each party, and decryption would imply that
        each party correctly processes the ciphertext using their secret key
        share).
    """
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
    """Public key for the Paillier cryptosystem

    Attributes:
        n (int): parameter `n` from the Paillier cryptosystem, should be the
            product of large safe primes (as large as possible, so ideally two
            primes of the same size)
        g (int): parameter `g` from the Paillier cryptsystem, should an
            invertible element of Z_n² whose order is a positive multiple of
            λ(n) where λ is the Carmichael function; in
            `generate_paillier_keypair()`, `g` is set to `1 + n`
        nsquare (int): cached value of `n × n`, used in operations on the
            ciphertext (probably insignificant gains and could be removed)
    """

    def __init__(self, n, g):
        """Constructor

        Arguments:
            n (int): parameter from the Paillier cryptosystem
            g (int): parameter from the Paillier cryptosystem
        """
        self.n = n
        self.nsquare = n * n
        self.g = g

        # cache
        self.inverts = {}

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
        n2 = self.nsquare
        m %= self.n  # explicitely reduces m to avoid negative/large exponents

        if self.g == 1 + self.n:
            raw_value = (1 + self.n * m) % n2
        else:
            raw_value = util.powmod(self.g, m, n2)

        if randomize:
            r = random.SystemRandom().randrange(self.n)
            raw_value = raw_value * util.powmod(r, self.n, n2) % n2
        return PaillierCiphertext(self, raw_value)

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
            ciphertext (PaillierCiphertext): the ciphertext to be decrypted
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
        ciphertext = ciphertext.raw_value
        m_mod_p = pk.L(util.powmod(ciphertext, p-1, p*p), p) * self.hp % p
        m_mod_q = pk.L(util.powmod(ciphertext, q-1, q*q), q) * self.hq % q
        plaintext = util.crt([m_mod_p, m_mod_q], [p, q])
        if relative and plaintext >= pk.n//2:
            plaintext -= pk.n
        return int(plaintext)


class InvalidProof(Exception):
    """Raised when the verification of a cryptographic proof fails"""


class PaillierPublicKeyShare:
    """Public key share of the Paillier cryptosystem

    Technically, it is just a single element used to verify the corresponding
    secret key share. However, this naming helps keeping the symmetry.

    Attributes:
        public_key (PaillierPublicKey): the non-shared public key
        verification (int): v^{s_i} where v is the attribute
            `verification_base` set in `generate_paillier_keypair_shares()` on
            `PaillierPublicKey` and `s_i` is the attribute `key_share` from the
            corresponding `PaillierSecretKeyShare`; this value is used in
            verification to check that the correct exponent was used in
            computations
    """
    def __init__(self, public_key, verification):
        """Constructor

        Arguments:
            public_key (PaillierPublicKey): the non-shared Paillier public key
            verification (int): parameter v_i in shared Paillier
        """
        self.public_key = public_key
        self.verification = verification  # v_i = v^{s_i}

    def verify_knowledge(self):
        """Check the proof of knowledge of the corresponding secret key

        Returns:
            generator: the corresponding protocol
        """
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
        """Check the proof of decryption of the corresponding secret key

        Arguments:
            ciphertext (PaillierCiphertext): the ciphertext to be decrypted in
                a verifiable manner

        Returns:
            generator: the corresponding protocol

            The generator itself returns a decryption share (int) of the
            ciphertext, to be given to `assemble_decryption_shares` along with
            the decryption shares from the other secret key shares
        """

        pk = self.public_key

        # run Chaum-Pedersen protocol
        partial_decryption, left_commitment, right_commitment = yield
        challenge = random.SystemRandom().randrange(2**80)
        proof = yield challenge  # proof is usually noted s

        # verify proof
        # check that v^s = t_1 * v_i^c
        if util.powmod(pk.verification_base, proof, pk.nsquare) != \
                left_commitment * util.powmod(self.verification, challenge, pk.nsquare) % pk.nsquare:
            raise InvalidProof
        # check that x^s = t_2 * m^c
        if util.powmod(ciphertext.raw_value, proof, pk.nsquare) != \
                right_commitment * util.powmod(partial_decryption, challenge, pk.nsquare) % pk.nsquare:
            raise InvalidProof

        return partial_decryption

    def verify_decrypt_batched(self, ciphertext_batch):
        """Batched version of `verify_decrypt()`

        Arguments:
            ciphertext_batch (list): the ciphertexts (PaillierCiphertext) to be
                decrypted in a verifiable manner

        Returns:
            generator: the corresponding protocol

            The generator itself returns a list; each element is an integer
            corresponding to the decryption share of the corresponding
            ciphertext from `ciphertext_batch` (i.e. in the same order), to be
            given to `assemble_decryption_shares` with other decryption shares
            of this particular ciphertext from the other secret key shares
        """
        pk = self.public_key

        # generate random λ_i *after* decryption shares have been provided
        partial_decryption_batch = yield
        lambda_batch = [
            random.SystemRandom().randrange(2**80)
            for _ in ciphertext_batch
        ]

        # run Chaum-Pedersen protocol
        left_commitment, right_commitment = yield lambda_batch
        challenge = random.SystemRandom().randrange(2**80)
        proof = yield challenge  # proof is usually noted s

        # compute combined plaintext and ciphertext for verification
        combined_plaintext = util.prod(
            util.powmod(plaintext, lambda_, pk.nsquare)
            for plaintext, lambda_ in zip(partial_decryption_batch, lambda_batch)
        )
        combined_ciphertext = util.prod(
            util.powmod(ciphertext.raw_value, lambda_, pk.nsquare)
            for ciphertext, lambda_ in zip(ciphertext_batch, lambda_batch)
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

        return partial_decryption_batch

    @staticmethod
    def assemble_decryption_shares(shares, decryption_shares, relative=True):
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
        plaintext = pk.L(util.prod(decryption_shares, pk.nsquare), pk.n)
        if relative and plaintext >= pk.n // 2:
            plaintext -= pk.n
        return int(plaintext)


class PaillierSecretKeyShare:
    """Secret key share of the Paillier cryptsystem

    Attributes:
        public_key (PaillierPublicKey): the non-shared public key
        key_share (int): the share of the secret exponent used for decryption
    """
    def __init__(self, public_key, key_share):
        """Constructor

        Arguments:
            public_key (PaillierPublicKey): the non-shared Paillier public key
            key_share (int): parameter s_i in shared Paillier
        """
        self.public_key = public_key
        self.key_share = key_share

    def precompute(self, n_uses):
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
            random.SystemRandom().randrange(pk.nsquare << 160)
            for _ in range(n_uses)
        ]
        self.precomputed_values = [
            (r, util.powmod(pk.verification_base, r, pk.nsquare))
            for r in randoms
        ]

    def prove_knowledge(self):
        """Proves knowldege of the secret key share

        Returns:
            generator: the corresponding protocol
        """
        pk = self.public_key

        if hasattr(self, 'precomputed_values'):
            # raises an exception if not enough precomputations were forecast
            r, commitment = self.precomputed_values.pop()
        else:
            r = random.SystemRandom().randrange(pk.nsquare << 160)
            commitment = util.powmod(pk.verification_base, r, pk.nsquare)

        challenge = yield commitment
        assert challenge < 2**80
        yield r + challenge * self.key_share

    def decrypt(self, ciphertext):
        """(Partially) decrypt a ciphertext

        Arguments:
            ciphertext (PaillierCiphertext): the ciphertext to be decrypted

        Returns:
            int: the decryption share of the ciphertext corresponding to this
                secret key share
        """
        pk = self.public_key
        return util.powmod(ciphertext.raw_value, self.key_share, pk.nsquare)

    def prove_decrypt(self, ciphertext):
        """(Partially) decrypt a ciphertext in a verifiable manner

        Arguments:
            ciphertext (PaillierCiphertext): the ciphertext to be decrypted

        Returns:
            generator: the corresponding protocol
        """
        pk = self.public_key
        partial_decryption = self.decrypt(ciphertext)

        if hasattr(self, 'precomputed_values'):
            # raises an exception if not enough precomputations were forecast
            r, left_commitment = self.precomputed_values.pop()
        else:
            r = random.SystemRandom().randrange(pk.nsquare << 160)
            left_commitment = util.powmod(pk.verification_base, r, pk.nsquare)

        # prove knowledge of key_share such that:
        #   * v_i = v**key_share
        #   * partial_decryption = ciphertext**key_share
        right_commitment = util.powmod(ciphertext.raw_value, r, pk.nsquare)
        challenge = yield partial_decryption, left_commitment, right_commitment
        assert challenge < 2**80
        yield r + challenge * self.key_share

    def prove_decrypt_batched(self, ciphertext_batch):
        """Batched version of `prove_decrypt()`

        Arguments:
            ciphertext_batch (list): the ciphertexts (PaillierCiphertext) to be
                decrypted in a verifiable manner

        Returns:
            generator: the corresponding protocol
        """
        pk = self.public_key
        partial_decryption_batch = [
            self.decrypt(ciphertext)
            for ciphertext in ciphertext_batch
        ]

        # to aggregate ZKPs, the verifier provides λ_i *after* the plaintexts
        # have been provided; then combined_ciphertext = ∏ ciphertext^{λ_i}
        # and combined_plaintext = ∏ m^{λ_i} (not needed for prover)
        lambda_batch = yield partial_decryption_batch
        combined_ciphertext = util.prod(
            util.powmod(ciphertext.raw_value, lambda_, pk.nsquare)
            for ciphertext, lambda_ in zip(ciphertext_batch, lambda_batch)
        )

        if hasattr(self, 'precomputed_values'):
            # raises an exception if not enough precomputations were forecast
            r, left_commitment = self.precomputed_values.pop()
        else:
            r = random.SystemRandom().randrange(pk.nsquare << 160)
            left_commitment = util.powmod(pk.verification_base, r, pk.nsquare)

        # prove knowledge of key_share such that:
        #   * v_i = v**key_share
        #   * combined_plaintext = combined_ciphertext**key_share
        right_commitment = util.powmod(combined_ciphertext, r, pk.nsquare)
        challenge = yield left_commitment, right_commitment
        assert challenge < 2**80
        yield r + challenge * self.key_share


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
            b = pk.encrypt(b, randomize=False)
        elif b.public_key != pk:
            raise ValueError('cannot sum values under different public keys')
        return PaillierCiphertext(pk, a.raw_value * b.raw_value % pk.nsquare)

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
        a = a.raw_value
        b %= pk.n

        if b > pk.n // 2:
            # small negatives values are common and it is faster to compute an
            # invert than an exponentiation to a value close to n
            b = pk.n - b
            a = util.invert(a, pk.nsquare)

        return PaillierCiphertext(pk, util.powmod(a, b, pk.nsquare))

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
