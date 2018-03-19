#!/usr/bin/env python3
"""Mock implementation of a partially homomorphic cryptosystem

This is mostly useful for testing the correctness of protocols relying on the
Paillier cryptosystem without incurring the computational cost of actually
using an implementation of Paillier.

The main entry point of this module is `generate_mock_keypair()`.
"""


def generate_mock_keypair(*args, **kwargs):
    """Generate a pair of mock keys

    Returns:
        tuple: pair of two elements, usually named respectively `pk`
            (`MockPaillierPublicKey`), and `sk` (`MockPaillierPrivateKey`)

        The public key (`pk`) allows to encrypt messages (relative integers);
        the secret key (`sk`) allows to decrypt ciphertexts generated using
        that public key (but not using another).
    """
    sk = MockPaillierPrivateKey()
    return sk.public_key, sk


class MockPaillierPublicKey:
    """Mock public key for the Paillier cryptosystem

    Attributes:
        security_parameter (int): required level of security in bits, used for
            various protocols
    """
    def __init__(self):
        """Constructor"""
        self.security_parameter = 80

    def encrypt(self, m):
        """Encrypt a message m into a ciphertext

        Arguments:
            m (int): the message to be encrypted

        Returns:
            PaillierCiphertext: a ciphertext for the given integer `m` it can
                be decrypted using the secret key corresponding to this public
                key
        """
        return MockPaillierCiphertext(self, m)


class MockPaillierPrivateKey:
    """Mock secret key for the Paillier cryptosystem

    Attributes:
        public_key (MockPaillierPublicKey): the corresponding public key
    """
    def __init__(self):
        """Constructor"""
        self.public_key = MockPaillierPublicKey()

    def decrypt(self, ciphertext):
        """Decrypt a ciphertext

        Arguments:
            ciphertext (MockPaillierCiphertext): the ciphertext to be decrypted

        Returns:
            int: the message represented in the ciphertext

            If no transformation other than (re)randomization has been
            performed on the ciphertext, then the original message should be
            returned. If homomorphic operations have been performed, then the
            result of these operations on the original messages should be
            returned.
        """
        assert ciphertext.public_key == self.public_key
        return ciphertext.raw_value


class MockPaillierCiphertext:
    """Mock ciphertext from the Paillier cryptosystem

        public_key (MockPaillierPublicKey): the mock Paillier public key used
            to generate this ciphertext
        raw_value (int): an element of Z_n², that should equals to `g^m r^n`
            where `n` and `g` are the attributes of the public key, `m` is the
            message which was encrypted and `r` is a random element of Z_n
    """
    def __init__(self, public_key, raw_value):
        """Constructor

        Arguments:
            public_key (PaillierPublicKey): the Paillier public key
            raw_value (int): the actual ciphertext
        """
        self.public_key = public_key
        self.raw_value = raw_value

    def __add__(self, other):
        """Homomorphically add two mock Paillier ciphertexts together

        Arguments:
            a (MockPaillierCiphertext): left operand
            b (MockPaillierCiphertext or int): right operand

        Returns:
            MockPaillierCiphertext: decrypting this ciphertext should yield the
                sum of the values obtained by decrypting the ciphertexts `a`
                and `b` (or `b` itself)
        """
        pk = self.public_key
        if isinstance(other, MockPaillierCiphertext):
            return MockPaillierCiphertext(pk, self.raw_value + other.raw_value)
        else:
            return MockPaillierCiphertext(pk, self.raw_value + other)

    def __radd__(self, other):
        """Homomorphically add two mock Paillier ciphertexts together

        Arguments:
            a (MockPaillierCiphertext): right operand
            b (MockPaillierCiphertext or int): left operand

        Returns:
            MockPaillierCiphertext: decrypting this ciphertext should yield the
                sum of the values obtained by decrypting the ciphertexts `a`
                and `b` (or `b` itself)
        """
        return self + other

    def __neg__(self):
        """Homomorphically negate a mock Paillier ciphertext

        Arguments:
            a (MockPaillierCiphertext): operand

        Returns:
            MockPaillierCiphertext: decrypting this ciphertext should yield the
                opposite of the value obtained by decrypting the ciphertext `a`
        """
        return self * -1

    def __sub__(self, other):
        """Homomorphically subtract two mock Paillier ciphertexts

        Arguments:
            a (MockPaillierCiphertext): left operand
            b (MockPaillierCiphertext or int): right operand

        Returns:
            MockPaillierCiphertext: decrypting this ciphertext should yield the
                the value obtained by decrypting the ciphertext `a` minus the
                value obtained by decrypted the ciphertext `b` (or `b` itself)
        """
        return self + -other

    def __rsub__(self, other):
        """Homomorphically subtract two mock Paillier ciphertexts

        Arguments:
            a (MockPaillierCiphertext): right operand
            b (MockPaillierCiphertext or int): left operand

        Returns:
            MockPaillierCiphertext: decrypting this ciphertext should yield the
                the value obtained by decrypting the ciphertext `b` (or `b`
                itself) minus the value obtained by decrypted the ciphertext
                `a`
        """
        return -self + other

    def __mul__(self, other):
        """Homomorphically multiply a mock Paillier ciphertext by an integer

        Note that it is not possible to perform this operation between two
        (mock) Paillier ciphertexts. This is because the Paillier cryptosystem
        is only partially homomorphic, and not fully homomorphic. For an
        implementation of a fully homomorphic cryptosystem, search for TFHE.

        Arguments:
            a (MockPaillierCiphertext): left operand
            b (int): right operand

        Returns:
            MockPaillierCiphertext: decrypting this ciphertext should yield the
                product of the value obtained by decrypting the ciphertext `a`
                with the integer `b`
        """
        pk = self.public_key
        if isinstance(other, MockPaillierCiphertext):
            raise NotImplementedError('Good luck with that...')
        else:
            return MockPaillierCiphertext(pk, self.raw_value * other)

    def __rmul__(self, other):
        """Homomorphically multiply a mock Paillier ciphertext by an integer

        Note that it is not possible to perform this operation between two
        (mock) Paillier ciphertexts. This is because the Paillier cryptosystem
        is only partially homomorphic, and not fully homomorphic. For an
        implementation of a fully homomorphic cryptosystem, search for TFHE.

        Arguments:
            a (MockPaillierCiphertext): right operand
            b (int): left operand

        Returns:
            MockPaillierCiphertext: decrypting this ciphertext should yield the
                product of the value obtained by decrypting the ciphertext `a`
                with the integer `b`
        """
        return self * other

    def __truediv__(self, other):
        """Homomorphically divide a mock Paillier ciphertext by an integer

        Note that it is not possible to perform this operation between two
        (mock) Paillier ciphertexts. This is because the Paillier cryptosystem
        is only partially homomorphic, and not fully homomorphic. For an
        implementation of a fully homomorphic cryptosystem, search for TFHE.

        Also note that his is an exact division modulo `n`. Thus, the result is
        itself an integer `q` such that `q × b = a mod n`.

        Arguments:
            a (PaillierCiphertext): left operand
            b (int): right operand

        Returns:
            MockPaillierCiphertext: decrypting this ciphertext should yield the
                division modulo `n` of the value obtained by decrypting the
                ciphertext `a` with the integer `b`
        """
        pk = self.public_key
        if isinstance(other, MockPaillierCiphertext):
            raise NotImplementedError('Good luck with that...')
        else:
            assert self.raw_value % other == 0  # assume the simple case
            return MockPaillierCiphertext(pk, self.raw_value // other)
