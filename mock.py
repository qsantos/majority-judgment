#!/usr/bin/env python3


def generate_mock_keypair(*args, **kwargs):
    sk = MockPaillierPrivateKey()
    return sk.public_key, sk


class MockPaillierPublicKey:
    def encrypt(self, m):
        return MockPaillierCiphertext(self, m)


class MockPaillierPrivateKey:
    def __init__(self):
        self.public_key = MockPaillierPublicKey()

    def decrypt(self, ciphertext):
        assert ciphertext.public_key == self.public_key
        return ciphertext.raw_value


class MockPaillierCiphertext:
    def __init__(self, public_key, raw_value):
        self.public_key = public_key
        self.raw_value = raw_value

    def __add__(self, other):
        pk = self.public_key
        if isinstance(other, MockPaillierCiphertext):
            return MockPaillierCiphertext(pk, self.raw_value + other.raw_value)
        else:
            return MockPaillierCiphertext(pk, self.raw_value + other)

    def __radd__(self, other):
        return self + other

    def __neg__(self):
        return self * -1

    def __sub__(self, other):
        return self + -other

    def __rsub__(self, other):
        return -self + other

    def __mul__(self, other):
        pk = self.public_key
        if isinstance(other, MockPaillierCiphertext):
            raise NotImplementedError('Good luck with that...')
        else:
            return MockPaillierCiphertext(pk, self.raw_value * other)

    def __rmul__(self, other):
        return self * other

    def __truediv__(self, other):
        pk = self.public_key
        if isinstance(other, MockPaillierCiphertext):
            raise NotImplementedError('Good luck with that...')
        else:
            assert self.raw_value % other == 0
            return MockPaillierCiphertext(pk, self.raw_value // other)
