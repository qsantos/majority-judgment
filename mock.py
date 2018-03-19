#!/usr/bin/env python


def generate_mock_keypair(*args, **kwargs):
    sk = MockPaillierPrivateKey()
    return sk.public_key, sk


class MockPaillierPublicKey:
    def encrypt(self, x):
        return MockPaillierEncryptedNumber(self, x)


class MockPaillierPrivateKey:
    def __init__(self):
        self.public_key = MockPaillierPublicKey()

    def decrypt(self, x):
        assert x.public_key == self.public_key
        return x.x


class MockPaillierEncryptedNumber:
    def __init__(self, public_key, x):
        self.public_key = public_key
        self.x = x

    def __add__(self, other):
        pk = self.public_key
        if isinstance(other, MockPaillierEncryptedNumber):
            return MockPaillierEncryptedNumber(pk, self.x + other.x)
        else:
            return MockPaillierEncryptedNumber(pk, self.x + other)

    def __radd__(self, other):
        return self + other

    def __mul__(self, other):
        pk = self.public_key
        if isinstance(other, MockPaillierEncryptedNumber):
            raise NotImplementedError('Good luck with that...')
        else:
            return MockPaillierEncryptedNumber(pk, self.x * other)

    def __rmul__(self, other):
        return self * other

    def __neg__(self):
        return self * -1

    def __sub__(self, other):
        return self + -other

    def __rsub__(self, other):
        return -self + other

    def __truediv__(self, other):
        pk = self.public_key
        if isinstance(other, MockPaillierEncryptedNumber):
            raise NotImplementedError('Good luck with that...')
        else:
            assert self.x % other == 0
            return MockPaillierEncryptedNumber(pk, self.x // other)
