#!/usr/bin/env python


class MockPaillierEncryptedNumber:
    def __init__(self, x):
        self.x = x

    def __add__(self, other):
        if isinstance(other, MockPaillierEncryptedNumber):
            return MockPaillierEncryptedNumber(self.x + other.x)
        else:
            return MockPaillierEncryptedNumber(self.x + other)

    def __radd__(self, other):
        return self + other

    def __mul__(self, other):
        if isinstance(other, MockPaillierEncryptedNumber):
            raise NotImplementedError('Good luck with that...')
        else:
            return MockPaillierEncryptedNumber(self.x * other)

    def __rmul__(self, other):
        return self * other

    def __neg__(self):
        return self * -1

    def __sub__(self, other):
        return self + -other

    def __rsub__(self, other):
        return -self + other

    def __truediv__(self, other):
        if isinstance(other, MockPaillierEncryptedNumber):
            raise NotImplementedError('Good luck with that...')
        else:
            assert self.x % other == 0
            return MockPaillierEncryptedNumber(self.x // other)


class MockPaillierPrivateKey:
    def decrypt(self, x):
        return x.x


class MockPaillierPublicKey:
    def encrypt(self, x):
        return MockPaillierEncryptedNumber(x)


def mock_paillier_keypair():
    return MockPaillierPublicKey(), MockPaillierPrivateKey()
