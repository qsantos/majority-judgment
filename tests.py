#!/usr/bin/env python
import unittest

import util
import mock
import paillier

_N_BITS = 103


class PartiallyHomomorphicSchemeFixture:
    def test_encrypt(self):
        pk, sk = self.generate_keypair(_N_BITS)

        # check the ciphertexts are actually randomized
        c = pk.encrypt(12)
        d = pk.encrypt(12)
        self.assertTrue(c != d)

    def test_decrypt(self):
        pk, sk = self.generate_keypair(_N_BITS)
        self.assertEqual(sk.decrypt(pk.encrypt(-1)), -1)
        self.assertEqual(sk.decrypt(pk.encrypt(0)), 0)
        self.assertEqual(sk.decrypt(pk.encrypt(1)), 1)
        self.assertEqual(sk.decrypt(pk.encrypt(12)), 12)

    def test_additive(self):
        pk, sk = self.generate_keypair(_N_BITS)
        a = pk.encrypt(42)
        b = pk.encrypt(9)

        # additions
        self.assertEqual(sk.decrypt(a + b), 51)
        self.assertEqual(sk.decrypt(a + 9), 51)
        self.assertEqual(sk.decrypt(42 + b), 51)

        # negation
        self.assertEqual(sk.decrypt(-a), -42)
        self.assertEqual(sk.decrypt(-b), -9)

        # subtraction
        self.assertEqual(sk.decrypt(a - b), 33)
        self.assertEqual(sk.decrypt(a - 9), 33)
        self.assertEqual(sk.decrypt(42 - b), 33)

        # multiplication
        self.assertEqual(sk.decrypt(a * 3), 126)
        self.assertEqual(sk.decrypt(-2 * b), -18)

        # exact division
        self.assertEqual(sk.decrypt(a / 2), 21)
        self.assertEqual(sk.decrypt(b / -3), -3)

        # exceptions
        self.assertRaises(NotImplementedError, a.__mul__, b)
        self.assertRaises(NotImplementedError, a.__truediv__, b)


class TestMock(unittest.TestCase, PartiallyHomomorphicSchemeFixture):
    generate_keypair = staticmethod(mock.generate_mock_keypair)


class TestPaillier(unittest.TestCase, PartiallyHomomorphicSchemeFixture):
    generate_keypair = staticmethod(paillier.generate_paillier_keypair)

    def test_keygen(self):
        pk, sk = self.generate_keypair(_N_BITS)

        # check p and q are actually safe primes
        self.assertGreater(sk.p, 0)
        self.assertGreater(sk.q, 0)
        self.assertTrue(util.is_prime(sk.p))
        self.assertTrue(util.is_prime(sk.q))
        self.assertTrue(util.is_prime((sk.p-1) // 2))
        self.assertTrue(util.is_prime((sk.q-1) // 2))

        # check their sizes
        self.assertEqual(sk.p.bit_length() + sk.q.bit_length(), _N_BITS)
        self.assertGreaterEqual(sk.p.bit_length(), _N_BITS // 2)
        self.assertGreaterEqual(sk.q.bit_length(), _N_BITS // 2)

        # check consistency of n, nsquare and g
        self.assertEqual(pk.n, sk.p * sk.q)
        self.assertEqual(pk.nsquare, pk.n**2)
        self.assertGreater(pk.g, 0)
        self.assertLess(pk.g, pk.nsquare)

    def test_paillier_specific(self):
        pk, sk = self.generate_keypair(_N_BITS)

        # check the ciphertexts are in ℤ_n²
        c = pk.encrypt(12)
        self.assertGreater(c.raw_value, 0)
        self.assertLess(c.raw_value, pk.nsquare)

        # adding two values under different keys
        pkk, skk = self.generate_keypair(_N_BITS)
        self.assertRaises(ValueError, pk.encrypt(1).__add__, pkk.encrypt(2))


if __name__ == '__main__':
    unittest.main()
