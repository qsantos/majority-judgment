#!/usr/bin/env python3
import unittest

import util
import mock
import paillier
import mpcprotocols
import majorityjudgment

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

        # same, with raw values
        self.assertEqual(sk.decrypt(pk.encrypt(-1).raw_value), -1)
        self.assertEqual(sk.decrypt(pk.encrypt(0).raw_value), 0)
        self.assertEqual(sk.decrypt(pk.encrypt(1).raw_value), 1)
        self.assertEqual(sk.decrypt(pk.encrypt(12).raw_value), 12)

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


class TestPaillierShared(unittest.TestCase):
    def test_proof_of_knowledge(self):
        pk, pk_shares, sk_shares = paillier.generate_paillier_keypair_shares(3, _N_BITS)

        # valid proofs
        for pk_share, sk_share in zip(pk_shares, sk_shares):
            proof = sk_share.prove_knowledge()
            pk_share.verify_knowledge(proof)

        # invalid proof
        proof = sk_shares[0].prove_knowledge()
        self.assertRaises(paillier.InvalidProof, pk_shares[1].verify_knowledge, proof)

        for pk_share, sk_share in zip(pk_shares, sk_shares):
            # prepare pre-computations
            sk_share.precompute_proofs(1)

            # with pre-computations
            proof = sk_share.prove_knowledge()
            pk_share.verify_knowledge(proof)

            # not enough pre-computations
            self.assertRaises(IndexError, sk_share.prove_knowledge)

    def test_decryption(self):
        pk, pk_shares, sk_shares = paillier.generate_paillier_keypair_shares(3, _N_BITS)
        ciphertext = pk.encrypt(-42)

        partial_decryptions = [
            sk_share.decrypt(ciphertext)
            for sk_share in sk_shares
        ]
        plaintext = paillier.PaillierPublicKeyShare.assemble_decryption_shares(ciphertext, pk_shares, partial_decryptions)
        self.assertEqual(plaintext, -42)

    def test_proof_of_decryption(self):
        pk, pk_shares, sk_shares = paillier.generate_paillier_keypair_shares(3, _N_BITS)
        ciphertext = pk.encrypt(42)

        # valid decryption
        partial_decryptions = []
        for pk_share, sk_share in zip(pk_shares, sk_shares):
            partial_decryption, proof = sk_share.prove_decrypt(ciphertext)
            pk_share.verify_decrypt(ciphertext, partial_decryption, proof)
            partial_decryptions.append(partial_decryption)
        plaintext = paillier.PaillierPublicKeyShare.assemble_decryption_shares(ciphertext, pk_shares, partial_decryptions)
        self.assertEqual(plaintext, 42)

        # invalid decryption
        partial_decryption, proof = sk_shares[0].prove_decrypt(ciphertext)
        self.assertRaises(paillier.InvalidProof, pk_shares[1].verify_decrypt, ciphertext, partial_decryption, proof)

        # prepare pre-computations
        for sk_share in sk_shares:
            sk_share.precompute_proofs(1)

        # with pre-computations
        partial_decryptions = []
        for pk_share, sk_share in zip(pk_shares, sk_shares):
            partial_decryption, proof = sk_share.prove_decrypt(ciphertext)
            pk_share.verify_decrypt(ciphertext, partial_decryption, proof)
            partial_decryptions.append(partial_decryption)
        plaintext = paillier.PaillierPublicKeyShare.assemble_decryption_shares(ciphertext, pk_shares, partial_decryptions)
        self.assertEqual(plaintext, 42)

        # not enough pre-computations
        for pk_share, sk_share in zip(pk_shares, sk_shares):
            self.assertRaises(IndexError, sk_share.prove_decrypt, ciphertext)

    def test_proof_of_decryption_batched(self):
        pk, pk_shares, sk_shares = paillier.generate_paillier_keypair_shares(3, _N_BITS)
        ciphertext_batch = [pk.encrypt(i) for i in range(100)]

        # valid decryptions
        partial_decryption_batches = []
        for pk_share, sk_share in zip(pk_shares, sk_shares):
            partial_decryption_batch, proof = sk_share.prove_decrypt_batched(ciphertext_batch)
            pk_share.verify_decrypt_batched(ciphertext_batch, partial_decryption_batch, proof)
            partial_decryption_batches.append(partial_decryption_batch)
        partial_decryptions_batch = zip(*partial_decryption_batches)
        for i, (ciphertext, partial_decryptions) in enumerate(zip(ciphertext_batch, partial_decryptions_batch)):
            plaintext = paillier.PaillierPublicKeyShare.assemble_decryption_shares(ciphertext, pk_shares, partial_decryptions)
            self.assertEqual(plaintext, i)

        # invalid decryptions
        partial_decryption_batch, proof = sk_shares[0].prove_decrypt_batched(ciphertext_batch)
        self.assertRaises(paillier.InvalidProof, pk_shares[1].verify_decrypt_batched, ciphertext_batch, partial_decryption_batch, proof)

        # prepare pre-computations
        for sk_share in sk_shares:
            sk_share.precompute_proofs(1)

        # with pre-computations
        partial_decryption_batches = []
        for pk_share, sk_share in zip(pk_shares, sk_shares):
            partial_decryption_batch, proof = sk_share.prove_decrypt_batched(ciphertext_batch)
            pk_share.verify_decrypt_batched(ciphertext_batch, partial_decryption_batch, proof)
            partial_decryption_batches.append(partial_decryption_batch)
        partial_decryptions_batch = zip(*partial_decryption_batches)
        for i, (ciphertext, partial_decryptions) in enumerate(zip(ciphertext_batch, partial_decryptions_batch)):
            plaintext = paillier.PaillierPublicKeyShare.assemble_decryption_shares(ciphertext, pk_shares, partial_decryptions)
            self.assertEqual(plaintext, i)

        # not enough pre-computations
        for pk_share, sk_share in zip(pk_shares, sk_shares):
            self.assertRaises(IndexError, sk_share.prove_decrypt_batched, ciphertext_batch)

    def test_private_multiply(self):
        pk, sk = paillier.generate_paillier_keypair(_N_BITS)
        x, y = -2, 42
        cy = pk.encrypt(y).raw_value

        # valid multiplication
        cx, cz, proof = pk.prove_private_multiply(x, cy)
        pk.verify_private_multiply(cx, cy, cz, proof)
        self.assertEqual(sk.decrypt(cx), x)
        self.assertEqual(sk.decrypt(cz), x*y)

        # invalid multiplication
        fake_cy = pk.encrypt(y + 1).raw_value
        cx, cz, proof = pk.prove_private_multiply(x, fake_cy)
        self.assertRaises(paillier.InvalidProof, pk.verify_private_multiply, cx, cy, cz, proof)

        # prepare pre-computations
        pk.precompute_proofs([x, x+1])

        # with pre-computations
        cx, cz, proof = pk.prove_private_multiply(x, cy)
        pk.verify_private_multiply(cx, cy, cz, proof)
        self.assertEqual(sk.decrypt(cx), x)
        self.assertEqual(sk.decrypt(cz), x*y)

        # invalid pre-computations
        self.assertRaises(ValueError, pk.prove_private_multiply, x, cy)

        # no enough pre-computations
        self.assertRaises(IndexError, pk.prove_private_multiply, x, cy)

    def test_private_multiply_batched(self):
        pk, sk = paillier.generate_paillier_keypair(_N_BITS)
        x, y_list = -2, [42, -10]
        cy_list = [pk.encrypt(y).raw_value for y in y_list]

        # valid multiplications
        cx, cz_list, proof = pk.prove_private_multiply_batched(x, cy_list)
        pk.verify_private_multiply_batched(cx, cy_list, cz_list, proof)
        for y, cz in zip(y_list, cz_list):
            self.assertEqual(sk.decrypt(cx), x)
            self.assertEqual(sk.decrypt(cz), x*y)

        # invalid multiplications
        fake_cy_list = [cy + 1 for cy in cy_list]
        cx, cz_list, proof = pk.prove_private_multiply_batched(x, fake_cy_list)
        self.assertRaises(paillier.InvalidProof, pk.verify_private_multiply_batched, cx, cy_list, cz_list, proof)

        # prepare pre-computations
        pk.precompute_proofs([x, x+1])

        # with pre-computations
        cx, cz_list, proof = pk.prove_private_multiply_batched(x, cy_list)
        pk.verify_private_multiply_batched(cx, cy_list, cz_list, proof)
        for y, cz in zip(y_list, cz_list):
            self.assertEqual(sk.decrypt(cx), x)
            self.assertEqual(sk.decrypt(cz), x*y)

        # invalid pre-computations
        self.assertRaises(ValueError, pk.prove_private_multiply_batched, x, cy_list)

        # no enough pre-computations
        self.assertRaises(IndexError, pk.prove_private_multiply_batched, x, cy_list)


class MajorityJudgmentFixture:
    def test_obvious(self):
        self.assertEqual(0, self.run_election([
            [1, 0],
            [0, 1],
        ]))
        self.assertEqual(1, self.run_election([
            [0, 1],
            [1, 0],
        ]))

    def test_examples(self):
        # from <https://en.wikipedia.org/wiki/Majority_Judgment>
        self.assertEqual(1, self.run_election([
            [42, 0, 0, 58],  # Menphis
            [26, 0, 74, 0],  # Nashville (winner)
            [15, 17, 26, 42],  # Chattanooga
            [17, 15, 26, 52],  # Knoxville
        ]))
        # from <https://fr.wikipedia.org/wiki/Jugement_majoritaire>
        # in basis points
        self.assertEqual(0, self.run_election([
            [1742, 2128, 1971, 912, 1763, 1484],  # candidate A
            [1705, 2073, 1295, 1342, 1158, 2427],  # candidate B
        ]))
        # from Election by Majority Judgement: Experimental Evidence, p17
        # in per mille
        self.assertEqual(3, self.run_election([
            [41, 99, 163, 160, 226, 311],  # Besancenot
            [25, 76, 125, 206, 264, 304],  # Buffet
            [5, 10, 39, 95, 249, 604],  # Schivardi
            [136, 307, 251, 148, 84, 74],  # Bayrou (winner)
            [15, 60, 114, 160, 257, 395],  # Bové
            [29, 93, 175, 237, 261, 205],  # Voynet
            [24, 64, 87, 113, 158, 555],  # Villiers
            [167, 227, 191, 168, 122, 126],  # Royal
            [3, 18, 53, 110, 267, 550],  # Nihous
            [30, 46, 62, 65, 54, 744],  # Le Pen
            [21, 53, 102, 166, 259, 401],  # Laguiller
            [191, 198, 143, 115, 71, 282],  # Sarokzy
        ]))


class TestClearMajorityJudgment(unittest.TestCase, MajorityJudgmentFixture):
    run_election = staticmethod(majorityjudgment.clear_majority_judgment)


class TestPaillierMajorityJudgment(unittest.TestCase, MajorityJudgmentFixture):
    @staticmethod
    def run_election(A):
        pk, sk = mock.generate_mock_keypair()

        # prepare election
        n_candidates = len(A)
        n_choices = len(A[0])
        n_bits = max(x for row in A for x in row).bit_length() + 1
        protocols = mpcprotocols.MockMPCProtocols(sk)
        election = majorityjudgment.MPCMajorityJudgment(pk, protocols, n_choices, n_candidates, n_bits)
        election.precompute_randoms()

        # encrypt the ballots
        A = [[election.pk.encrypt(value) for value in row] for row in A]

        return election.run(A)


if __name__ == '__main__':
    unittest.main()
