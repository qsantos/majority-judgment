#!/usr/bin/env python
"""MultiParty Computation Protocols

Implement protocols involving several parties coordinating to compute the
result of a basic operation. These protocols can be directly used in programs
(e.g. the decrypt gate is used to reveal the final result of the program for
the majority judgment), or in gates, which are building blocks of intermediate
complexity (e.g. the random negate protocol is used in the conditional gate)

Currently, two protocols are offered (in batched version):
    decrypt: collectively compute the plaintext corresponding to a ciphertext
    random_negate: either negate two values or leave them alone (but randomize)
"""
import util
import random

import paillier


class MockMPCProtocols:
    """Mock a MPC protocol over a single node with simple keys"""
    def __init__(self, sk):
        """Constructor

        Arguments:
            sk (paillier.PaillierSecretKey): the secret key held by the party
        """
        self.sk = sk
        self.n_decrypt = 0
        self.d_decrypt = 0

    def decrypt_batched(self, ciphertext_batch):
        """Decrypt protocol

        Arguments:
            ciphertext_batch (list): the ciphertexts
                (paillier.PaillierCiphertext) to decrypt

        returns:
            list: the plaintexts (int) corresponding to the given ciphertexts
        """
        self.n_decrypt += len(ciphertext_batch)
        self.d_decrypt += 1
        return [self.sk.decrypt(x) for x in ciphertext_batch]

    def random_negate_batched(self, x_batch, y_batch):
        """Random negate protocol

        Arguments:
            x_batch (list): the left values (paillier.PaillierCiphertext) to randomly negate
            y_batch (list): the right values (paillier.PaillierCiphertext) to randomly negate

        Returns:
            tuple: a pair of two lists, x_batch and y_batch, where each (x, y)
            pair (from `zip(x_batch, y_batch)`) is two Paillier ciphertexts
            encrypting either the same values as the corresponding inputs, or
            their negation
        """
        r_batch = [random.choice([-1, 1]) for _ in x_batch]
        x_batch = [x*r for x, r in zip(x_batch, r_batch)]
        y_batch = [y*r for y, r in zip(y_batch, r_batch)]
        return x_batch, y_batch


class SharedMockMPCProtocols(MockMPCProtocols):
    """Mock a MPC protocol over a single node with shared keys"""
    def __init__(self, pk_shares, sk_shares):
        """Constructor

        Arguments:
            pk_shares (list): elements are paillier.PaillierPublicKeyShare
            sk_shares (list): elements are paillier.PaillierSecretKeyShare
        """
        self.pk_shares = pk_shares
        self.sk_shares = sk_shares

        self.n_decrypt = 0
        self.d_decrypt = 0

    def decrypt_batched(self, ciphertext_batch):
        """Decrypt protocol

        Arguments:
            ciphertext_batch (list): the ciphertexts
                (paillier.PaillierCiphertext) to decrypt

        returns:
            list: the plaintexts (int) corresponding to the given ciphertexts
        """
        self.n_decrypt += len(ciphertext_batch)
        self.d_decrypt += 1

        partial_decryption_batches = []
        for pk_share, sk_share in zip(self.pk_shares, self.sk_shares):
            partial_decryption_batch, proof = sk_share.prove_decrypt_batched(ciphertext_batch)
            pk_share.verify_decrypt_batched(ciphertext_batch, partial_decryption_batch, proof)
            partial_decryption_batches.append(partial_decryption_batch)
        partial_decryptions_batch = zip(*partial_decryption_batches)

        return [
            paillier.PaillierPublicKeyShare.assemble_decryption_shares(self.pk_shares, partial_decryptions)
            for partial_decryptions in partial_decryptions_batch
        ]

    def random_negate_batched(self, x_batch, y_batch):
        """Random negate protocol

        Arguments:
            x_batch (list): the left values (paillier.PaillierCiphertext) to randomly negate
            y_batch (list): the right values (paillier.PaillierCiphertext) to randomly negate

        Returns:
            tuple: a pair of two lists, x_batch and y_batch, where each (x, y)
            pair (from `zip(x_batch, y_batch)`) is two Paillier ciphertexts
            encrypting either the same values as the corresponding inputs, or
            their negation
        """
        assert len(x_batch) == len(y_batch)
        pk = self.pk_shares[0].public_key
        x_batch = [x.raw_value for x in x_batch]
        y_batch = [y.raw_value for y in y_batch]

        for _ in self.pk_shares:
            for i in range(len(x_batch)):
                cy_list = x_batch[i], y_batch[i]
                cx, cz_list, proof = pk.prove_private_multiply_batched(None, cy_list)
                pk.verify_private_multiply_batched(cx, cy_list, cz_list, proof)
                x_batch[i], y_batch[i] = cz_list

        x_batch = [paillier.PaillierCiphertext(pk, x) for x in x_batch]
        y_batch = [paillier.PaillierCiphertext(pk, y) for y in y_batch]
        return x_batch, y_batch
