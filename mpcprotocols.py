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

        decryption_share_batches = [
            util.run_protocol(
                sk_share.prove_decrypt_batched(ciphertext_batch),
                pk_share.verify_decrypt_batched(ciphertext_batch),
            )
            for pk_share, sk_share in zip(self.pk_shares, self.sk_shares)
        ]

        decryption_shares_batch = zip(*decryption_share_batches)
        return [
            paillier.PaillierPublicKeyShare.assemble_decryption_shares(self.pk_shares, decryption_shares)
            for decryption_shares in decryption_shares_batch
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
        pk = self.pk_shares[0].public_key

        for _ in self.pk_shares:
            r_batch = [random.choice([-1, 1]) for _ in x_batch]

            rx_batch = []
            for r, x in zip(r_batch, x_batch):
                _, x = util.run_protocol(
                    pk.prove_private_multiply(r, x),
                    pk.verify_private_multiply(x),
                )
                rx_batch.append(x)

            ry_batch = []
            for r, y in zip(r_batch, y_batch):
                _, y = util.run_protocol(
                    pk.prove_private_multiply(r, y),
                    pk.verify_private_multiply(y),
                )
                ry_batch.append(y)

            x_batch, y_batch = rx_batch, ry_batch

        return x_batch, y_batch
