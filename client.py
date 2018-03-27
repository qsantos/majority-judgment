#!/usr/bin/env python3
import random

import network
import paillier
import mpcprotocols
import majorityjudgment

_BUFFER_SIZE = 2**20


class SharedPaillierClientProtocols(mpcprotocols.MockMPCProtocols):
    def __init__(self, sk_share, server):
        self.sk_share = sk_share
        self.server = server

    def decrypt_batched(self, ciphertext_batch):
        # initiate prover
        prover = self.sk_share.prove_decrypt_batched(ciphertext_batch)

        # run proof protocol with server
        output = next(prover)
        # round 1
        self.server.send_json(output)
        input = self.server.receive_json()
        output = prover.send(input)
        # round 2
        self.server.send_json(output)
        input = self.server.receive_json()
        output = prover.send(input)
        # round 3
        self.server.send_json(output)

        # receive plaintexts
        return self.server.receive_json()

    def random_negate_batched(self, x_batch, y_batch):
        pk = self.sk_share.public_key

        x_batch, y_batch = self.server.receive_json()
        x_batch = [paillier.PaillierCiphertext(pk, x) for x in x_batch]
        y_batch = [paillier.PaillierCiphertext(pk, y) for y in y_batch]

        # initiate provers
        prover_batch = [
            pk.prove_private_multiply_batched(random.choice([-1, 1]), [x, y])
            for x, y in zip(x_batch, y_batch)
        ]

        # run proof protocol with server
        output_batch = [
            next(prover)
            for prover in prover_batch
        ]
        # round 1
        self.server.send_json(output_batch)
        input_batch = self.server.receive_json()
        output_batch = [
            prover.send(input)
            for prover, input in zip(prover_batch, input_batch)
        ]
        # round 2
        self.server.send_json(output_batch)
        input_batch = self.server.receive_json()
        output_batch = [
            prover.send(input)
            for prover, input in zip(prover_batch, input_batch)
        ]
        # round 3
        self.server.send_json(output_batch)

        # receive final x_batch and y_batch
        x_batch, y_batch = self.server.receive_json()
        x_batch = [paillier.PaillierCiphertext(pk, x) for x in x_batch]
        y_batch = [paillier.PaillierCiphertext(pk, y) for y in y_batch]
        return x_batch, y_batch


def main():
    server = network.MessageSocket()
    server.connect(('localhost', 4242))
    setup = server.receive_json()

    n_choices = setup['n_choices']
    n_candidates = setup['n_candidates']
    n_bits = setup['n_bits']

    pk = paillier.PaillierPublicKey(setup['n'], setup['g'])
    pk_shares = [
        paillier.PaillierPublicKeyShare(pk, setup['verification_base'], pk_share)
        for pk_share in setup['pk_shares']
    ]
    sk_share = paillier.PaillierSecretKeyShare(pk, setup['verification_base'], setup['sk_share'])
    # TOOD: sk_share.precompute

    protocols = SharedPaillierClientProtocols(sk_share, server)
    import random
    random.seed(0)
    election = majorityjudgment.MPCMajorityJudgment(pk, protocols, n_choices, n_candidates, n_bits)
    election.precompute_randoms()

    # retrieve A
    A = server.receive_json()
    A = [
        [paillier.PaillierCiphertext(pk, x) for x in row]
        for row in A
    ]

    election.run(A)


if __name__ == '__main__':
    main()
