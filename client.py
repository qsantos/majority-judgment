#!/usr/bin/env python3
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

        output = next(prover)

        self.server.send_json(output)
        input = self.server.receive_json()
        output = prover.send(input)

        self.server.send_json(output)
        input = self.server.receive_json()
        output = prover.send(input)

        self.server.send_json(output)

        return self.server.receive_json()


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
