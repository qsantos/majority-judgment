#!/usr/bin/env python3
import random
import argparse
import datetime

import network
import paillier
import mpcprotocols
import majorityjudgment

_BUFFER_SIZE = 2**20


class HonestSharedPaillierClientProtocols(mpcprotocols.MockMPCProtocols):
    def __init__(self, sk_share, server):
        self.sk_share = sk_share
        self.server = server

    def decrypt_batched(self, ciphertext_batch):
        # compute partial decryptions
        partial_decryption_batch = [
            self.sk_share.decrypt(ciphertext)
            for ciphertext in ciphertext_batch
        ]
        self.server.send_json(partial_decryption_batch)

        # receive plaintexts
        return self.server.receive_json()

    def random_negate_batched(self, x_batch, y_batch):
        pk = self.sk_share.public_key

        n_rounds = self.server.receive_json()

        for _ in range(n_rounds):
            x_batch, y_batch = self.server.receive_json()
            for i in range(len(x_batch)):
                r = random.SystemRandom().choice([-1, 1])
                x_batch[i], _ = pk.raw_multiply(x_batch[i], r)
                y_batch[i], _ = pk.raw_multiply(y_batch[i], r)
            self.server.send_json([x_batch, y_batch])

        # receive final x_batch and y_batch
        x_batch, y_batch = self.server.receive_json()
        x_batch = [paillier.PaillierCiphertext(pk, x) for x in x_batch]
        y_batch = [paillier.PaillierCiphertext(pk, y) for y in y_batch]
        return x_batch, y_batch


class SharedPaillierClientProtocols(mpcprotocols.MockMPCProtocols):
    def __init__(self, sk_share, server):
        self.sk_share = sk_share
        self.server = server

    def decrypt_batched(self, ciphertext_batch):
        # compute partial decryptions and prove it
        partial_decryption_batch, proof = self.sk_share.prove_decrypt_batched(ciphertext_batch)
        self.server.send_json([partial_decryption_batch, proof])

        # receive plaintexts
        return self.server.receive_json()

    def random_negate_batched(self, x_batch, y_batch):
        pk = self.sk_share.public_key

        n_rounds = self.server.receive_json()

        for _ in range(n_rounds):
            x_batch, y_batch = self.server.receive_json()
            cx_cz_list_proof_batch = [
                pk.prove_private_multiply_batched(None, [x, y])
                for x, y in zip(x_batch, y_batch)
            ]
            self.server.send_json(cx_cz_list_proof_batch)

        # receive final x_batch and y_batch
        x_batch, y_batch = self.server.receive_json()
        x_batch = [paillier.PaillierCiphertext(pk, x) for x in x_batch]
        y_batch = [paillier.PaillierCiphertext(pk, y) for y in y_batch]
        return x_batch, y_batch


def main():
    parser = argparse.ArgumentParser()
    parser.description = 'Run an MPC node for majority judgment'
    parser.add_argument('host', nargs='?', default='localhost')
    parser.add_argument('port', nargs='?', default=4242, type=int)
    parser.add_argument('--honest', action='store_true')
    args = parser.parse_args()

    print('Connecting to {}:{}'.format(args.host, args.port))
    server = network.MessageSocket()
    server.connect((args.host, args.port))
    setup = server.receive_json()

    n_choices = setup['n_choices']
    n_candidates = setup['n_candidates']
    n_bits = setup['n_bits']

    # key setup
    pk = paillier.PaillierPublicKey(setup['n'], setup['g'])
    pk_shares = [
        paillier.PaillierPublicKeyShare(pk, setup['verification_base'], pk_share)
        for pk_share in setup['pk_shares']
    ]
    sk_share = paillier.PaillierSecretKeyShare(pk, setup['verification_base'], setup['sk_share'])
    if args.honest:
        protocols = HonestSharedPaillierClientProtocols(sk_share, server)
    else:
        protocols = SharedPaillierClientProtocols(sk_share, server)

        # pre-computations for proofs
        n_random_negate = (
            (n_candidates * n_choices + 2 * n_candidates) * (n_bits - 1) +  # lsbs
            ((n_choices-1)*n_candidates + n_candidates*n_candidates) * (2*n_bits-1) +  # gt_gate
            (n_choices-1) * (n_candidates-1) +  # big_and
            2*n_candidates*(n_choices-1) + 7*n_candidates*(n_candidates-1)  # and_gate
        )
        randoms = [random.choice([-1, 1]) for _ in range(n_random_negate)]
        pk.precompute_proofs(randoms)
        n_batched_decryptions = 4*n_bits + (n_candidates-1).bit_length() + 6
        sk_share.precompute_proofs(n_batched_decryptions)
        print('Pre-computations done')

    election = majorityjudgment.MPCMajorityJudgment(pk, protocols, n_choices, n_candidates, n_bits)
    election.random_bits = [
        paillier.PaillierCiphertext(pk, x)
        for x in setup['random_bits']
    ]
    election.random_ints = [
        paillier.PaillierCiphertext(pk, x)
        for x in setup['random_ints']
    ]
    server.send_json('READY')
    print('Ready to run the election')

    # retrieve A
    A = server.receive_json()
    A = [
        [paillier.PaillierCiphertext(pk, x) for x in row]
        for row in A
    ]

    # run the election
    print('Here we go!')
    start = datetime.datetime.now()
    election.run(A)
    elapsed = datetime.datetime.now() - start
    print('Finished in {}'.format(elapsed))

    if hasattr(pk, 'precomputed_values'):
        assert not pk.precomputed_values
    if hasattr(sk_share, 'precomputed_values'):
        assert not sk_share.precomputed_values


if __name__ == '__main__':
    main()
