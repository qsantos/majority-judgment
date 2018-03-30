#!/usr/bin/env python3
import json
import datetime

import util
import network
import paillier
import mpcprotocols
import majorityjudgment

_BUFFER_SIZE = 2**20


class SharedPaillierServerProtocols(mpcprotocols.MockMPCProtocols):
    def __init__(self, pk_shares, clients):
        self.pk_shares = pk_shares
        self.clients = clients

    def decrypt_batched(self, ciphertext_batch):
        # initiate verifiers
        verifiers = [
            pk_share.verify_decrypt_batched(ciphertext_batch)
            for pk_share in self.pk_shares
        ]

        # run proof protocol (TODO: non fixed number of rounds)
        for verifier in verifiers:
            next(verifier)
        for verifier, client in zip(verifiers, self.clients):
            client.send_json(verifier.send(client.receive_json()))
        for verifier, client in zip(verifiers, self.clients):
            client.send_json(verifier.send(client.receive_json()))
        results = []
        for verifier, client in zip(verifiers, self.clients):
            try:
                verifier.send(client.receive_json())
            except StopIteration as e:
                results.append(e.value)

        # assemble plaintexts
        partial_decryption_batches = results
        partial_decryptions_batch = zip(*partial_decryption_batches)
        plaintext_batch = [
            paillier.PaillierPublicKeyShare.assemble_decryption_shares(self.pk_shares, partial_decryptions)
            for partial_decryptions in partial_decryptions_batch
        ]

        # broadcast plaintexts
        for client in self.clients:
            client.send_json(plaintext_batch)

        # done
        return plaintext_batch

    def random_negate_batched(self, x_batch, y_batch):
        pk = self.pk_shares[0].public_key

        x_batch = list(x_batch)
        y_batch = list(y_batch)

        assert len(x_batch) == len(y_batch)

        stride = (len(x_batch)-1) // len(self.pk_shares) + 1
        n_rounds = (len(x_batch)-1) // stride + 1

        for client in self.clients:
            client.send_json(n_rounds)

        for offset in range(0, len(x_batch), stride):
            n_rounds -= 1
            verifier_subbatches = []
            for i, client in enumerate(self.clients):
                start = offset+stride*i
                stop = offset+stride*(i+1)
                x_subbatch = list(util.slice_warp(x_batch, start, stop))
                y_subbatch = list(util.slice_warp(y_batch, start, stop))

                # transmit x_batch and y_batch to next client
                x_raw_subbatch = [x.raw_value for x in x_subbatch]
                y_raw_subbatch = [y.raw_value for y in y_subbatch]
                client.send_json([x_raw_subbatch, y_raw_subbatch])

                # initiate verifiers
                verifier_subbatch = [
                    pk.verify_private_multiply_batched([x, y])
                    for x, y in zip(x_subbatch, y_subbatch)
                ]
                verifier_subbatches.append(verifier_subbatch)

                for verifier in verifier_subbatch:
                    next(verifier)

            assert len(verifier_subbatches) == len(self.clients)

            # run proof protocol (TODO: non fixed number of rounds)
            # round 1
            for client, verifier_subbatch in zip(self.clients, verifier_subbatches):
                input_batch = client.receive_json()
                output_batch = [
                    verifier.send(input)
                    for verifier, input in zip(verifier_subbatch, input_batch)
                ]
                client.send_json(output_batch)

            # round 2
            for client, verifier_subbatch in zip(self.clients, verifier_subbatches):
                input_batch = client.receive_json()
                output_batch = [
                    verifier.send(input)
                    for verifier, input in zip(verifier_subbatch, input_batch)
                ]
                client.send_json(output_batch)

            # round 3
            for i, (client, verifier_subbatch) in enumerate(zip(self.clients, verifier_subbatches)):
                input_batch = client.receive_json()
                for j, (verifier, input) in enumerate(zip(verifier_subbatch, input_batch)):
                    try:
                        verifier.send(input)
                    except StopIteration as e:
                        x, y = e.value[1]
                        # update x_batch and y_batch
                        index = (offset+stride*i+j) % len(x_batch)
                        x_batch[index] = x
                        y_batch[index] = y

        assert n_rounds == 0

        # broadcast final value of x_batch and y_batch
        x_batch_raw = [x.raw_value for x in x_batch]
        y_batch_raw = [y.raw_value for y in y_batch]
        for client in self.clients:
            client.send_json([x_batch_raw, y_batch_raw])

        # done
        return x_batch, y_batch


def main():
    n_choices = 5
    n_candidates = 3
    n_bits = 27
    n_parties = 3

    # generate the ballots
    clear_A = [
        util.random_numbers_totaling(2**n_bits // 2 - 1, n_choices)
        for _ in range(n_candidates)
    ]

    # wait for all parties to connect
    listener = network.MessageSocket()
    listener.listen(('', 4242))
    clients = []
    for _ in range(n_parties):
        client, addr = listener.accept()
        clients.append(client)

    # load cached keys or generate new ones
    try:
        with open('key.cache') as f:
            data = json.load(f)
    except (FileNotFoundError, json.decoder.JSONDecodeError):
        print('Generating keys')
        pk, sk = paillier.generate_paillier_keypair()
        # cache them
        with open('key.cache', 'w') as f:
            json.dump({'p': sk.p, 'q': sk.q, 'g': pk.g}, f)
        print('Key generated')
    else:
        sk = paillier.PaillierSecretKey(data['p'], data['q'], data['g'])
        pk = sk.public_key
        print('Keys loaded')

    # share keypair
    pk_shares, sk_shares = paillier.share_paillier_keypair(pk, sk, n_parties)

    # setup
    protocols = SharedPaillierServerProtocols(pk_shares, clients)
    election = majorityjudgment.MPCMajorityJudgment(pk, protocols, n_choices, n_candidates, n_bits)
    election.precompute_randoms()
    setup = {
        'n_choices': n_choices,
        'n_candidates': n_candidates,
        'n_bits': n_bits,
        'n': pk.n,
        'g': pk.g,
        'verification_base': sk_shares[0].verification_base,
        'pk_shares': [sk_share.key_share for sk_share in sk_shares],
        'random_bits': [x.raw_value for x in election.random_bits],
        'random_ints': [x.raw_value for x in election.random_ints],
    }

    # broadcast setup to parties
    for client, sk_share in zip(clients, sk_shares):
        setup['sk_share'] = sk_share.key_share
        client.send_json(setup)

    # wait for the clients to be ready
    for client, sk_share in zip(clients, sk_shares):
        assert client.receive_json() == 'READY'

    # broadcast A
    A = [[election.pk.encrypt(value) for value in row] for row in clear_A]
    raw_A = [
        [x.raw_value for x in row]
        for row in A
    ]
    for client in clients:
        client.send_json(raw_A)

    # run the election
    start = datetime.datetime.now()
    winner = election.run(A)
    elapsed = datetime.datetime.now() - start
    print('Finished in {}'.format(elapsed))
    print(winner)
    assert winner == majorityjudgment.clear_majority_judgment(clear_A)


if __name__ == '__main__':
    main()
