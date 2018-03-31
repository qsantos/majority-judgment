#!/usr/bin/env python3
import json
import argparse
import datetime

import util
import network
import paillier
import mpcprotocols
import majorityjudgment

_BUFFER_SIZE = 2**20


class HonestSharedPaillierServerProtocols(mpcprotocols.MockMPCProtocols):
    def __init__(self, pk_shares, clients):
        self.pk_shares = pk_shares
        self.clients = clients

    def decrypt_batched(self, ciphertext_batch):
        # collect partial decryptions
        partial_decryption_batches = [
            client.receive_json()
            for client in self.clients
        ]

        # assemble plaintexts
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

        x_batch = [x.raw_value for x in x_batch]
        y_batch = [y.raw_value for y in y_batch]

        assert len(x_batch) == len(y_batch)

        stride = (len(x_batch)-1) // len(self.pk_shares) + 1
        n_rounds = (len(x_batch)-1) // stride + 1

        for client in self.clients:
            client.send_json(n_rounds)

        for offset in range(0, len(x_batch), stride):
            # split into subbatches for pipelining
            for i, client in enumerate(self.clients):
                start = offset+stride*i
                stop = offset+stride*(i+1)
                x_subbatch = list(util.slice_warp(x_batch, start, stop))
                y_subbatch = list(util.slice_warp(y_batch, start, stop))

                # transmit x_batch and y_batch to next client
                client.send_json([x_subbatch, y_subbatch])

            # collect randomly negated values and verify proofs
            for i, client in enumerate(self.clients):
                x_subbatch, y_subbatch = client.receive_json()
                for j, (x, y) in enumerate(zip(x_subbatch, y_subbatch)):
                    # update x_batch and y_batch
                    index = (offset+stride*i+j) % len(x_batch)
                    x_batch[index], y_batch[index] = x, y

        # broadcast final value of x_batch and y_batch
        for client in self.clients:
            client.send_json([x_batch, y_batch])

        # done
        x_batch = [paillier.PaillierCiphertext(pk, x) for x in x_batch]
        y_batch = [paillier.PaillierCiphertext(pk, y) for y in y_batch]
        return x_batch, y_batch


class SharedPaillierServerProtocols(mpcprotocols.MockMPCProtocols):
    def __init__(self, pk_shares, clients):
        self.pk_shares = pk_shares
        self.clients = clients

    def decrypt_batched(self, ciphertext_batch):
        # collect partial decryptions and verify proofs
        partial_decryption_batches = []
        for pk_share, client in zip(self.pk_shares, self.clients):
            partial_decryption_batch, proof = client.receive_json()
            pk_share.verify_decrypt_batched(ciphertext_batch, partial_decryption_batch, proof)
            partial_decryption_batches.append(partial_decryption_batch)

        # assemble plaintexts
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

        x_batch = [x.raw_value for x in x_batch]
        y_batch = [y.raw_value for y in y_batch]

        assert len(x_batch) == len(y_batch)

        stride = (len(x_batch)-1) // len(self.pk_shares) + 1
        n_rounds = (len(x_batch)-1) // stride + 1

        for client in self.clients:
            client.send_json(n_rounds)

        for offset in range(0, len(x_batch), stride):
            # split into subbatches for pipelining
            cy_list_batches = []
            for i, client in enumerate(self.clients):
                start = offset+stride*i
                stop = offset+stride*(i+1)
                x_subbatch = list(util.slice_warp(x_batch, start, stop))
                y_subbatch = list(util.slice_warp(y_batch, start, stop))

                # transmit x_batch and y_batch to next client
                client.send_json([x_subbatch, y_subbatch])
                cy_list_batch = list(zip(x_subbatch, y_subbatch))
                cy_list_batches.append(cy_list_batch)

            # collect randomly negated values and verify proofs
            for i, (client, cy_list_batch) in enumerate(zip(self.clients, cy_list_batches)):
                cx_cz_list_proof_batch = client.receive_json()
                for j, (cy_list, (cx, cz_list, proof)) in enumerate(zip(cy_list_batch, cx_cz_list_proof_batch)):
                    pk.verify_private_multiply_batched(cx, cy_list, cz_list, proof)

                    # update x_batch and y_batch
                    index = (offset+stride*i+j) % len(x_batch)
                    x_batch[index], y_batch[index] = cz_list

        # broadcast final value of x_batch and y_batch
        for client in self.clients:
            client.send_json([x_batch, y_batch])

        # done
        x_batch = [paillier.PaillierCiphertext(pk, x) for x in x_batch]
        y_batch = [paillier.PaillierCiphertext(pk, y) for y in y_batch]
        return x_batch, y_batch


def main():
    parser = argparse.ArgumentParser()
    parser.description = 'Run an MPC coordinator for majority judgment'
    parser.add_argument('parties', type=int)
    parser.add_argument('--choices', '-n', default=5, type=int)
    parser.add_argument('--candidates', '-m', default=3, type=int)
    parser.add_argument('--bits', '-l', default=11, type=int)
    parser.add_argument('--honest', action='store_true')
    args = parser.parse_args()

    # generate the ballots
    clear_A = [
        util.random_numbers_totaling(2**args.bits // 2 - 1, args.choices)
        for _ in range(args.candidates)
    ]

    # wait for all parties to connect
    print('Waiting for clients to connect')
    listener = network.MessageSocket()
    listener.listen(('', 4242))
    clients = []
    for _ in range(args.parties):
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
    pk_shares, sk_shares = paillier.share_paillier_keypair(pk, sk, args.parties)

    # setup
    if args.honest:
        protocols = HonestSharedPaillierServerProtocols(pk_shares, clients)
    else:
        protocols = SharedPaillierServerProtocols(pk_shares, clients)
    election = majorityjudgment.MPCMajorityJudgment(pk, protocols, args.choices, args.candidates, args.bits)
    election.precompute_randoms()

    # broadcast setup to parties
    print('Distributing keys')
    setup = {
        'n_choices': args.choices,
        'n_candidates': args.candidates,
        'n_bits': args.bits,
        'n': pk.n,
        'g': pk.g,
        'verification_base': sk_shares[0].verification_base,
        'pk_shares': [sk_share.key_share for sk_share in sk_shares],
        'random_bits': [x.raw_value for x in election.random_bits],
        'random_ints': [x.raw_value for x in election.random_ints],
    }
    for client, sk_share in zip(clients, sk_shares):
        setup['sk_share'] = sk_share.key_share
        client.send_json(setup)

    # wait for the clients to be ready
    print('Waiting for clients to be ready')
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
    print('Election started')
    start = datetime.datetime.now()
    winner = election.run(A)
    elapsed = datetime.datetime.now() - start
    print('Finished in {}'.format(elapsed))
    print(winner)
    assert winner == majorityjudgment.clear_majority_judgment(clear_A)


if __name__ == '__main__':
    main()
