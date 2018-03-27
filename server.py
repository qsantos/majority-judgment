#!/usr/bin/env python3
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

        for client in self.clients:
            # transmit x_batch and y_batch to next client
            x_batch_raw = [x.raw_value for x in x_batch]
            y_batch_raw = [y.raw_value for y in y_batch]
            client.send_json([x_batch_raw, y_batch_raw])

            # initiate verifiers
            verifier_batch = [
                pk.verify_private_multiply_batched([x, y])
                for x, y in zip(x_batch, y_batch)
            ]

            # run proof protocol (TODO: non fixed number of rounds)
            for verifier in verifier_batch:
                next(verifier)
            # round 1
            input_batch = client.receive_json()
            output_batch = [
                verifier.send(input)
                for verifier, input in zip(verifier_batch, input_batch)
            ]
            client.send_json(output_batch)
            # round 2
            input_batch = client.receive_json()
            output_batch = [
                verifier.send(input)
                for verifier, input in zip(verifier_batch, input_batch)
            ]
            client.send_json(output_batch)
            # round 3
            results = []
            input_batch = client.receive_json()
            for verifier, input in zip(verifier_batch, input_batch):
                try:
                    verifier.send(input)
                except StopIteration as e:
                    results.append(e.value[1])

            # update x_batch and y_batch
            x_y_batch = results
            x_batch = [x for x, y in x_y_batch]
            y_batch = [y for x, y in x_y_batch]

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

    # setup
    pk, pk_shares, sk_shares = paillier.generate_paillier_keypair_shares(n_parties, safe_primes=False)
    import random
    random.seed(0)
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
    }

    # broadcast setup to parties
    for client, sk_share in zip(clients, sk_shares):
        setup['sk_share'] = sk_share.key_share
        client.send_json(setup)

    # encrypt the ballots
    A = [[election.pk.encrypt(value) for value in row] for row in clear_A]

    # broadcast A
    raw_A = [
        [x.raw_value for x in row]
        for row in A
    ]
    for client in clients:
        client.send_json(raw_A)

    winner = election.run(A)
    print(winner)
    assert winner == majorityjudgment.clear_majority_judgment(clear_A)


if __name__ == '__main__':
    main()
