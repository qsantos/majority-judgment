#!/usr/bin/env python3
import util
import network
import paillier
import mpcprotocols
import majorityjudgment

_BUFFER_SIZE = 2**20


class SharedPaillierServerProtocols(mpcprotocols.MockMPCProtocols):  # TODO
    def __init__(self, pk_shares, clients):
        self.pk_shares = pk_shares
        self.clients = clients

    def decrypt_batched(self, ciphertext_batch):
        verifiers = [
            pk_share.verify_decrypt_batched(ciphertext_batch)
            for pk_share in self.pk_shares
        ]

        for verifier in verifiers:
            next(verifier)

        partial_decryption_batches = [
            client.receive_json()['partial_decryption_batch']
            for client in self.clients
        ]

        lambda_batches = [
            verifier.send(partial_decryption_batch)
            for verifier, partial_decryption_batch in zip(verifiers, partial_decryption_batches)
        ]

        for client, lambda_batch in zip(self.clients, lambda_batches):
            m = {'lambda_batch': [
                lambda_ for lambda_ in lambda_batch
            ]}
            client.send_json(m)

        left_commitments = []
        right_commitments = []
        for client in self.clients:
             m = client.receive_json()
             left_commitments.append(m['left_commitment'])
             right_commitments.append(m['right_commitment'])

        challenges = [
            verifier.send((left_commitment, right_commitment))
            for verifier, left_commitment, right_commitment in zip(verifiers, left_commitments, right_commitments)
        ]

        for client, challenge in zip(self.clients, challenges):
            client.send_json({'challenge': challenge})

        proofs = [
            client.receive_json()['proof']
            for client in self.clients
        ]

        for verifier, proof in zip(verifiers, proofs):
            try:
                verifier.send(proof)
            except StopIteration:
                pass

        partial_decryptions_batch = zip(*partial_decryption_batches)
        plaintext_batch = [
            paillier.PaillierPublicKeyShare.assemble_decryption_shares(self.pk_shares, partial_decryptions)
            for partial_decryptions in partial_decryptions_batch
        ]

        for client, challenge in zip(self.clients, challenges):
            client.send_json({'plaintext_batch': plaintext_batch})

        return plaintext_batch


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
