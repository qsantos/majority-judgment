#!/usr/bin/env python3
import math
import json
import random
import argparse
import datetime

import util
import mock
import ballot
import paillier
import mpcprotocols
import majorityjudgment


def run_test(seed, pk, protocols, n_choices, n_candidates, n_bits):
    random.seed(seed)

    # generate the ballots
    clear_A = [
        util.random_numbers_totaling(2**n_bits // 2 - 1, n_choices)
        for _ in range(n_candidates)
    ]
    if debug_level >= 2:
        print('A =', clear_A)
    # for simplicity, we assume that the aggregate matrix is already normalized
    assert all(sum(clear_A[0]) == sum(row) for row in clear_A)

    # clear protocol
    if debug_level >= 2:
        print('Running majority judgment in the clear')
    clear_winner = majorityjudgment.clear_majority_judgment(clear_A)
    if debug_level >= 1:
        print('Clear protocol winner is', clear_winner)

    election = majorityjudgment.MPCMajorityJudgment(
        pk, protocols, n_choices, n_candidates, n_bits
    )
    election.precompute_randoms()

    # encrypt the ballots
    A = [[election.pk.encrypt(value) for value in row] for row in clear_A]

    # encrypted protocol
    if debug_level >= 2:
        print('Running majority judgment encrypted')
    start = datetime.datetime.now()
    winner = election.run(A)
    elapsed = datetime.datetime.now() - start
    if debug_level >= 1:
        print('Encrypted protocol winner is', winner)
        print('Finished in {}'.format(elapsed))

    # show number of calls to oracle
    if debug_level >= 1:
        print('{} decrypt (depth: {})'.format(
            protocols.n_decrypt, protocols.d_decrypt)
        )

    assert winner == clear_winner

    # check that pre-computation were forecast acurately
    try:
        assert not pk.precomputed_values
        for sk_share in protocols.sk_shares:
            assert not sk_share.precomputed_values
    except AttributeError:
        pass


def load_keypair(args):
    if args.parties < 0:
        pk, sk = mock.generate_mock_keypair()
        protocols = mpcprotocols.MockMPCProtocols(sk)
        return pk, protocols

    # load cached keys or generate new ones
    try:
        with open('key.cache') as f:
            data = json.load(f)
    except (FileNotFoundError, json.decoder.JSONDecodeError):
        # generate the keys
        pk, sk = paillier.generate_paillier_keypair()
        # cache them
        with open('key.cache', 'w') as f:
            json.dump({'p': sk.p, 'q': sk.q, 'g': pk.g}, f)
        print('Key generated')
    else:
        sk = paillier.PaillierSecretKey(data['p'], data['q'], data['g'])
        pk = sk.public_key
        print('Keys loaded')

    if args.parties == 0:
        # no key sharing
        return pk, mpcprotocols.MockMPCProtocols(sk)

    # prepare key sharing
    pk_shares, sk_shares = paillier.share_paillier_keypair(pk, sk, args.parties)

    # pre-computations for proofs
    n_random_negate = args.parties * (
        (args.candidates * args.choices + 2 * args.candidates) * (args.bits - 1) +  # lsbs
        ((args.choices-1)*args.candidates + args.candidates*args.candidates) * (2*args.bits-1) +  # gt_gate
        (args.choices-1) * (args.candidates-1) +  # big_and
        2*args.candidates*(args.choices-1) + 7*args.candidates*(args.candidates-1)  # and_gate
    )
    randoms = [random.choice([-1, 1]) for _ in range(n_random_negate)]
    pk.precompute_proofs(randoms)
    n_batched_decryptions = 4*args.bits + (args.candidates-1).bit_length() + 6
    for sk_share in sk_shares:
        sk_share.precompute_proofs(n_batched_decryptions)
    print('Pre-computations done')

    return pk, mpcprotocols.SharedMockMPCProtocols(pk_shares, sk_shares)


def main():
    parser = argparse.ArgumentParser()
    parser.description = 'Majority judgment protocol with Paillier encryption'
    parser.add_argument('--debug', '-d', default=1, type=int)
    parser.add_argument('--parties', default=0, type=int)
    parser.add_argument('--choices', '-n', default=5, type=int)
    parser.add_argument('--candidates', '-m', default=3, type=int)
    parser.add_argument('--bits', '-l', default=11, type=int)
    parser.add_argument('--simulations', default=1, type=int)
    parser.add_argument('--ballots', default=0, type=int)
    parser.add_argument('seed', default=0, type=int, nargs='?')
    args = parser.parse_args()

    global debug_level
    debug_level = args.debug

    pk, protocols = load_keypair(args)

    for _ in range(args.ballots):
        ballot.prepare_ballot(pk, args.choices, args.candidates)

    max_simulations = args.simulations if args.simulations >= 0 else float('inf')
    seed = args.seed
    simulated = 0
    while simulated < max_simulations:
        print('Seed: {}'.format(seed))
        run_test(seed, pk, protocols, args.choices, args.candidates, args.bits)
        seed += 1
        simulated += 1


if __name__ == '__main__':
    main()
