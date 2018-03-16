#!/usr/bin/env python3
"""Majority judgment using Paillier encryption

LSBs and the conditional gates are partially implemented: the interaction
between the parties is simulated by generating all values locally

LSBs requires the input to be Paillier encryptions (cannot be adapted to El
Gamal or BGN). However, the output of the last LSBs can be El Gamal or BGN
encryption, so that the last conditional gates could be replaced by offline
pairings.

Depends on `gmpy2`
"""
import math
import time
import json
import random
import argparse

import util
import mock
import paillier
import mpcgates
import mpcprotocols

# debug_level = 0: quiet
# debug_level = 1: normal output
# debug_level = 2: some intermediate values
# debug_level = 3: detailed intermediate values
debug_level = 1


class MPCMajorityJudgment(mpcgates.MPCGates):
    """Majority Judgment in the context of MultiParty Computation

    The main method of this class is `run()`. Due to the high complexity of the
    prococol, the code is split into several methods named `compute_*()`.

    Building blocks can be found in the `mpcprotocols` (operations directly
    involving the parties) and `mpcgates` (building blocks built above the
    protocols, and which abstract away the notion of parties) modules.

    To minimize the number of interaction (circuit depth), these operations are
    batched (hence the name). For instance, each call to a `and_gate_batched()`
    computes several logical and in parallel. In general `*_batch` variables
    represent values that are batched togather for concurrent handling.

    Other methods are:
        * `debug_decrypt()`: decrypt a value (only for debugging!)
        * `debug()`: show name and value of an attribute for easy debugging
    """
    def __init__(self, pk, protocols, n_choices, n_candidates, n_bits):
        super().__init__(protocols)

        self.n_choices = n_choices
        self.n_candidates = n_candidates
        self.n_bits = n_bits

        self.pk = pk

        self.ZERO = pk.encrypt(0, randomize=False)
        self.ONE = pk.encrypt(1, randomize=False)

    def debug_decrypt(self, x):
        """Debug helper: recursively decrypt values"""
        if x is None:
            return None
        try:
            x = iter(x)
        except TypeError:
            if not isinstance(x, mock.MockPaillierCiphertext):
                raise NotImplementedError
            return x.raw_value
        else:
            return [self.debug_decrypt(value) for value in x]

    def debug(self, level, name, value):
        """Debug helper: display name and value of an attribute"""
        if level > debug_level:
            return
        print('{} = {}'.format(name, self.debug_decrypt(value)))

    def precompute_randoms(self):
        """Pre-compute what can be pre-computed

        In practice, this means generating encrypted random values, which do
        not depend on any input.
        """
        self.random_bits = [
            random.choice([self.ZERO, self.ONE])
            for _ in range(self.n_candidates*(self.n_choices+2)*self.n_bits)
        ]
        _max = 2**self.pk.security_parameter
        self.random_ints = [
            self.pk.encrypt(random.randrange(_max), randomize=False)
            for _ in range(self.n_candidates*(self.n_choices+2))
        ]

    def compute_sums(self):
        """Compute total and doubled partial sums of the ballots

        The doubled partial sums are compared to the total sums to locate the
        median.
        """
        self.total_sum_of_candidate = [sum(row) for row in self.A]
        self.debug(3, 'total_sum_of_candidate', self.total_sum_of_candidate)

        self.sums_of_candidate = [
            [2*sum(row[:j]) for j in range(1, len(row))]
            for row in self.A
        ]
        self.debug(3, 'sums_of_candidate', self.sums_of_candidate)

    def compute_bitrep_of_sums(self):
        """Switch the sums to binary representation"""
        flattened = self.bit_extraction_gate_batched(
            self.n_bits,
            self.total_sum_of_candidate +
            [x for row in self.sums_of_candidate for x in row]
        )
        self.total_sum_of_candidate = flattened[:self.n_candidates]
        self.sums_of_candidate = flattened[self.n_candidates:]

    def compute_greater_than_median(self):
        """Compute median detection vector"""
        # compare medians and partial sums to detect which values are greater
        # than the best median
        greater_than_candidate_median = self.gt_gate_batched(
            [
                self.total_sum_of_candidate[candidate]
                for candidate in range(self.n_candidates)
                for _ in range(self.n_choices-1)
            ],
            self.sums_of_candidate  # already flattened
        )
        # unflatten
        n = self.n_choices-1  # length of each row
        greater_than_candidate_median = [
            greater_than_candidate_median[i*n:(i+1)*n]
            for i in range(self.n_candidates)
        ]
        self.debug(3, 'greater_than_candidate_median', greater_than_candidate_median)

        self.greater_than_best_median = self.big_and_gate_batched([
            [
                greater_than_candidate_median[candidate][choice]
                for candidate in range(self.n_candidates)
            ] for choice in range(self.n_choices-1)
        ])
        self.debug(3, 'greater_than_best_median', self.greater_than_best_median)

    def compute_T(self):
        """Compute intermediate tie-breaking matrix T"""
        is_lower_than_best_median = [self.ONE - v for v in self.greater_than_best_median]
        conditioned_terms = self.and_gate_batched(
            [
                self.A[candidate][choice]
                for candidate in range(self.n_candidates)
                for choice in range(self.n_choices-1)
            ] + [
                self.A[candidate][choice]
                for candidate in range(self.n_candidates)
                for choice in range(1, self.n_choices)
            ],
            self.greater_than_best_median * self.n_candidates +
            is_lower_than_best_median * self.n_candidates
        )
        n = self.n_choices-1  # length of each row
        self.T = [
            sum(conditioned_terms[i*n:(i+1)*n])
            for i in range(self.n_candidates*2)
        ]
        self.debug(2, 'T', self.T)

    def compute_bitrep_of_T(self):
        """Switch T to binary representation"""
        self.T = self.bit_extraction_gate_batched(self.n_bits, self.T)

    def compute_comparisons(self):
        """Run challenges between the candidates (each-other and themselves)"""
        T_victory = self.T[:self.n_candidates]
        T_elimination = self.T[self.n_candidates:]

        comparisons = self.gt_gate_batched(
            T_victory + [
                T_victory[candidate]
                for candidate in range(self.n_candidates)
                for other_candidate in range(candidate)
            ] + [
                T_elimination[candidate]
                for candidate in range(self.n_candidates)
                for other_candidate in range(candidate)
            ],
            T_elimination + [
                T_victory[other_candidate]
                for candidate in range(self.n_candidates)
                for other_candidate in range(candidate)
            ] + [
                T_elimination[other_candidate]
                for candidate in range(self.n_candidates)
                for other_candidate in range(candidate)
            ]
        )

        n = self.n_candidates
        self.is_positive = comparisons[:n]
        more_greater_flat = comparisons[n:n+n*(n-1)//2]
        more_lower_flat = comparisons[n+n*(n-1)//2:]

        # unflatten
        self.more_greater = [
            [None]*self.n_candidates
            for _ in range(self.n_candidates)
        ]
        self.more_lower = [
            [None]*self.n_candidates
            for _ in range(self.n_candidates)
        ]
        i = 0
        for candidate in range(self.n_candidates):
            for other_candidate in range(candidate):
                result = more_greater_flat[i]
                self.more_greater[candidate][other_candidate] = result
                self.more_greater[other_candidate][candidate] = self.ONE - result
                result = more_lower_flat[i]
                self.more_lower[candidate][other_candidate] = result
                self.more_lower[other_candidate][candidate] = self.ONE - result
                i += 1

        # batch together comparisons for self-elimination and for challenges
        self.debug(3, 'is_positive', self.is_positive)
        self.debug(3, 'more_greater', self.more_greater)
        self.debug(3, 'more_lower', self.more_lower)

    def compute_winner(self):
        """Identify the winner (if any) using the results of the challenges"""

        positivity_batch = self.and_gate_batched(
            [
                self.is_positive[candidate]
                for candidate in range(self.n_candidates)
                for other_candidate in range(self.n_candidates)
                if other_candidate != candidate
            ] + [
                self.ONE - self.is_positive[candidate]
                for candidate in range(self.n_candidates)
                for other_candidate in range(self.n_candidates)
                if other_candidate != candidate
            ],
            [
                self.is_positive[other_candidate]
                for candidate in range(self.n_candidates)
                for other_candidate in range(self.n_candidates)
                if other_candidate != candidate
            ] + [
                self.ONE - self.is_positive[other_candidate]
                for candidate in range(self.n_candidates)
                for other_candidate in range(self.n_candidates)
                if other_candidate != candidate
            ]
        )

        win_conditions_batch = self.and_gate_batched(
            positivity_batch + [
                self.is_positive[candidate]
                for candidate in range(self.n_candidates)
                for other_candidate in range(self.n_candidates)
                if other_candidate != candidate
            ], [
                self.more_greater[candidate][other_candidate]
                for candidate in range(self.n_candidates)
                for other_candidate in range(self.n_candidates)
                if other_candidate != candidate
            ] + [
                self.more_lower[other_candidate][candidate]
                for candidate in range(self.n_candidates)
                for other_candidate in range(self.n_candidates)
                if other_candidate != candidate
            ] + [
                self.ONE - self.is_positive[other_candidate]
                for candidate in range(self.n_candidates)
                for other_candidate in range(self.n_candidates)
                if other_candidate != candidate
            ]
        )

        n = self.n_candidates
        when_both_positive = win_conditions_batch[n*(n-1):2*n*(n-1)]
        when_both_negative = win_conditions_batch[2*n*(n-1):]
        when_better_sign = win_conditions_batch[:n*(n-1)]

        lose_conditions_batch = self.and_gate_batched(
            self.and_gate_batched(
                [self.ONE - x for x in when_better_sign],
                [self.ONE - x for x in when_both_positive]),
            [self.ONE - x for x in when_both_negative]
        )

        n = self.n_candidates - 1  # length of each row
        lose_batch = [
            sum(lose_conditions_batch[i*n:(i+1)*n], self.ZERO)
            for i in range(self.n_candidates)
        ]
        self.debug(3, 'lose_batch', lose_batch)

        # reveal whether lose is null or not (masking with random number)
        max_ = 2**self.n_bits
        r_batch = [random.randrange(1, max_) for _ in range(self.n_candidates)]
        if debug_level >= 2:
            print('r_batch =', r_batch)

        clear_lose_batch = self.protocols.decrypt_batched([
            lose * r for lose, r in zip(lose_batch, r_batch)
        ])
        if debug_level >= 2:
            print('clear_lose_batch =', clear_lose_batch)

        assert clear_lose_batch.count(0) == 1
        self.winner = clear_lose_batch.index(0)

    def run(self, A):
        """Main method of the protocol"""
        self.A = A
        self.compute_sums()
        self.compute_bitrep_of_sums()
        self.compute_greater_than_median()
        self.compute_T()
        self.compute_bitrep_of_T()
        self.compute_comparisons()
        self.compute_winner()
        return self.winner


def clear_majority_judgment(A):
    """Compute the result of a majority judgment election in the clear"""
    n_candidates = len(A)

    # find best median
    best_median = float('inf')
    for candidate, ballots in enumerate(A):
        median_votes_for_candidate = sum(ballots) // 2
        partial_sum = 0
        for choice, n_votes in enumerate(ballots):
            partial_sum += n_votes
            if partial_sum > median_votes_for_candidate:
                break
        candidate_median = choice
        if debug_level >= 3:
            print('Median of {} is {}'.format(candidate, candidate_median))
        if candidate_median < best_median:
            best_median = candidate_median

    # compute T
    candidates = list(range(n_candidates))
    T_victory = [sum(row[:best_median]) for row in A]
    T_elimination = [sum(row[best_median+1::]) for row in A]
    if debug_level >= 2:
        print('T =', T_victory, T_elimination)

    # resolve tie
    while T_victory.count(-1) < n_candidates - 1:  # several candidates left
        if max(T_elimination) >= max(T_victory):
            # eliminate candidate
            eliminated = max(candidates, key=T_elimination.__getitem__)
            if debug_level >= 3:
                print('Candidate {} eliminated'.format(eliminated))
            del candidates[candidates.index(eliminated)]
            T_elimination[eliminated] = -1
            T_victory[eliminated] = -1
        else:  # immediate victory
            return max(candidates, key=T_victory.__getitem__)
    # victory by default
    return max(candidates, key=T_victory.__getitem__)


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
    clear_winner = clear_majority_judgment(clear_A)
    if debug_level >= 1:
        print('Clear protocol winner is', clear_winner)

    election = MPCMajorityJudgment(pk, protocols, n_choices, n_candidates, n_bits)
    election.precompute_randoms()

    # encrypt the ballots
    A = [[election.pk.encrypt(value) for value in row] for row in clear_A]

    # encrypted protocol
    if debug_level >= 2:
        print('Running majority judgment encrypted')
    start = time.time()
    winner = election.run(A)
    elapsed = time.time() - start
    if debug_level >= 1:
        print('Encrypted protocol winner is', winner)
        print('Took: {:.1f} s'.format(elapsed))

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
    n_batched_decryptions = 4*args.bits + args.candidates.bit_length() + 6
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
    parser.add_argument('seed', default=0, type=int, nargs='?')
    args = parser.parse_args()

    global debug_level
    debug_level = args.debug

    pk, protocols = load_keypair(args)

    max_simulations = args.simulations if args.simulations else float('inf')
    seed = args.seed
    simulated = 0
    while simulated < max_simulations:
        print('Seed: {}'.format(seed))
        run_test(seed, pk, protocols, args.choices, args.candidates, args.bits)
        seed += 1
        simulated += 1


if __name__ == '__main__':
    main()
