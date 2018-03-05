#!/usr/bin/env python3
"""
Majority judgement using Paillier encryption

LSBs and the conditional gates are partially implemented: the interaction
between the parties is simulated by generating all values locally

LSBs requires the input to be Paillier encryptions (cannot be adapted to El
Gamal or BGN). However, the output of the last LSBs can be El Gamal or BGN
encryption, so that the last conditional gates could be replaced by offline
pairings.

Depends on `phe` (avaliable through in PIP):
    <https://github.com/n1analytics/python-paillier>
"""
import random
import argparse

import phe

# debug_level = 0: quiet
# debug_level = 1: normal output
# debug_level = 2: some intermediate values
# debug_level = 3: detailed intermediate values
# debug_level = 4: all comparisons as well
debug_level = 1


class PaillierMajorityJudgement:
    def __init__(self, n_choices, n_candidates, n_bits):
        self.n_choices = n_choices
        self.n_candidates = n_candidates
        self.n_bits = n_bits
        self.n_parties = 8
        self.security_parameter = 80

        self.pk, self.sk = phe.paillier.generate_paillier_keypair()

        self.n_decrypt_gate = 0
        self.d_decrypt_gate = 0

        self.ZERO = self.pk.encrypt(0)
        self.ONE = self.pk.encrypt(1)

        self.HALF_MOD_N = phe.util.invert(2, self.pk.n)

    def halve(self, x):
        """Halve an integer that is known to be even
        
        EncryptedNumber.__truediv__ casts it to a float, which can be
        problematic when the number is large
        """
        return phe.EncryptedNumber(self.pk, x._raw_mul(self.HALF_MOD_N), x.exponent)

    def decrypt_gate_batched(self, x_batch):
        self.n_decrypt_gate += len(x_batch)
        self.d_decrypt_gate += 1
        return [int(self.sk.decrypt(x)) for x in x_batch]

    def conditional_gate_batched(self, x_batch, y_batch):
        """Conditional gate, as per ST04

        Practical Two-Party Computation Based on the Conditional Gate
        Section 3.2 (pages 7 through 10)

            x is an encryption of an integer
            y is an encryption of -1 or 1
            returns x * y
        """
        x_batch, y_batch = list(x_batch), list(y_batch)
        assert len(x_batch) == len(y_batch)

        for _ in range(self.n_parties):
            for i in range(len(x_batch)):
                r = random.choice([-1, 1])
                x_batch[i] *= r
                y_batch[i] *= r
        clear_y_batch = self.decrypt_gate_batched(y_batch)
        return [x * clear_y for x, clear_y in zip(x_batch, clear_y_batch)]

    def and_gate_batched(self, x_batch, y_batch):
        """Extended and gate

            x is an encryption of an integer
            y is an encryption of 0 or 1
            returns x if y = 1 else 0

        When x is 0 or 1, acts as a normal and gate"""
        y_as_one_or_minus_one_batch = [2*y-1 for y in y_batch]
        x_or_minus_x_batch = self.conditional_gate_batched(x_batch, y_as_one_or_minus_one_batch)
        return [self.halve(x_or_minus_x + x) for x_or_minus_x, x in zip(x_or_minus_x_batch, x_batch)]

    def big_and_gate_batched(self, bits_batch):
        """Reduce bits through and_gate"""
        bits_batch = [list(bits) for bits in bits_batch]
        while any(len(bits) > 1 for bits in bits_batch):
            half_batch = [len(bits) // 2 for bits in bits_batch]
            left_batch = [bits[:half] for bits, half in zip(bits_batch, half_batch)]
            right_batch = [bits[half:half*2] for bits, half in zip(bits_batch, half_batch)]
            rest_batch = [bits[half*2:] for bits, half in zip(bits_batch, half_batch)]  # either zero or one element

            # flatten
            left_flat = [x for left in left_batch for x in left]
            right_flat = [x for right in right_batch for x in right]

            # run the gate batched
            result_flat = self.and_gate_batched(left_flat, right_flat)

            # unflaten
            result_batch = []
            total = 0
            for half in half_batch:
                result_batch.append(result_flat[total:total+half])
                total += half

            # append rest
            bits_batch = [
                result + rest for result, rest in zip(result_batch, rest_batch)
            ]
        return [bits[0] for bits in bits_batch]

    def gt_gate_batched(self, x_batch, y_batch):
        """Greater-than gate, as per ST04

        Practical Two-Party Computation Based on the Conditional Gate
        Section 5.2 (page 15)

            x is an encryption of an integer
            y is an encryption of an integer
            returns 1 if x > y else 0
        """
        x_batch = [list(x) for x in x_batch]
        y_batch = [list(y) for y in y_batch]
        assert len(x_batch) == len(y_batch)
        assert all(len(x) == len(y) for x, y in zip(x_batch, y_batch))
        # not strictly necessary but makes the code easier
        assert all(len(x) == len(x_batch[0]) for x in x_batch)

        length_batch = [len(x) for x in x_batch]

        # flatten
        x_flat = [bit for x in x_batch for bit in x]
        y_flat = [bit for y in y_batch for bit in y]

        # first, compute all xi & yi in batch
        x_and_y_flat = self.and_gate_batched(x_flat, y_flat)

        # unflatten
        x_and_y_batch = []
        total = 0
        for length in length_batch:
            x_and_y_batch.append(x_and_y_flat[total:total+length])
            total += length

        # first bit (only one and_gate needed)
        ti_batch = [x[0] - x_and_y[0] for x, x_and_y in zip(x_batch, x_and_y_batch)]

        # rest of the bits (two and_gate per bit)
        for i in range(1, len(x_batch[0])):
            # ti = (1 - (xi - yi)**2) * ti + xi*(1-yi)
            #    = (1 - xi - yi + 2 xi yi) ti + xi - xi yi
            parenthesis_batch = [
                1 - x[i] - y[i] + 2*x_and_y[i]
                for x, y, x_and_y in zip(x_batch, y_batch, x_and_y_batch)
            ]
            left_hand_addition_batch = self.and_gate_batched(parenthesis_batch, ti_batch)
            ti_batch = [
                left_hand_addition + x[i] - x_and_y[i]
                for left_hand_addition, x, x_and_y in zip(left_hand_addition_batch, x_batch, x_and_y_batch)
            ]
            # we exploit the fact that all the integers to compare are of the same
            # length, otherwise, we would need to keep track of whose bits are
            # being sent to the and_gate

        if debug_level >= 4:
            for x, y, ti in zip(x_batch, y_batch, ti_batch):
                print('{} > {} -> {}'.format(self.debug_decrypt(x), self.debug_decrypt(y), self.debug_decrypt(ti)))
        return ti_batch

    def private_add_gate_batched(self, x_batch, y_batch):
        """Add gate for encrypted x and clear y, both in binary representation

            x is a list of encrypted bits
            y is a list of bits
            return a list of encrypted bits representing the sum of x and y

        Note that the final carry is discarded
        """
        x_batch = [list(x) for x in x_batch]
        y_batch = [list(y) for y in y_batch]
        assert len(x_batch) == len(y_batch)
        assert all(len(x) == len(y) for x, y in zip(x_batch, y_batch))
        # not strictly necessary but makes the code easier
        assert all(len(x) == len(x_batch[0]) for x in x_batch)

        # first bit (no and_gate needed)
        ret_batch = [
            [x[0] + y[0] - 2*x[0]*y[0]]  # xi ^ yi
            for x, y in zip(x_batch, y_batch)
        ]
        c_batch = [x[0]*y[0] for x, y in zip(x_batch, y_batch)]  # xi & yi

        # rest of the bits (one and_gate per bit)
        for i in range(1, len(x_batch[0])):
            xi_xor_yi_batch = [
                x[i] + y[i] - 2*x[i]*y[i]  # xi ^ yi
                for x, y in zip(x_batch, y_batch)
            ]
            xi_xor_yi_and_c_batch = self.and_gate_batched(xi_xor_yi_batch, c_batch)
            for k in range(len(x_batch)):
                xi_xor_yi = xi_xor_yi_batch[k]
                xi_xor_yi_and_c = xi_xor_yi_and_c_batch[k]
                c = c_batch[k]
                xi = x_batch[k][i]
                yi = y_batch[k][i]

                r = xi_xor_yi + c - 2*xi_xor_yi_and_c
                c_batch[k] = self.halve(xi + yi + c - r)
                ret_batch[k].append(r)
        return ret_batch

    def lsbs_gate_batched(self, x_batch):
        """LSBs gate, as per ST06

        Efficient Binary Conversion for Paillier Encrypted Values
        Section 4 (pages 10 through 12)

            x is an encryption of an integer
            returns the list of the encrypted bits of x

        Alternatively, an iterable of integers (resp. iterable of iterable of
        integers...) can be provided and a list (resp. list of list of
        integers, ...) will be returned.
        """
        x_batch = list(x_batch)

        # generate r_*
        r_star_batch = [self.random_ints.pop() for _ in x_batch]
        # the n_bits first bits of r are published encrypted individually
        encrypted_r_bits_batch = [
            [self.random_bits.pop() for _ in range(self.n_bits)]
            for _ in x_batch
        ]
        # compute r = r_star 2**n_bits + \sum r_i 2**i
        r_batch = [
            r_star * (2**self.n_bits) + sum(encrypted_r_bits[i] * (2**i) for i in range(self.n_bits))
            for r_star, encrypted_r_bits in zip(r_star_batch, encrypted_r_bits_batch)
        ]

        # get clear bits of y = x - r
        y_batch = self.decrypt_gate_batched([x - r for x, r in zip(x_batch, r_batch)])
        y_bits_batch = [
            [(y >> i) & 1 for i in range(self.n_bits)]
            for y in y_batch
        ]

        # compute x = y + r using the encrypted bits of r and the clear bits of y
        return self.private_add_gate_batched(encrypted_r_bits_batch, y_bits_batch)

    def debug_decrypt(self, x):
        """Debug helper: recursively decrypt values"""
        if x is None:
            return None
        try:
            x = iter(x)
        except TypeError:
            return self.sk.decrypt(x)
        else:
            return [self.debug_decrypt(value) for value in x]

    def precompute(self):
        self.random_bits = [
            random.choice([self.ZERO, self.ONE])
            for _ in range(self.n_candidates*(self.n_choices+2)*self.n_bits)
        ]
        self.random_ints = [
            self.pk.encrypt(random.randrange(2**self.security_parameter))
            for _ in range(self.n_candidates*(self.n_choices+2))
        ]

    def compute_is_left_right_to_median(self, A):
        total_sum_of_candidate = [sum(row) for row in A]
        doubled_partial_sums_of_candidate = [
            [2*sum(row[:j]) for j in range(1, len(row))]
            for row in A
        ]

        if debug_level >= 2:
            print('A =', self.debug_decrypt(A))

        if debug_level >= 3:
            print('total_sum_of_candidate =', self.debug_decrypt(total_sum_of_candidate))
            print('doubled_partial_sums_of_candidate =', self.debug_decrypt(doubled_partial_sums_of_candidate))

        # flatten total_sum_of_candidate and doubled_partial_sums_of_candidate together
        flattened = total_sum_of_candidate + \
            [x for row in doubled_partial_sums_of_candidate for x in row]
        # switch to binary representation
        flattened = self.lsbs_gate_batched(flattened)
        # unflatten
        total_sum_of_candidate = flattened[:self.n_candidates]
        doubled_partial_sums_of_candidate = flattened[self.n_candidates:]

        # compare medians and partial sums to detect which values are left to the
        # best median and which are right to the best median
        is_right_to_candidate_median = self.gt_gate_batched(
            doubled_partial_sums_of_candidate,  # already flattened
            [
                total_sum_of_candidate[candidate]
                for candidate in range(self.n_candidates)
                for _ in range(self.n_choices-1)
            ]
        )
        # unflatten
        is_right_to_candidate_median = [
            is_right_to_candidate_median[candidate*(self.n_choices-1):(candidate+1)*(self.n_choices-1)]
            for candidate in range(self.n_candidates)
        ]
        is_right_to_median = self.big_and_gate_batched([
            [
                is_right_to_candidate_median[candidate][choice]
                for candidate in range(self.n_candidates)
            ] for choice in range(self.n_choices-1)
        ])
        is_left_to_median = [self.ONE - v for v in is_right_to_median]

        if debug_level >= 3:
            print('is_right_to_candidate_median =', self.debug_decrypt(is_right_to_candidate_median))
            print('is_left_to_median =', self.debug_decrypt(is_left_to_median))
            print('is_right_to_median =', self.debug_decrypt(is_right_to_median))

        return is_left_to_median, is_right_to_median

    def compute_T(self, A, is_left_to_median, is_right_to_median):
        conditioned_terms = self.and_gate_batched(
            [
                A[candidate][choice]
                for candidate in range(self.n_candidates)
                for choice in range(self.n_choices-1)
            ] + [
                A[candidate][choice]
                for candidate in range(self.n_candidates)
                for choice in range(1, self.n_choices)
            ],
            is_left_to_median * self.n_candidates + is_right_to_median * self.n_candidates
        )
        T = [
            sum(conditioned_terms[candidate*(self.n_choices-1):(candidate+1)*(self.n_choices-1)])
            for candidate in range(self.n_candidates*2)
        ]

        if debug_level >= 2:
            print('T =', self.debug_decrypt(T))

        return T

    def compute_winner(self, T):
        assert len(T) % 2 == 0

        T_elimination, T_victory = T[:self.n_candidates], T[self.n_candidates:]

        left_challenger = [
            T_victory[candidate]
            for candidate in range(self.n_candidates)
            for other_candidate in range(candidate)
        ]
        right_challenger = [
            T_victory[other_candidate]
            for candidate in range(self.n_candidates)
            for other_candidate in range(candidate)
        ]
        # batch together comparisons for self-elimination and for challenges
        comparisons = self.gt_gate_batched(
            T_elimination + left_challenger,
            T_victory + right_challenger
        )
        self_elimination = comparisons[:self.n_candidates]
        # extend triangular comparison matrix to full matrix
        challenges = [[None]*self.n_candidates for _ in range(self.n_candidates)]
        i_comparison = self.n_candidates
        for candidate in range(self.n_candidates):
            for other_candidate in range(candidate):
                comparison = comparisons[i_comparison]
                challenges[candidate][other_candidate] = comparison
                challenges[other_candidate][candidate] = self.ONE - comparison
                i_comparison += 1

        if debug_level >= 3:
            print('comparisons =', self.debug_decrypt(comparisons))
            print('challenges =', self.debug_decrypt(challenges))

        # batch challenge results (challenge did happen and was lost)
        challenge_results = self.and_gate_batched(
            [
                self.ONE - self_elimination[other_candidate]
                for candidate in range(self.n_candidates)
                for other_candidate in range(self.n_candidates)
                if other_candidate != candidate
            ],
            [
                challenges[other_candidate][candidate]
                for candidate in range(self.n_candidates)
                for other_candidate in range(self.n_candidates)
                if other_candidate != candidate
            ]
        )

        if debug_level >= 3:
            print('challenge_results =', self.debug_decrypt(challenge_results))

        # explicit formula (sum of simple ands version)
        lose_batch = [
            self_elimination[candidate] + sum(
                challenge_results[candidate*(self.n_candidates-1):(candidate+1)*(self.n_candidates-1)]
            )
            for candidate in range(self.n_candidates)
        ]

        if debug_level >= 3:
            print('lose_batch =', self.debug_decrypt(lose_batch))

        # reveal whether lose is null or not (masking with random number)
        r_batch = [random.randrange(1, 2**self.n_bits) for _ in range(self.n_candidates)]
        clear_lose_batch = self.decrypt_gate_batched([
            lose * r for lose, r in zip(lose_batch, r_batch)
        ])

        if debug_level >= 2:
            print('r_batch =', r_batch)
            print('clear_lose_batch =', clear_lose_batch)

        assert clear_lose_batch.count(0) <= 1
        if 0 in clear_lose_batch:
            return clear_lose_batch.index(0)
        else:
            return None

    def run(self, A):
        self.precompute()
        is_left_to_median, is_right_to_median = self.compute_is_left_right_to_median(A)
        T = self.compute_T(A, is_left_to_median, is_right_to_median)
        T = self.lsbs_gate_batched(T)  # switch to binary representation again
        return self.compute_winner(T)


def clear_majority_judgement(n_choices, n_candidates, A):
    # find best median
    best_median = 0
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
        if candidate_median > best_median:
            best_median = candidate_median

    # compute T
    candidates = list(range(n_candidates))
    T_elimination = [sum(row[:best_median]) for row in A]
    T_victory = [sum(row[best_median+1:]) for row in A]
    if debug_level >= 2:
        print('T =', T_elimination, T_victory)

    # resolve tie
    while candidates:
        if max(T_elimination) > max(T_victory):
            # eliminate candidate
            eliminated = max(candidates, key=T_elimination.__getitem__)
            if debug_level >= 3:
                print('Candidate {} eliminated'.format(eliminated))
            del candidates[candidates.index(eliminated)]
            T_elimination[eliminated] = 0
            T_victory[eliminated] = 0
        else:
            winner = max(candidates, key=T_victory.__getitem__)
            return winner
    return None


def run_test(seed, n_choices, n_candidates, n_bits):
    random.seed(seed)
    max_value = 2**n_bits // n_choices // 2

    clear_A = [
        [random.randrange(max_value) for _ in range(n_choices)]
        for _ in range(n_candidates)
    ]
    if debug_level >= 3:
        print('A =', clear_A)

    if debug_level >= 2:
        print('Running majority judgement in the clear')
    clear_winner = clear_majority_judgement(n_choices, n_candidates, clear_A)
    if debug_level >= 1:
        print('Clear protocol winner is', clear_winner)

    election = PaillierMajorityJudgement(n_choices, n_candidates, n_bits)
    A = [[election.pk.encrypt(value) for value in row] for row in clear_A]

    if debug_level >= 2:
        print('Running majority judgement encrypted')
    winner = election.run(A)
    if debug_level >= 1:
        print('Encrypted protocol winner is', winner)

    # show calls to oracles
    if debug_level >= 1:
        print('{} decrypt gates (depth: {})'.format(election.n_decrypt_gate, election.d_decrypt_gate))

    assert winner == clear_winner


def main():
    parser = argparse.ArgumentParser()
    parser.description = 'Run majority judgement protocol using Paillier encrption'
    parser.add_argument('--debug', '-d', default=1, type=int)
    parser.add_argument('--choices', '-n', default=5, type=int)
    parser.add_argument('--candidates', '-m', default=3, type=int)
    parser.add_argument('--bits', '-l', default=11, type=int)
    parser.add_argument('seed', default=0, type=int, nargs='?')
    args = parser.parse_args()

    global debug_level
    debug_level = args.debug

    seed = args.seed
    while True:
        print('Seed: {}'.format(seed))
        run_test(seed, args.choices, args.candidates, args.bits)
        seed += 1


if __name__ == '__main__':
    main()
