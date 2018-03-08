#!/usr/bin/env python3
"""
Majority judgment using Paillier encryption

LSBs and the conditional gates are partially implemented: the interaction
between the parties is simulated by generating all values locally

LSBs requires the input to be Paillier encryptions (cannot be adapted to El
Gamal or BGN). However, the output of the last LSBs can be El Gamal or BGN
encryption, so that the last conditional gates could be replaced by offline
pairings.

Depends on `phe` (available through PIP):
    <https://github.com/n1analytics/python-paillier>
"""
import math
import random
import argparse

import phe

import paillier

# debug_level = 0: quiet
# debug_level = 1: normal output
# debug_level = 2: some intermediate values
# debug_level = 3: detailed intermediate values
debug_level = 1


class PaillierMajorityJudgement:
    """Implementation of a Majority Judgement protocol with Paillier encryption

    The main method of this class is `run()`. Due to the high complexity of the
    prococol, the code is split into several methods named `compute_*()`.

    Basic operations (decryption, logical and, comparison, addition, bit
    representation) are implemented in the `*_gate_batched()` methods. These
    imply interactions between the different participants. To minimize the
    number of interaction (circuit depth), these operations are batched (hence
    the name). For instance, each call to a `and_gate_batched()` computes
    several logical and in parallel. In general `*_batch` variables represent
    values that are batched togather for concurrent handling.

    Other methods are:
        * `debug_decrypt()`: decrypt a value (only for debugging!)
        * `debug()`: show name and value of an attribute for easy debugging
    """
    def __init__(self, pk, sk, n_choices, n_candidates, n_bits):
        self.n_choices = n_choices
        self.n_candidates = n_candidates
        self.n_bits = n_bits
        self.n_parties = 8
        self.security_parameter = 80

        self.pk = pk
        self.sk = sk

        self.n_decrypt_gate = 0
        self.d_decrypt_gate = 0

        self.ZERO = self.pk.encrypt(0)
        self.ONE = self.pk.encrypt(1)

    def decrypt_gate_batched(self, x_batch):
        """Decryption gate

        Each participant is assumed to hold part of the decryption key. This
        gate allows them to cooperate so as to decrypt specific values.
        """
        self.n_decrypt_gate += len(x_batch)
        self.d_decrypt_gate += 1
        return [self.sk.decrypt(x) for x in x_batch]

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
        x_or_minus_x_batch = self.conditional_gate_batched(
            x_batch, y_as_one_or_minus_one_batch
        )
        return [
            (x_or_minus_x + x) / 2
            for x_or_minus_x, x in zip(x_or_minus_x_batch, x_batch)
        ]

    def big_and_gate_batched(self, bits_batch):
        """Reduce bits through and_gate"""
        bits_batch = [list(bits) for bits in bits_batch]
        while any(len(bits) > 1 for bits in bits_batch):
            # split bits in two halves, and a rest (if length is odd)
            half_length_batch = [len(bits) // 2 for bits in bits_batch]
            left_half_batch = [
                bits[:half]
                for bits, half in zip(bits_batch, half_length_batch)
            ]
            right_half_batch = [
                bits[half:half*2]
                for bits, half in zip(bits_batch, half_length_batch)
            ]
            rest_batch = [
                bits[half*2:]  # either zero or one element
                for bits, half in zip(bits_batch, half_length_batch)
            ]

            # flatten for batching
            left_flat = [x for left in left_half_batch for x in left]
            right_flat = [x for right in right_half_batch for x in right]

            # run the gate batched
            result_flat = self.and_gate_batched(left_flat, right_flat)

            # unflaten
            result_batch = []
            total = 0
            for half in half_length_batch:
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
        xy_flat = self.and_gate_batched(x_flat, y_flat)

        # unflatten
        xy_batch = []
        total = 0
        for length in length_batch:
            xy_batch.append(xy_flat[total:total+length])
            total += length

        # first bit (only one and_gate needed)
        ti_batch = [
            x[0] - xy[0]
            for x, xy in zip(x_batch, xy_batch)
        ]

        # rest of the bits (two and_gate per bit)
        for i in range(1, len(x_batch[0])):
            # ti = (1 - (xi - yi)**2) * ti + xi*(1-yi)
            #    = (1 - xi - yi + 2 xi yi) ti + xi - xi yi
            parenthesis_batch = [
                1 - x[i] - y[i] + 2*xy[i]
                for x, y, xy in zip(x_batch, y_batch, xy_batch)
            ]
            product_batch = self.and_gate_batched(parenthesis_batch, ti_batch)
            ti_batch = [
                product + x[i] - xy[i]
                for product, x, xy in zip(product_batch, x_batch, xy_batch)
            ]
            # we exploit the fact that all the integers to compare are of the
            # same length, otherwise, we would need to keep track of whose bits
            # are being sent to the and_gate

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
            xi_xor_yi_and_c_batch = \
                self.and_gate_batched(xi_xor_yi_batch, c_batch)
            for k in range(len(x_batch)):
                xi_xor_yi = xi_xor_yi_batch[k]
                xi_xor_yi_and_c = xi_xor_yi_and_c_batch[k]
                c = c_batch[k]
                xi = x_batch[k][i]
                yi = y_batch[k][i]

                r = xi_xor_yi + c - 2*xi_xor_yi_and_c
                c_batch[k] = (xi + yi + c - r) / 2
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
        r_bits_batch = [
            [self.random_bits.pop() for _ in range(self.n_bits)]
            for _ in x_batch
        ]
        # compute r = r_star 2**n_bits + \sum r_i 2**i
        r_batch = [
            r_star * (2**self.n_bits) + sum(
                r_bits[i] * (2**i) for i in range(self.n_bits)
            )
            for r_star, r_bits in zip(r_star_batch, r_bits_batch)
        ]

        # get clear bits of y = x - r
        y_batch = self.decrypt_gate_batched([
            x - r
            for x, r in zip(x_batch, r_batch)
        ])
        y_bits_batch = [
            [(y >> i) & 1 for i in range(self.n_bits)]
            for y in y_batch
        ]

        # compute x = y + r using encrypted bits of r and clear bits of y
        return self.private_add_gate_batched(r_bits_batch, y_bits_batch)

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

    def debug(self, level, name, value):
        """Debug helper: display name and value of an attribute"""
        if level > debug_level:
            return
        print('{} = {}'.format(name, self.debug_decrypt(value)))

    def compute_precomputations(self):
        """Pre-compute what can be pre-computed

        In practice, this means generating encrypted random values, which do
        not depend on any input.
        """
        self.random_bits = [
            random.choice([self.ZERO, self.ONE])
            for _ in range(self.n_candidates*(self.n_choices+2)*self.n_bits)
        ]
        self.random_ints = [
            self.pk.encrypt(random.randrange(2**self.security_parameter))
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
        flattened = self.lsbs_gate_batched(
            self.total_sum_of_candidate +
            [x for row in self.sums_of_candidate for x in row]
        )
        self.total_sum_of_candidate = flattened[:self.n_candidates]
        self.sums_of_candidate = flattened[self.n_candidates:]

    def compute_right_to_median(self):
        """Compute median detection vector"""
        # compare medians and partial sums to detect which values are left to
        # the best median and which are right to the best median
        right_to_candidate_median = self.gt_gate_batched(
            self.sums_of_candidate,  # already flattened
            [
                self.total_sum_of_candidate[candidate]
                for candidate in range(self.n_candidates)
                for _ in range(self.n_choices-1)
            ]
        )
        # unflatten
        n = self.n_choices-1  # length of each row
        right_to_candidate_median = [
            right_to_candidate_median[i*n:(i+1)*n]
            for i in range(self.n_candidates)
        ]
        self.debug(3, 'right_to_candidate_median', right_to_candidate_median)

        self.right_to_median = self.big_and_gate_batched([
            [
                right_to_candidate_median[candidate][choice]
                for candidate in range(self.n_candidates)
            ] for choice in range(self.n_choices-1)
        ])
        self.debug(3, 'right_to_median', self.right_to_median)

    def compute_T(self):
        """Compute intermediate tie-breaking matrix T"""
        is_left_to_median = [self.ONE - v for v in self.right_to_median]
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
            is_left_to_median * self.n_candidates +
            self.right_to_median * self.n_candidates
        )
        n = self.n_choices-1  # length of each row
        self.T = [
            sum(conditioned_terms[i*n:(i+1)*n])
            for i in range(self.n_candidates*2)
        ]
        self.debug(2, 'T', self.T)

    def compute_bitrep_of_T(self):
        """Switch T to binary representation"""
        self.T = self.lsbs_gate_batched(self.T)

    def compute_challenge_results(self):
        """Run challenges between the candidates (each-other and themselves)"""
        T_elimination = self.T[:self.n_candidates]
        T_victory = self.T[self.n_candidates:]

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
        self.debug(3, 'comparisons', comparisons)

        self.self_elimination = comparisons[:self.n_candidates]
        self.debug(3, 'self_elimination', self.self_elimination)

        # extend triangular comparison matrix to full matrix
        challenges = [
            [None]*self.n_candidates
            for _ in range(self.n_candidates)
        ]
        i_comparison = self.n_candidates
        for candidate in range(self.n_candidates):
            for other_candidate in range(candidate):
                comparison = comparisons[i_comparison]
                challenges[candidate][other_candidate] = comparison
                challenges[other_candidate][candidate] = self.ONE - comparison
                i_comparison += 1
        self.debug(3, 'challenges', challenges)

        # batch challenge results (challenge did happen and was lost)
        self.challenge_results = self.and_gate_batched(
            [
                self.ONE - self.self_elimination[other_candidate]
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
        self.debug(3, 'challenge_results', self.challenge_results)

    def compute_winner(self):
        """Identify the winner (if any) using the results of the challenges"""
        # explicit formula (sum of simple ands version)
        n = self.n_candidates - 1  # length of each row
        lose_batch = [
            self.self_elimination[i] + sum(self.challenge_results[i*n:(i+1)*n])
            for i in range(self.n_candidates)
        ]
        self.debug(3, 'lose_batch', lose_batch)

        # reveal whether lose is null or not (masking with random number)
        max_ = 2**self.n_bits
        r_batch = [random.randrange(1, max_) for _ in range(self.n_candidates)]
        if debug_level >= 2:
            print('r_batch =', r_batch)

        clear_lose_batch = self.decrypt_gate_batched([
            lose * r for lose, r in zip(lose_batch, r_batch)
        ])
        if debug_level >= 2:
            print('clear_lose_batch =', clear_lose_batch)

        assert clear_lose_batch.count(0) <= 1
        if 0 in clear_lose_batch:
            self.winner = clear_lose_batch.index(0)
        else:
            self.winner = None

    def run(self, A):
        """Main method of the protocol"""
        self.A = A
        self.compute_precomputations()
        self.compute_sums()
        self.compute_bitrep_of_sums()
        self.compute_right_to_median()
        self.compute_T()
        self.compute_bitrep_of_T()
        self.compute_challenge_results()
        self.compute_winner()
        return self.winner


def clear_majority_judgment(n_choices, n_candidates, A):
    """Compute the result of a majority judgment election in the clear"""
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


#inspired from http://umusebo.com/generate-n-random-numbers-whose-sum-equals-a-known-value/


def random_numbers_totaling(total, count):
    """Return count random numbers whose sum equals total"""
    # divide [0, total] in count random subranges
    fenceposts = sorted(random.choice(range(total+1)) for _ in range(count-1))
    # return the lengths of these subranges
    return [b - a for a, b in zip([0] + fenceposts, fenceposts + [total])]


def run_test(seed, pk, sk, n_choices, n_candidates, n_bits):
    random.seed(seed)

    # generate the ballots
    clear_A = [
        random_numbers_totaling(2**n_bits // 2 - 1, n_choices)
        for _ in range(n_candidates)
    ]
    if debug_level >= 2:
        print('A =', clear_A)
    # for simplicity, we assume that the aggregate matrix is already normalized
    assert all(sum(clear_A[0]) == sum(row) for row in clear_A)

    # clear protocol
    if debug_level >= 2:
        print('Running majority judgment in the clear')
    clear_winner = clear_majority_judgment(n_choices, n_candidates, clear_A)
    if debug_level >= 1:
        print('Clear protocol winner is', clear_winner)

    # encrypt the ballots
    election = PaillierMajorityJudgement(pk, sk, n_choices, n_candidates,
                                         n_bits)

    A = [[election.pk.encrypt(value) for value in row] for row in clear_A]

    # encrypted protocol
    if debug_level >= 2:
        print('Running majority judgment encrypted')
    winner = election.run(A)
    if debug_level >= 1:
        print('Encrypted protocol winner is', winner)

    # show number of calls to oracle
    if debug_level >= 1:
        print('{} decrypt gates (depth: {})'.format(
            election.n_decrypt_gate, election.d_decrypt_gate)
        )

    assert winner == clear_winner


def crt(residues, modulos):
    redidues = list(residues)
    product = 1
    for modulo in modulos:
        product *= modulo
    r = 0
    for residue, modulo in zip(residues, modulos):
        NX = product // modulo
        r += residue * NX * phe.util.invert(NX, modulo)
        r %= product
    return r


class SharedPaillerSecretKey:
    def __init__(self, shares):
        self.shares = shares

    def decrypt(self, x):
        pk = x.public_key
        c = x.ciphertext(be_secure=False)
        decrypts = [phe.util.powmod(c, share, pk.nsquare) for share in self.shares]
        product = 1
        for decrypt in decrypts:
            product = (product * decrypt) % pk.nsquare
        clear = (product-1) // pk.n
        if clear > pk.n // 2:
            return clear - pk.n
        return clear


def share_paillier_secret_key(sk, n_parties):
    pk = sk.public_key
    # Carmicael function applied on n (= lcm(p-1, q-1))
    lambda_ = (sk.p-1)*(sk.q-1) // math.gcd(sk.p-1, sk.q-1)

    # choose d such that d = 0 mod lambda_ and d = 1 mod n
    d = crt([0, 1], [lambda_, pk.n])

    shares = [
        random.randrange(pk.n*lambda_)
        for _ in range(n_parties-1)
    ]
    shares.append((d - sum(shares)) % (pk.n*lambda_))
    return SharedPaillerSecretKey(shares)


def main():
    parser = argparse.ArgumentParser()
    parser.description = 'Majority judgment protocol with Paillier encryption'
    parser.add_argument('--debug', '-d', default=1, type=int)
    parser.add_argument('--parties', default=0, type=int)
    parser.add_argument('--choices', '-n', default=5, type=int)
    parser.add_argument('--candidates', '-m', default=3, type=int)
    parser.add_argument('--bits', '-l', default=11, type=int)
    parser.add_argument('--cryptosystem', '-c', default='phe',
                        choices=['mock', 'phe'])
    parser.add_argument('--simulations', default=1, type=int)
    parser.add_argument('seed', default=0, type=int, nargs='?')
    args = parser.parse_args()

    global debug_level
    debug_level = args.debug

    # in phe, __truediv__ returns a float, so we redefine it for integers only
    def __truediv__(self, other):
        # assumes self is divisible by other
        if other != 2:
            # we only ever use halving, so let us keep it simple
            raise NotImplementedError
        if not hasattr(self.public_key, '_HALF_MOD_N'):
            # compute 1/2 mod n
            self.public_key._HALF_MOD_N = phe.util.invert(2, self.public_key.n)
        half_self = self._raw_mul(self.public_key._HALF_MOD_N)
        return phe.EncryptedNumber(self.public_key, half_self, self.exponent)
    phe.EncryptedNumber.__truediv__ = __truediv__

    # select the cryptosystem
    if args.cryptosystem == 'mock':
        pk, sk = paillier.mock_paillier_keypair()
    elif args.cryptosystem == 'phe':
        pk, sk = phe.paillier.generate_paillier_keypair()
    else:
        raise NotImplementedError

    if args.parties > 0:
        sk = share_paillier_secret_key(sk, args.parties)

    max_simulations = args.simulations if args.simulations else float('inf')
    seed = args.seed
    simulated = 0
    while simulated < max_simulations:
        print('Seed: {}'.format(seed))
        run_test(seed, pk, sk, args.choices, args.candidates, args.bits)
        seed += 1
        simulated += 1


if __name__ == '__main__':
    main()
