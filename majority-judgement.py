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

n_parties = 8
security_parameter = 80

# public_key is used as a global to encrypt constants (0 or 1)
# private_key is used as a global to black-box gates and for debugging
public_key, private_key = phe.paillier.generate_paillier_keypair()

ZERO = public_key.encrypt(0)
ONE = public_key.encrypt(1)

# we sometimes need to halve integers that are known to be even; using
# `EncryptedNumber.__truediv__` casts it to float, so we do it manually instead
HALF_MOD_N = phe.util.invert(2, public_key.n)


def halve(x):
    return phe.EncryptedNumber(public_key, x._raw_mul(HALF_MOD_N), x.exponent)


def private_add_gate_batched(x_batch, y_batch):
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
    # xi ^ yi
    ret_batch = [[x[0] + y[0] - 2*x[0]*y[0]] for x, y in zip(x_batch, y_batch)]
    # xi & yi
    c_batch = [x[0]*y[0] for x, y in zip(x_batch, y_batch)]

    # rest of the bits (one and_gate per bit)
    for i in range(1, len(x_batch[0])):
        xi_xor_yi_batch = [
            x[i] + y[i] - 2*x[i]*y[i]
            for x, y in zip(x_batch, y_batch)
        ]
        xi_xor_yi_and_c_batch = and_gate_batched(xi_xor_yi_batch, c_batch)
        for k in range(len(x_batch)):
            xi_xor_yi = xi_xor_yi_batch[k]
            xi_xor_yi_and_c = xi_xor_yi_and_c_batch[k]
            c = c_batch[k]
            xi = x_batch[k][i]
            yi = y_batch[k][i]

            r = xi_xor_yi + c - 2*xi_xor_yi_and_c
            c_batch[k] = halve(xi + yi + c - r)
            ret_batch[k].append(r)
    return ret_batch


def random_integer_gate_batched(upper_bound_batched):
    global n_random_integer_gate, d_random_integer_gate
    n_random_integer_gate += len(upper_bound_batched)
    d_random_integer_gate += 1
    return [
        public_key.encrypt(random.randrange(upper_bound))
        for upper_bound in upper_bound_batched
    ]


def random_bit_gate_batched(count):
    global n_random_bit_gate, d_random_bit_gate
    n_random_bit_gate += count
    d_random_bit_gate += 1
    return [random.choice([ZERO, ONE]) for _ in range(count)]


def decrypt_gate_batched(x_batch):
    global n_decrypt_gate, d_decrypt_gate
    n_decrypt_gate += len(x_batch)
    d_decrypt_gate += 1
    return [int(private_key.decrypt(x)) for x in x_batch]


def lsbs_batched(x_batch, n_bits):
    """LSBs gate, as per ST06

    Efficient Binary Conversion for Paillier Encrypted Values
    Section 4 (pages 10 through 12)

        x is an encryption of an integer
        returns the list of the encrypted bits of x

    Alternatively, an iterable of integers (resp. iterable of iterable of
    integers...) can be provided and a list (resp. list of list of integers,
    ...) will be returned.
    """
    x_batch = list(x_batch)

    # generate r_*
    r_star_batch = random_integer_gate_batched(
        [2**security_parameter]*len(x_batch)
    )
    # the n_bits first bits of r are published encrypted individually
    encrypted_r_bits_flat = random_bit_gate_batched(len(x_batch) * n_bits)
    encrypted_r_bits_batch = [
        encrypted_r_bits_flat[i*n_bits:(i+1)*n_bits]
        for i in range(len(x_batch))
    ]
    # compute r = r_star 2**n_bits + \sum r_i 2**i
    r_batch = [
        r_star * (2**n_bits) + sum(encrypted_r_bits[i] * (2**i) for i in range(n_bits))
        for r_star, encrypted_r_bits in zip(r_star_batch, encrypted_r_bits_batch)
    ]

    # get clear bits of y = x - r
    y_batch = decrypt_gate_batched([x - r for x, r in zip(x_batch, r_batch)])
    y_bits_batch = [
        [(y >> i) & 1 for i in range(n_bits)]
        for y in y_batch
    ]

    # compute x = y + r using the encrypted bits of r and the clear bits of y
    return private_add_gate_batched(encrypted_r_bits_batch, y_bits_batch)


def conditional_gate_batched(x_batch, y_batch):
    """Conditional gate, as per ST04

    Practical Two-Party Computation Based on the Conditional Gate
    Section 3.2 (pages 7 through 10)

        x is an encryption of an integer
        y is an encryption of -1 or 1
        returns x * y
    """
    global n_conditional_gate, d_conditional_gate
    n_conditional_gate += len(x_batch)
    d_conditional_gate += 1

    x_batch, y_batch = list(x_batch), list(y_batch)
    assert len(x_batch) == len(y_batch)

    for _ in range(n_parties):
        for i in range(len(x_batch)):
            r = random.choice([-1, 1])
            x_batch[i] *= r
            y_batch[i] *= r
    clear_y_batch = decrypt_gate_batched(y_batch)
    return [x * clear_y for x, clear_y in zip(x_batch, clear_y_batch)]


def and_gate_batched(x_batch, y_batch):
    """Extended and gate

        x is an encryption of an integer
        y is an encryption of 0 or 1
        returns x if y = 1 else 0

    When x is 0 or 1, acts as a normal and gate"""
    y_as_one_or_minus_one_batch = [2*y-1 for y in y_batch]
    x_or_minus_x_batch = conditional_gate_batched(x_batch, y_as_one_or_minus_one_batch)
    return [halve(x_or_minus_x + x) for x_or_minus_x, x in zip(x_or_minus_x_batch, x_batch)]


def big_and_batched(bits_batch):
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
        result_flat = and_gate_batched(left_flat, right_flat)

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


def gt_gate_batched(x_batch, y_batch):
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
    x_and_y_flat = and_gate_batched(x_flat, y_flat)

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
        left_hand_addition_batch = and_gate_batched(parenthesis_batch, ti_batch)
        ti_batch = [
            left_hand_addition + x[i] - x_and_y[i]
            for left_hand_addition, x, x_and_y in zip(left_hand_addition_batch, x_batch, x_and_y_batch)
        ]
        # we exploit the fact that all the integers to compare are of the same
        # length, otherwise, we would need to keep track of whose bits are
        # being sent to the and_gate

    if debug_level >= 4:
        for x, y, ti in zip(x_batch, y_batch, ti_batch):
            print('{} > {} -> {}'.format(decrypt(x), decrypt(y), decrypt(ti)))
    return ti_batch


def decrypt(x):
    """Debug helper: decrypt values, lists of values, lists of lists, ..."""
    if x is None:
        return None
    try:
        x = iter(x)
    except TypeError:
        pass
    else:
        return [decrypt(value) for value in x]
    return private_key.decrypt(x)


def compute_is_left_right_to_median(A, n_bits):
    # not very Pythonic but let's keep it simple for now
    n_candidates = len(A)
    n_choices = len(A[0])

    total_sum_of_candidate = [sum(row) for row in A]
    doubled_partial_sums_of_candidate = [
        [2*sum(row[:j]) for j in range(1, len(row))]
        for row in A
    ]

    if debug_level >= 2:
        print('A =', decrypt(A))

    if debug_level >= 3:
        print('total_sum_of_candidate =', decrypt(total_sum_of_candidate))
        print('doubled_partial_sums_of_candidate =', decrypt(doubled_partial_sums_of_candidate))

    # flatten total_sum_of_candidate and doubled_partial_sums_of_candidate together
    flattened = total_sum_of_candidate + \
        [x for row in doubled_partial_sums_of_candidate for x in row]
    # switch to binary representation
    flattened = lsbs_batched(flattened, n_bits)
    # unflatten
    total_sum_of_candidate = flattened[:n_candidates]
    doubled_partial_sums_of_candidate = flattened[n_candidates:]

    # compare medians and partial sums to detect which values are left to the
    # best median and which are right to the best median
    is_right_to_candidate_median = gt_gate_batched(
        doubled_partial_sums_of_candidate,  # already flattened
        [
            total_sum_of_candidate[candidate]
            for candidate in range(n_candidates)
            for _ in range(n_choices-1)
        ]
    )
    # unflatten
    is_right_to_candidate_median = [
        is_right_to_candidate_median[candidate*(n_choices-1):(candidate+1)*(n_choices-1)]
        for candidate in range(n_candidates)
    ]
    is_right_to_median = big_and_batched([
        [
            is_right_to_candidate_median[candidate][choice]
            for candidate in range(n_candidates)
        ] for choice in range(n_choices-1)
    ])
    is_left_to_median = [ONE - v for v in is_right_to_median]

    if debug_level >= 3:
        print('is_right_to_candidate_median =', decrypt(is_right_to_candidate_median))
        print('is_left_to_median =', decrypt(is_left_to_median))
        print('is_right_to_median =', decrypt(is_right_to_median))

    return is_left_to_median, is_right_to_median


def compute_T(A, is_left_to_median, is_right_to_median):
    # not very Pythonic but let's keep it simple for now
    n_candidates = len(A)
    n_choices = len(A[0])

    conditioned_terms = and_gate_batched(
        [
            A[candidate][choice]
            for candidate in range(n_candidates)
            for choice in range(n_choices-1)
        ] + [
            A[candidate][choice]
            for candidate in range(n_candidates)
            for choice in range(1, n_choices)
        ],
        is_left_to_median * n_candidates + is_right_to_median * n_candidates
    )
    T = [
        sum(conditioned_terms[candidate*(n_choices-1):(candidate+1)*(n_choices-1)])
        for candidate in range(n_candidates*2)
    ]

    if debug_level >= 2:
        print('T =', decrypt(T))

    return T


def compute_winner(T, n_bits):
    assert len(T) % 2 == 0
    # not very Pythonic but let's keep it simple for now
    n_candidates = len(T) // 2

    T_elimination, T_victory = T[:n_candidates], T[n_candidates:]

    left_challenger = [
        T_victory[candidate]
        for candidate in range(n_candidates)
        for other_candidate in range(candidate)
    ]
    right_challenger = [
        T_victory[other_candidate]
        for candidate in range(n_candidates)
        for other_candidate in range(candidate)
    ]
    # batch together comparisons for self-elimination and for challenges
    comparisons = gt_gate_batched(
        T_elimination + left_challenger,
        T_victory + right_challenger
    )
    self_elimination = comparisons[:n_candidates]
    # extend triangular comparison matrix to full matrix
    challenges = [[None]*n_candidates for _ in range(n_candidates)]
    i_comparison = n_candidates
    for candidate in range(n_candidates):
        for other_candidate in range(candidate):
            comparison = comparisons[i_comparison]
            challenges[candidate][other_candidate] = comparison
            challenges[other_candidate][candidate] = ONE - comparison
            i_comparison += 1

    if debug_level >= 3:
        print('comparisons =', decrypt(comparisons))
        print('challenges =', decrypt(challenges))

    # batch challenge results (challenge did happen and was lost)
    challenge_results = and_gate_batched(
        [
            ONE - self_elimination[other_candidate]
            for candidate in range(n_candidates)
            for other_candidate in range(n_candidates)
            if other_candidate != candidate
        ],
        [
            challenges[other_candidate][candidate]
            for candidate in range(n_candidates)
            for other_candidate in range(n_candidates)
            if other_candidate != candidate
        ]
    )

    if debug_level >= 3:
        print('challenge_results =', decrypt(challenge_results))

    # explicit formula (sum of simple ands version)
    lose_batch = [
        self_elimination[candidate] + sum(
            challenge_results[candidate*(n_candidates-1):(candidate+1)*(n_candidates-1)]
        )
        for candidate in range(n_candidates)
    ]

    if debug_level >= 3:
        print('lose_batch =', decrypt(lose_batch))

    # reveal whether lose is null or not (masking with random number)
    r_batch = [random.randrange(1, 2**n_bits) for _ in range(n_candidates)]
    clear_lose_batch = decrypt_gate_batched([
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


def run_majority_judgement(A, n_bits):
    is_left_to_median, is_right_to_median = compute_is_left_right_to_median(A, n_bits)
    T = compute_T(A, is_left_to_median, is_right_to_median)
    T = lsbs_batched(T, n_bits)  # switch to binary representation again
    return compute_winner(T, n_bits)


def clear_majority_judgement(A):
    # not very Pythonic but let's keep it simple for now
    n_candidates = len(A)
    n_choices = len(A[0])

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
    A = [[public_key.encrypt(value) for value in row] for row in clear_A]
    if debug_level >= 3:
        print('A =', clear_A)

    if debug_level >= 2:
        print('Running majority judgement in the clear')
    clear_winner = clear_majority_judgement(clear_A)
    if debug_level >= 1:
        print('Clear protocol winner is', clear_winner)

    global n_conditional_gate, d_conditional_gate
    global n_random_integer_gate, d_random_integer_gate
    global n_random_bit_gate, d_random_bit_gate
    global n_decrypt_gate, d_decrypt_gate
    n_conditional_gate, d_conditional_gate = 0, 0
    n_random_integer_gate, d_random_integer_gate = 0, 0
    n_random_bit_gate, d_random_bit_gate = 0, 0
    n_decrypt_gate, d_decrypt_gate = 0, 0

    if debug_level >= 2:
        print('Running majority judgement encrypted')
    winner = run_majority_judgement(A, n_bits)
    if debug_level >= 1:
        print('Encrypted protocol winner is', winner)

    # show calls to oracles
    if debug_level >= 1:
        print('{} conditional gates (depth: {})'.format(n_conditional_gate, d_conditional_gate))
        print('{} random integer gates (depth: {})'.format(n_random_integer_gate, d_random_integer_gate))
        print('{} random bit gates (depth: {})'.format(n_random_bit_gate, d_random_bit_gate))
        print('{} decrypt gates (depth: {})'.format(n_decrypt_gate, d_decrypt_gate))

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
