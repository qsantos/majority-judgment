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

parser = argparse.ArgumentParser()
parser.description = 'Run majority judgement protocol using Paillier encrption'
parser.add_argument('--debug', '-d', default=1, type=int)
args = parser.parse_args()

# debug_level = 0: quiet
# debug_level = 1: normal output
# debug_level = 2: some intermediate values
# debug_level = 3: detailed intermediate values
# debug_level = 4: all comparisons as well
debug_level = args.debug

n_bits = 11  # NOTE: have enough bits for double partial sums!
n_lsbs = 0
n_parties = 8
n_conditional_gate = 0
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


def private_add_gate(x, y):
    """Add gate for encrypted x and clear y, both in binary representation

        x is a list of encrypted bits
        y is a list of bits
        return a list of encrypted bits representing the sum of x and y

    Note that the final carry is discarded
    """
    x, y = iter(x), iter(y)
    ret = []

    # first bit (no and_gate needed)
    xi, yi = next(x), next(y)
    ret = [xi + yi - 2*xi*yi]  # xi ^ yi
    c = xi*yi  # xi & yi

    # rest of the bits (one and_gate per bit)
    for xi, yi in zip(x, y):
        xi_xor_yi = xi + yi - 2*xi*yi
        r = xi_xor_yi + c - 2*and_gate(xi_xor_yi, c)
        c = halve(xi + yi + c - r)
        ret.append(r)
    return ret


def lsbs(x):
    """LSBs gate, as per ST06

    Efficient Binary Conversion for Paillier Encrypted Values
    Section 4 (pages 10 through 12)

        x is an encryption of an integer
        returns the list of the encrypted bits of x

    Alternatively, an iterable of integers (resp. iterable of iterable of
    integers...) can be provided and a list (resp. list of list of integers,
    ...) will be returned.
    """
    # overload for iterables
    try:
        x = iter(x)
    except TypeError:
        pass
    else:
        return [lsbs(value) for value in x]

    global n_lsbs
    n_lsbs += 1

    # generate r
    r = random.randrange(2**(n_bits + security_parameter))
    # the m first bits of r are published encrypted individually
    encrypted_r_bits = [[ZERO, ONE][(r >> i) & 1] for i in range(n_bits)]

    # get clear bits of y = x - r
    y = int(private_key.decrypt(x - public_key.encrypt(r)))
    y_bits = [(y >> i) & 1 for i in range(n_bits)]

    # compute x = y + r using the encrypted bits of r and the clear bits of y
    return private_add_gate(encrypted_r_bits, y_bits)


def conditional_gate(x, y):
    """Conditional gate, as per ST04

    Practical Two-Party Computation Based on the Conditional Gate
    Section 3.2 (pages 7 through 10)

        x is an encryption of an integer
        y is an encryption of -1 or 1
        returns x * y
    """
    global n_conditional_gate
    n_conditional_gate += 1

    for _ in range(n_parties):
        r = random.choice([-1, 1])
        x *= r
        y *= r
    return x * private_key.decrypt(y)


def and_gate(x, y):
    """Extended and gate

        x is an encryption of an integer
        y is an encryption of 0 or 1
        returns x if y = 1 else 0

    When x is 0 or 1, acts as a normal and gate"""
    return halve(conditional_gate(x, 2*y-1) + x)


def big_and(bits):
    """Reduce bits through and_gate"""
    bits = iter(bits)
    r = next(bits)
    for bit in bits:
        r = and_gate(r, bit)
    return r


def gt_gate(x, y):
    """Greater-than gate, as per ST04

    Practical Two-Party Computation Based on the Conditional Gate
    Section 5.2 (page 15)

        x is an encryption of an integer
        y is an encryption of an integer
        returns 1 if x > y else 0
    """
    x, y = iter(x), iter(y)

    # first bit (only one and_gate needed)
    xi, yi = next(x), next(y)
    xi_yi = and_gate(xi, yi)
    ti = xi - xi_yi

    # rest of the bits (two and_gate per bit)
    for xi, yi in zip(x, y):
        # ti = (1 - (xi - yi)**2) * ti + xi*(1-yi)
        #    = (1 - xi - yi + 2 xi yi) ti + xi - xi yi
        xi_yi = and_gate(xi, yi)
        ti = and_gate(1 - xi - yi + 2*xi_yi, ti) + xi - xi_yi
    if debug_level >= 4:
        print('{} > {} -> {}'.format(decrypt(x), decrypt(y), decrypt(ti)))
    return ti


def decrypt(x):
    """Debug helper: decrypt values, lists of values, lists of lists, ..."""
    try:
        x = iter(x)
    except TypeError:
        pass
    else:
        return [decrypt(value) for value in x]
    return private_key.decrypt(x)


# assume that A has been computed as the sum of the individual ballots
clear_A = [
    [12, 68, 417, 104, 28],
    [7, 99, 221, 71, 29],
    [301, 107, 58, 16, 2],
]
A = [[public_key.encrypt(value) for value in row] for row in clear_A]
# not very Pythonic but let's keep it simple for now
n_candidates = len(A)
n_choices = len(A[0])

total_sum_of_candidate = [sum(row) for row in A]
doubled_partial_sums_of_candidate = [
    [2*sum(row[:j]) for j in range(1, len(row))]
    for row in A
]

assert len(total_sum_of_candidate) == n_candidates
assert len(doubled_partial_sums_of_candidate) == n_candidates
assert len(doubled_partial_sums_of_candidate[0]) == n_choices-1

if debug_level >= 2:
    print('A =', decrypt(A))

if debug_level >= 3:
    print('total_sum_of_candidate =', decrypt(total_sum_of_candidate))
    print('doubled_partial_sums_of_candidate =', decrypt(doubled_partial_sums_of_candidate))

# switch to binary representation
total_sum_of_candidate = lsbs(total_sum_of_candidate)
doubled_partial_sums_of_candidate = lsbs(doubled_partial_sums_of_candidate)

# compare medians and partial sums to detect which values are left to the
# best median and which are right to the best median
is_not_left_to_candidate_median = [
    [
        gt_gate(
            doubled_partial_sums_of_candidate[candidate][choice],
            total_sum_of_candidate[candidate]
        ) for choice in range(n_choices-1)
    ] + [ONE] for candidate in range(n_candidates)
]
is_right_to_candidate_median = [
    [ZERO] + [
        gt_gate(
            doubled_partial_sums_of_candidate[candidate][choice],
            total_sum_of_candidate[candidate]
        ) for choice in range(n_choices-1)
    ] for candidate in range(n_candidates)
]
is_not_left_to_median = [
    big_and(
        is_not_left_to_candidate_median[candidate][choice]
        for candidate in range(n_candidates)
    ) for choice in range(n_choices-1)
] + [ONE]
is_left_to_median = [ONE - v for v in is_not_left_to_median]
is_right_to_median = [ZERO] + [
    big_and(
        is_right_to_candidate_median[candidate][choice]
        for candidate in range(n_candidates)
    ) for choice in range(1, n_choices)
]

if debug_level >= 3:
    print('is_not_left_to_candidate_median =', decrypt(is_not_left_to_candidate_median))
    print('is_right_to_candidate_median =', decrypt(is_right_to_candidate_median))
    print('is_not_left_to_median =', decrypt(is_not_left_to_median))
    print('is_left_to_median =', decrypt(is_left_to_median))
    print('is_right_to_median =', decrypt(is_right_to_median))


# at this point, we have built is_left_to_median and is_right_to_median;
# by multiplying them to the values of A, we can construct T

# left column
T_elimination = [
    sum(
        and_gate(A[candidate][choice], is_left_to_median[choice])
        for choice in range(n_choices-1)
    ) for candidate in range(n_candidates)
]
# right column
T_victory = [
    sum(
        and_gate(A[candidate][choice], is_right_to_median[choice])
        for choice in range(1, n_choices)
    ) for candidate in range(n_candidates)
]

if debug_level >= 2:
    print('T_elimination =', decrypt(T_elimination))
    print('T_victory =', decrypt(T_victory))

# now that we have T, we switch to binary representation again
T_elimination = lsbs(T_elimination)
T_victory = lsbs(T_victory)
# here, the output could be El Gamal or BGN ciphers instead

# and now, it only remain to find the winner using the explicit formula
for candidate in range(n_candidates):
    # explicit formula (sum of simple ands version)
    lose = gt_gate(T_elimination[candidate], T_victory[candidate]) + sum(
        and_gate(
            gt_gate(T_victory[other_candidate], T_elimination[other_candidate]),
            gt_gate(T_victory[other_candidate], T_victory[candidate])
        )
        for other_candidate in range(n_candidates)
        if other_candidate != candidate
    )

    # reveal whether the result is null or not
    r = random.randrange(2**n_bits)  # should be secure random
    has_won = private_key.decrypt(lose * r) == 0
    if debug_level >= 1 and has_won:
        print('Candidate {} wins!'.format(candidate))

# show calls to oracles
if debug_level >= 1:
    print('{} LSBs invocations'.format(n_lsbs))
    print('{} conditional gates'.format(n_conditional_gate))
