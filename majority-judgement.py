#!/usr/bin/env python3
"""
Majority judgement using Paillier encryption

BITREP and the conditional gates are replaced with black-box oracles where the
values are decrypted, computation done in the clear, and the result
re-encrypted. The two oracles count the number of queries.

BITREP requires the input to be Paillier encryptions (cannot be adapted to El
Gamal or BGN). However, the output of the last BITREP can be El Gamal or BGN
encryption, so that the last conditional gates could be replaced by offline
pairings.

Depends on `phe` (avaliable through in PIP):
    <https://github.com/n1analytics/python-paillier>
"""
import phe
import random

# debug_level = 0: quiet
# debug_level = 1: normal output
# debug_level = 2: some intermediate values
# debug_level = 3: detailed intermediate values
# debug_level = 4: all comparisons as well
debug_level = 1

n_bits = 10
n_bitrep = 0
n_parties = 8
n_conditional_gate = 0

# public_key is used as a global to encrypt constants (0 or 1)
# private_key is used as a global to black-box gates and for debugging
public_key, private_key = phe.paillier.generate_paillier_keypair()




def bitrep(x):
    """BITREP gate, as per ST06

    Efficient Binary Conversion for Paillier Encrypted Values
    Section 5 (page 13), uses section 2 through 4 (pages 7 through 12)

        x is an encryption of an integer
        retunrns the list of the encrypted bits of x

    Alternatively, an iterable of integers (resp. iterable of iterable of
    integers...) can be provided and a list (resp. list of list of integers,
    ...) will be returned.
    """
    try:
        # overload for iterables
        return [bitrep(value) for value in x]
    except TypeError:
        global n_bitrep
        n_bitrep += 1

        cleartext = int(private_key.decrypt(x))
        return [
            public_key.encrypt((cleartext >> i) & 1) for i in range(n_bits)
        ]

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
    return (conditional_gate(x, 2*y-1) + x) / 2


def big_and(bits):
    """Reduce bits through and_gate"""
    bits = iter(bits)
    r = next(bits)
    for bit in bits:
        r = conditional_gate(r, bit)
    return r



def gt_gate(x, y):
    """Greater-than gate, as per ST04

    Practical Two-Party Computation Based on the Conditional Gate
    Section 5.2 (page 15)

        x is an encryption of an integer
        y is an encryption of an integer
        returns 1 if x > y else 0
    """
    ti = public_key.encrypt(0)
    for xi, yi in zip(x, y):
        # ti = (1 - (xi - yi)**2) * ti + xi*(1-yi)
        #    = (1 - xi - yi + 2 xi yi) ti + xi - xi yi
        xi_yi = and_gate(xi, yi)
        ti = and_gate(1 - xi - yi + 2*xi_yi, ti) + xi - xi_yi
    if debug_level >= 4:
        print('{} > {} -> {}'.format(decrypt(x), decrypt(y), decrypt(ti)))
    return ti


def decrypt(ciphertext):
    """Debug helper: decrypt values, lists of values, lists of lists, ..."""
    try:
        return [decrypt(value) for value in ciphertext]
    except TypeError:
        return private_key.decrypt(ciphertext)


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

median_of_candidate = [sum(row)/2 for row in A]
partial_sums_of_candidate = [
    [sum(row[:j]) for j in range(1, len(row))]
    for row in A
]

assert len(median_of_candidate) == n_candidates
assert len(partial_sums_of_candidate) == n_candidates
assert len(partial_sums_of_candidate[0]) == n_choices-1

if debug_level >= 2:
    print('A =', decrypt(A))

if debug_level >= 3:
    print('median_of_candidate =', decrypt(median_of_candidate))
    print('partial_sums_of_candidate =', decrypt(partial_sums_of_candidate))

# switch to binary representation
median_of_candidate = bitrep(median_of_candidate)
partial_sums_of_candidate = bitrep(partial_sums_of_candidate)

# compare medians and partial sums to detect which values are left to the
# best median and which are right to the best median
is_not_left_to_candidate_median = [
    [
        gt_gate(
            partial_sums_of_candidate[candidate][choice],
            median_of_candidate[candidate]
        ) for choice in range(n_choices-1)
    ] + [public_key.encrypt(1)]
    for candidate in range(n_candidates)
]
is_right_to_candidate_median = [
    [public_key.encrypt(0)] + [
        gt_gate(
            partial_sums_of_candidate[candidate][choice],
            median_of_candidate[candidate]
        ) for choice in range(n_choices-1)
    ]
    for candidate in range(n_candidates)
]
is_not_left_to_median = [
    big_and(
        is_not_left_to_candidate_median[candidate][choice]
        for candidate in range(n_candidates)
    ) for choice in range(n_choices)
]
is_left_to_median = [
    public_key.encrypt(1) - is_not_left_to_median[choice]
    for choice in range(n_choices)
]
is_right_to_median = [
    big_and(
        is_right_to_candidate_median[candidate][choice]
        for candidate in range(n_candidates)
    ) for choice in range(n_choices)
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
        for choice in range(n_choices)
    ) for candidate in range(n_candidates)
]
# right column
T_victory = [
    sum(
        and_gate(A[candidate][choice], is_right_to_median[choice])
        for choice in range(n_choices)
    ) for candidate in range(n_candidates)
]

if debug_level >= 2:
    print('T_elimination =', decrypt(T_elimination))
    print('T_victory =', decrypt(T_victory))

# now that we have T, we switch to binary representation again
T_elimination = bitrep(T_elimination)
T_victory = bitrep(T_victory)
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
    print('{} BITREP invocations'.format(n_bitrep))
    print('{} conditional gates'.format(n_conditional_gate))
