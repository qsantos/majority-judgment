#!/usr/bin/env python
class MPCGates:
    """MultiParty Computation Gates

    Implement building blocks for more complex programs in the context of
    multiparty computation. The gates delegate the notion of parties or network
    to protocols (see the `mpcprotocols` module).
    """
    def __init__(self, protocols):
        """Constructor

        Arguments:
            protocols: an object implementing the `decrypt_gate_batched()` and
                `random_negate_batched()` methods (see `mpcprotocols` module).
        """
        self.protocols = protocols

    def conditional_gate_batched(self, x_batch, y_batch):
        """Conditional gate, as per ST04

        Practical Two-Party Computation Based on the Conditional Gate
        Section 3.2 (pages 7 through 10)

            x is an encryption of an integer
            y is an encryption of -1 or 1
            returns x * y
        """
        x_batch, y_batch = self.protocols.random_negate_batched(x_batch, y_batch)
        clear_y_batch = self.protocols.decrypt_batched(y_batch)
        assert all(y in [-1, 1] for y in clear_y_batch)
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
        ciphertext_batch = [x[0]*y[0] for x, y in zip(x_batch, y_batch)]  # xi & yi

        # rest of the bits (one and_gate per bit)
        for i in range(1, len(x_batch[0])):
            xi_xor_yi_batch = [
                x[i] + y[i] - 2*x[i]*y[i]  # xi ^ yi
                for x, y in zip(x_batch, y_batch)
            ]
            xi_xor_yi_and_c_batch = \
                self.and_gate_batched(xi_xor_yi_batch, ciphertext_batch)
            for k in range(len(x_batch)):
                xi_xor_yi = xi_xor_yi_batch[k]
                xi_xor_yi_and_c = xi_xor_yi_and_c_batch[k]
                c = ciphertext_batch[k]
                xi = x_batch[k][i]
                yi = y_batch[k][i]

                r = xi_xor_yi + c - 2*xi_xor_yi_and_c
                ciphertext_batch[k] = (xi + yi + c - r) / 2
                ret_batch[k].append(r)
        return ret_batch

    def bit_extraction_gate_batched(self, n_bits, x_batch):
        """Bit extraction gate, as per ST06 (LSBs gate)

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
            [self.random_bits.pop() for _ in range(n_bits)]
            for _ in x_batch
        ]
        # compute r = r_star 2**n_bits + \sum r_i 2**i
        r_batch = [
            r_star * (2**n_bits) + sum(
                r_bits[i] * (2**i) for i in range(n_bits)
            )
            for r_star, r_bits in zip(r_star_batch, r_bits_batch)
        ]

        # get clear bits of y = x - r
        y_batch = self.protocols.decrypt_batched([
            x - r
            for x, r in zip(x_batch, r_batch)
        ])
        y_bits_batch = [
            [(y >> i) & 1 for i in range(n_bits)]
            for y in y_batch
        ]

        # compute x = y + r using encrypted bits of r and clear bits of y
        return self.private_add_gate_batched(r_bits_batch, y_bits_batch)
