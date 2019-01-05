Installation
============

Debian
------

Install the Debian package `python3-gmpy2`.

Virtual environment
-------------------

Install the Debian packages `libgmp-dev libmpfr-dev libmpc-dev`. Then install
the Python package `gmpy2`.

Usage
=====

To simulate the protocol over a single host, use `__main__.py`. To run the
protocol over a network, first run `server.py` with the required number of
clients. Then, start each client in turn. Documentation for each executable can
be obtained with the `--help` flag.

Available options:

* debug: set verbosity
* parties: number of talliers in the protocol
* choices: number of possible grades for each candidate
* candidates: number of candidates in the elections
* bits: number of bits required to represent the number of voters
* simulations: how many times to run the simulation
* seed: random seed, useful for replay
* honest: in honest mode, skip cryptographic proofs

Limit
=====

* ballots are assumed to already be aggregated
* basic secret sharing is used instead of Shamir's Secret Sharing
* talliers coordinate through a single host

Code
====

Miscellaneous:

* `util.py`: various arithmetic utilities
* `tests.py`: unit tests

Encryption:

* `mock.py`: mock implementation of homomorphic encryption
* `paillier.py`: actual implementation of Paillier cryptosystem
* `ballot.py`: (aggregated) ballot encryption

MPC:

* `mpcgates.py`: basic MPC gates
* `mpcprotocols.py`: emulate MPC protocol on a single host
* `majorityjudgment.py`: overall voting protocol using MPC operations

Execution:

* `__main__.py`: run MPC Majority Judgemnt on a single host
* `network.py`: basic network utilities
* `server.py`: central server for MPC Majority Judgment
* `client.py`: client (tallier)
