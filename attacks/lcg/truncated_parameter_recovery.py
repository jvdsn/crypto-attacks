import logging
import os
import sys
from itertools import combinations
from math import ceil
from math import gcd
from math import sqrt

from sage.all import ZZ
from sage.all import Zmod
from sage.all import factor
from sage.all import matrix

path = os.path.dirname(os.path.dirname(os.path.dirname(os.path.realpath(os.path.abspath(__file__)))))
if sys.path[1] != path:
    sys.path.insert(1, path)

from attacks.hnp import lattice_attack
from shared.lattice import shortest_vectors
from shared.polynomial import polynomial_gcd_crt


# Section 2.1 in "On Stern's Attack Against Secret Truncated Linear Congruential Generators".
def _generate_polynomials(y, n, t):
    B = matrix(ZZ, n, n + t)
    for i in range(n):
        for j in range(t):
            B[i, j] = y[i + j + 1] - y[i + j]

        B[i, t + i] = 1

    x = ZZ["x"].gen()
    for v in shortest_vectors(B):
        P = 0
        for i, l in enumerate(v[t:]):
            P += l * x ** i
        yield P


# Section 4 in "On Stern's Attack Against Secret Truncated Linear Congruential Generators".
def _recover_modulus_and_multiplier(polynomials, m=None, a=None, check_modulus=None):
    for comb in combinations(polynomials, 3):
        P0 = comb[0]
        P1 = comb[1]
        P2 = comb[2]
        m_ = gcd(P0.resultant(P1), P1.resultant(P2), P0.resultant(P2))
        if (m is None and check_modulus(m_)) or m_ == m:
            if a is None:
                factors = factor(m_)
                g = polynomial_gcd_crt(P0, polynomial_gcd_crt(P1, P2, factors), factors)
                for a_ in g.change_ring(Zmod(m_)).roots(multiplicities=False):
                    yield int(m_), int(a_)
            else:
                yield int(m_), a


# Generates possible values for the modulus, multiplier, increment, and seed.
# This is similar to the Hidden Number Problem, but with two 'global' unknowns.
def _recover_increment_and_seed(y, k, s, m, a):
    a_ = []
    b_ = []
    X = 2 ** (k - s)
    mult1 = a
    mult2 = 1
    for i in range(len(y)):
        a_.append([mult1, mult2])
        b_.append(-X * y[i])
        mult1 = (a * mult1) % m
        mult2 = (a * mult2 + 1) % m

    for _, (x0_, c_) in lattice_attack.attack(a_, b_, m, X):
        yield m, a, c_, x0_


def attack(y, k, s, m=None, a=None, check_modulus=None):
    """
    Recovers possible parameters and states from a truncated linear congruential generator.
    More information: Contini S., Shparlinski I. E., "On Stern's Attack Against Secret Truncated Linear Congruential Generators"
    If no modulus is provided, attempts to recover a modulus from the outputs.
    If no multiplier is provided, attempts to recover a multiplier from the outputs.
    Also recovers an increment from the outputs.
    The resulting parameters may not match the original parameters, but the generated sequence should be the same up to some small error.
    :param y: the sequential output values obtained from the truncated LCG (the states truncated to s most significant bits)
    :param k: the bit length of the states
    :param s: the bit length of the outputs
    :param m: the modulus of the LCG (can be None)
    :param a: the multiplier of the LCG (can be None)
    :param check_modulus: a function which checks if a possible value can be the modulus (default: compare the bit length with k)
    :return: a generator generating possible parameters (tuples of modulus, multiplier, increment, and seed) of the truncated LCG
    """
    if m is None or a is None:
        alpha = s / k
        t = int(1 / alpha)
        n = ceil(sqrt(2 * alpha * t * k))

        # We start at the minimum useful chunk size.
        chunk_size = n + t
        while chunk_size <= len(y):
            logging.info(f"Trying chunk size {chunk_size}...")
            polynomials = []
            for i in range(len(y) // chunk_size):
                logging.info(f"Generating polynomials for n = {n}, t = {t}...")
                for P in _generate_polynomials(y[chunk_size * i:chunk_size * (i + 1)], n, t):
                    polynomials.append(P)

            logging.info("Recovering modulus and multiplier...")
            for m_, a_ in _recover_modulus_and_multiplier(polynomials, m, a, check_modulus or (lambda m_: m_.bit_length() == k)):
                logging.info("Recovering increment and seed...")
                yield from _recover_increment_and_seed(y, k, s, m_, a_)

            t += 1
            n = ceil(sqrt(2 * alpha * t * k))
            chunk_size = n + t
    else:
        logging.info("Recovering increment and seed...")
        yield from _recover_increment_and_seed(y, k, s, m, a)
