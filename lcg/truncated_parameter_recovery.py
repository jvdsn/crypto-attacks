from itertools import combinations
from math import ceil
from math import gcd
from math import sqrt

from sage.all import ZZ
from sage.all import Zmod
from sage.all import crt
from sage.all import factor
from sage.all import matrix

from hnp import lattice_attack


# Euclid's algorithm for polynomials.
def _polynomial_gcd(a, b):
    assert a.base_ring() == b.base_ring()

    while b:
        try:
            a, b = b, a % b
        except (RuntimeError, ValueError):
            raise ArithmeticError("a or b is not invertible", a, b)

    return a


# Uses the Chinese Remainder Theorem to compute the polynomial gcd modulo a composite number.
def _polynomial_gcd_crt(a, b, modulus):
    gs = []
    ps = []
    for p, _ in factor(modulus):
        zmodp = Zmod(p)
        gs.append(_polynomial_gcd(a.change_ring(zmodp), b.change_ring(zmodp)).change_ring(ZZ))
        ps.append(p)

    return gs[0] if len(gs) == 1 else crt(gs, ps)


# Section 2.1 in "On Stern's Attack Against Secret Truncated Linear Congruential Generators".
def _generate_polynomials(y, n, t):
    B = matrix(ZZ, n, n + t)
    for i in range(n):
        for j in range(t):
            B[i, j] = y[i + j + 1] - y[i + j]

        B[i, t + i] = 1

    B = B.LLL()

    x = ZZ["x"].gen()
    for row in B.rows():
        P = 0
        for i, l in enumerate(row[t:]):
            P += l * x ** i
        yield P


# Generates possible values for the modulus and multiplier.
# Section 4 in "On Stern's Attack Against Secret Truncated Linear Congruential Generators".
def _recover_modulus_and_multiplier(polynomials, modulus_bitsize, modulus=None, multiplier=None):
    for combination in combinations(polynomials, 3):
        P0 = combination[0]
        P1 = combination[1]
        P2 = combination[2]
        possible_modulus = gcd(P0.resultant(P1), P1.resultant(P2), P0.resultant(P2))
        if (modulus is None and possible_modulus.bit_length() == modulus_bitsize) or possible_modulus == modulus:
            if multiplier is None:
                g = _polynomial_gcd_crt(P0, _polynomial_gcd_crt(P1, P2, possible_modulus), possible_modulus)
                for possible_multiplier in g.change_ring(Zmod(possible_modulus)).roots(multiplicities=False):
                    yield int(possible_modulus), int(possible_multiplier)
            else:
                yield int(possible_modulus), multiplier


# Generates possible values for the modulus, multiplier, increment, and seed.
# This is similar to the Hidden Number Problem, but with two 'global' unknowns.
def _recover_increment_and_seed(outputs, state_bitsize, output_bitsize, modulus, multiplier):
    a = []
    b = []
    X = 2 ** (state_bitsize - output_bitsize)
    mult1 = multiplier
    mult2 = 1
    for i in range(len(outputs)):
        a.append([mult1, mult2])
        b.append(-X * outputs[i])
        mult1 = (multiplier * mult1) % modulus
        mult2 = (multiplier * mult2 + 1) % modulus

    for _, params in lattice_attack.attack(a, b, modulus, X):
        yield modulus, multiplier, params[1], params[0]


def attack(outputs, state_bitsize, output_bitsize, modulus_bitsize, modulus=None, multiplier=None):
    """
    Recovers possible parameters and states from a truncated linear congruential generator.
    More information: Contini S., Shparlinski I. E., "On Stern's Attack Against Secret Truncated Linear Congruential Generators"
    If no modulus is provided, attempts to recover a modulus from the outputs.
    If no multiplier is provided, attempts to recover a multiplier from the outputs.
    Also recovers an increment from the outputs.
    The resulting parameters may not match the original parameters, but the generated sequence should be the same up to some small error.
    :param outputs: the sequential output values obtained from the truncated LCG (the states truncated to output_bitsize most significant bits)
    :param state_bitsize: the size in bits of the states
    :param output_bitsize: the size in bits of the outputs
    :param modulus_bitsize: the size in bits of the modulus
    :param modulus: the modulus of the LCG (can be None)
    :param multiplier: the multiplier of the LCG (can be None)
    :return: a generator generating possible parameters (tuples of modulus, multiplier, increment, and seed) of truncated the LCG.
    """
    if modulus is None or multiplier is None:
        alpha = output_bitsize / state_bitsize
        t = int(1 / alpha)
        n = ceil(sqrt(2 * alpha * t * state_bitsize))

        # We start at the minimum useful chunk size.
        chunk_size = n + t
        while chunk_size <= len(outputs):
            polynomials = []
            for i in range(len(outputs) // chunk_size):
                for P in _generate_polynomials(outputs[chunk_size * i:chunk_size * (i + 1)], n, t):
                    polynomials.append(P)

            for possible_modulus, possible_multiplier in _recover_modulus_and_multiplier(polynomials, modulus_bitsize, modulus, multiplier):
                yield from _recover_increment_and_seed(outputs, state_bitsize, output_bitsize, possible_modulus, possible_multiplier)

            t += 1
            n = ceil(sqrt(2 * alpha * t * state_bitsize))
            chunk_size = n + t
    else:
        yield from _recover_increment_and_seed(outputs, state_bitsize, output_bitsize, modulus, multiplier)
