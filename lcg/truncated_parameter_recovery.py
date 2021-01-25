from itertools import combinations
from math import ceil
from math import gcd
from math import sqrt

from sage.all import QQ
from sage.all import ZZ
from sage.all import Zmod
from sage.all import crt
from sage.all import factor
from sage.all import matrix
from sage.all import vector


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
    V = []
    for i in range(n):
        Vi = vector(ZZ, [y[i + j + 1] - y[i + j] for j in range(t)])
        V.append(Vi)

    L = matrix(ZZ, n, t + n)
    for i in range(n):
        for j in range(t):
            L[i, j] = V[i][j]

        L[i, t + i] = 1

    L = L.LLL()

    x = ZZ["x"].gen()
    for row in L.rows():
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


# Generates possible values for the modulus, multiplier, increment, and states.
# This is similar to the Hidden Number Problem, but with two 'global' unknowns.
def _recover_increment_and_states(outputs, state_bitsize, output_bitsize, modulus, multiplier):
    B = 2 ** (state_bitsize - output_bitsize)
    mult1 = multiplier
    mult2 = 1

    # Adapted from the code to solve the Hidden Number Problem using a lattice attack.
    m = len(outputs)
    M = matrix(QQ, m + 3, m + 3)
    for i in range(m):
        M[i, i] = modulus
        M[m, i] = mult1
        M[m + 1, i] = mult2
        # Adding B // 2 improves the quality of the results.
        M[m + 2, i] = (-(B * outputs[i] + B // 2)) % modulus
        mult1 = (multiplier * mult1) % modulus
        mult2 = (multiplier * mult2 + 1) % modulus
    M[m, m] = B / QQ(modulus)
    M[m + 1, m + 1] = B / QQ(modulus)
    M[m + 2, m] = 0
    M[m + 2, m + 1] = 0
    M[m + 2, m + 2] = B

    L = M.LLL()

    for row in L.rows():
        seed = (int(row[m] * modulus) // B) % modulus
        increment = (int(row[m + 1] * modulus) // B) % modulus
        if seed != 0 and increment != 0 and row[m + 2] == B:
            states = []
            for i in range(len(outputs)):
                states.append((B * outputs[i] + B // 2 + int(row[i])))
            yield modulus, multiplier, increment, states
            break


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
    :return: a generator generating possible parameters (tuples of modulus, multiplier, increment, and states) of truncated the LCG.
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
                yield from _recover_increment_and_states(outputs, state_bitsize, output_bitsize, possible_modulus, possible_multiplier)

            t += 1
            n = ceil(sqrt(2 * alpha * t * state_bitsize))
            chunk_size = n + t
    else:
        yield from _recover_increment_and_states(outputs, state_bitsize, output_bitsize, modulus, multiplier)
