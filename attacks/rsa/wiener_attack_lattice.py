import logging
import os
import sys
from math import isqrt

from sage.all import ZZ
from sage.all import matrix

path = os.path.dirname(os.path.dirname(os.path.dirname(os.path.realpath(os.path.abspath(__file__)))))
if sys.path[1] != path:
    sys.path.insert(1, path)

from attacks.factorization import known_phi
from shared.lattice import shortest_vectors
from shared.small_roots import aono


def attack(N, e):
    """
    Recovers the prime factors of a modulus and the private exponent if the private exponent is too small.
    More information: Nguyen P. Q., "Public-Key Cryptanalysis"
    :param N: the modulus
    :param e: the public exponent
    :return: a tuple containing the prime factors and the private exponent, or None if the private exponent was not found
    """
    s = isqrt(N)
    L = matrix(ZZ, [[e, s], [N, 0]])

    for v in shortest_vectors(L):
        d = v[1] // s
        k = abs(v[0] - e * d) // N
        d = abs(d)
        if pow(pow(2, e, N), d, N) != 2:
            continue

        phi = (e * d - 1) // k
        factors = known_phi.factorize(N, phi)
        if factors:
            return *factors, int(d)


def attack_multiple_exponents(N, e, d_bit_length, m=1):
    """
    Recovers the prime factors of a modulus given multiple public exponents with small corresponding private exponents.
    More information: Aono Y., "Minkowski sum based lattice construction for multivariate simultaneous Coppersmith’s technique and applications to RSA" (Section 4)
    :param N: the modulus
    :param e: the public exponent
    :param d_bit_length: the bit length of the private exponents
    :param m: the m value to use for the small roots method (default: 1)
    :return: a tuple containing the prime factors, or None if the prime factors were not found
    """
    l = len(e)
    assert len(set(e)) == l, "All public exponents must be distinct"
    assert l >= 1, "At least one public exponent is required."

    pr = ZZ[",".join(f"x{i}" for i in range(l)) + ",y"]
    gens = pr.gens()
    x = gens[:-1]
    y = gens[-1]
    F = [-1 + x[k] * (y + N) for k in range(l)]
    X = [2 ** d_bit_length for _ in range(l)]
    Y = 3 * isqrt(N)
    logging.info(f"Trying m = {m}...")
    for roots in aono.integer_multivariate(F, e, m, X + [Y]):
        phi = roots[y] + N
        factors = known_phi.factorize(N, phi)
        if factors:
            return factors
