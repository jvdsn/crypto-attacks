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
