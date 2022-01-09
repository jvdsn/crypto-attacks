import os
import sys
from math import gcd

from sage.all import ZZ
from sage.all import matrix

path = os.path.dirname(os.path.dirname(os.path.dirname(os.path.realpath(os.path.abspath(__file__)))))
if sys.path[1] != path:
    sys.path.insert(1, path)

from shared.lattice import shortest_vectors


def _recover_factors(L, N):
    for v in shortest_vectors(L):
        factors = []
        for i, Ni in enumerate(N):
            qi = gcd(v[i], Ni)
            if 1 < qi < Ni and Ni % qi == 0:
                factors.append((Ni // qi, qi))

        if len(factors) == len(N):
            return factors


def factorize_msb(N, n, t):
    """
    Factorizes the moduli when some most significant bits are equal among multiples of a prime factor.
    More information: Nitaj A., Ariffin MRK., "Implicit factorization of unbalanced RSA moduli" (Section 4)
    :param N: the moduli
    :param n: the bit length of the moduli
    :param t: the number of shared most significant bits
    :return: a list containing a tuple of the factors of each modulus, or None if the factors were not found
    """
    L = matrix(ZZ, len(N), len(N))
    L[0, 0] = 2 ** (n - t)
    for i in range(1, len(N)):
        L[0, i] = N[i]

    for i in range(1, len(N)):
        L[i, i] = -N[0]

    return _recover_factors(L, N)


def factorize_lsb(N, n, t):
    """
    Factorizes the moduli when some least significant bits are equal among multiples of a prime factor.
    More information: Nitaj A., Ariffin MRK., "Implicit factorization of unbalanced RSA moduli" (Section 6)
    :param N: the moduli
    :param n: the bit length of the moduli
    :param t: the number of shared least significant bits
    :return: a list containing a tuple of the factors of each modulus, or None if the factors were not found
    """
    L = matrix(ZZ, len(N), len(N))
    L[0, 0] = 1
    for i in range(1, len(N)):
        L[0, i] = N[i] * pow(N[0], -1, 2 ** t) % (2 ** t)

    for i in range(1, len(N)):
        L[i, i] = -2 ** t

    return _recover_factors(L, N)
