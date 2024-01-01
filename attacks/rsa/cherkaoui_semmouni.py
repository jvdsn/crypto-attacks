import logging
import os
import sys
from math import isqrt
from math import log
from math import sqrt

from sage.all import RR
from sage.all import ZZ

path = os.path.dirname(os.path.dirname(os.path.dirname(os.path.realpath(os.path.abspath(__file__)))))
if sys.path[1] != path:
    sys.path.insert(1, path)

from shared.small_roots import herrmann_may


def attack(N, e, beta, delta, m=1, t=None, check_bounds=True):
    """
    Recovers the prime factors of a modulus and the private exponent if |p - q| is sufficiently small.
    More information: Cherkaoui-Semmouni M. et al., "Cryptanalysis of RSA Variants with Primes Sharing Most Significant Bits"
    :param N: the modulus
    :param e: the exponent
    :param beta: the parameter beta such that |p - q| <= N^beta
    :param delta: the parameter delta such that d <= N^delta
    :param m: the m value to use for the small roots method (default: 1)
    :param t: the t value to use for the small roots method (default: automatically computed using m)
    :param check_bounds: perform bounds check (default: True)
    :return: a tuple containing the prime factors and the private exponent, or None if the factors could not be found
    """
    alpha = log(e, N)
    assert not check_bounds or delta < 2 - sqrt(2 * alpha * beta), f"Bounds check failed ({delta} < {2 - sqrt(2 * alpha * beta)})."

    x, y = ZZ["x", "y"].gens()
    A = -(N - 1) ** 2
    f = x * y + A * x + 1
    X = int(2 * e * RR(N) ** (delta - 2))  # Equivalent to 2N^(alpha + delta - 2)
    Y = int(RR(N) ** (2 * beta))
    t = int((2 - delta - 2 * beta) / (2 * beta) * m) if t is None else t
    logging.info(f"Trying m = {m}, t = {t}...")
    for x0, y0 in herrmann_may.modular_bivariate(f, e, m, t, X, Y):
        s = isqrt(y0)
        d = s ** 2 + 4 * N
        p = int(-s + isqrt(d)) // 2
        q = int(s + isqrt(d)) // 2
        d = int(f(x0, y0) // e)
        return p, q, d

    return None
