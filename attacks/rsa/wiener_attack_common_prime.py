import logging
import os
import sys
from math import log
from math import sqrt

from sage.all import RR
from sage.all import ZZ

path = os.path.dirname(os.path.dirname(os.path.dirname(os.path.realpath(os.path.abspath(__file__)))))
if sys.path[1] != path:
    sys.path.insert(1, path)

from shared.small_roots import jochemsz_may_integer


def attack(N, e, delta=0.25, m=1, t=None, check_bounds=True):
    """
    Recovers the prime factors of a modulus and the private exponent if the private exponent is too small (Common Prime RSA version).
    More information: Jochemsz E., May A., "A Strategy for Finding Roots of Multivariate Polynomials with New Applications in Attacking RSA Variants" (Section 5)
    :param N: the modulus
    :param e: the public exponent
    :param delta: a predicted bound on the private exponent (d < N^delta) (default: 0.25)
    :param m: the m value to use for the small roots method (default: 1)
    :param t: the t value to use for the small roots method (default: automatically computed using m)
    :param check_bounds: perform bounds check (default: True)
    :return: a tuple containing the prime factors and the private exponent, or None if the private exponent was not found
    """
    gamma = 1 - log(e, N)
    assert not check_bounds or delta <= 1 / 4 * (4 + 4 * gamma - sqrt(13 + 20 * gamma + 4 * gamma ** 2)), "Bounds check failed."

    x, y, z = ZZ["x", "y", "z"].gens()
    f = e ** 2 * x ** 2 + e * x * (y + z - 2) - (y + z - 1) - (N - 1) * y * z
    X = int(RR(N) ** delta)
    Y = int(RR(N) ** (delta - 1 / 2) * e)  # Equivalent to N^(delta + 1 / 2 - gamma)
    Z = int(RR(N) ** (delta - 1 / 2) * e)  # Equivalent to N^(delta + 1 / 2 - gamma)
    W = int(RR(N) ** (2 * delta) * e ** 2)  # Equivalent to N^(2 * delta + 2 - 2 * gamma)
    t = int((1 / 2 + gamma - 4 * delta) / (2 * delta) * m) if t is None else t
    logging.info(f"Trying m = {m}, t = {t}...")
    strategy = jochemsz_may_integer.ExtendedStrategy([t, 0, 0])
    for x0, y0, z0 in jochemsz_may_integer.integer_multivariate(f, m, W, [X, Y, Z], strategy):
        d = x0
        ka = y0
        kb = z0
        if pow(pow(2, e, N), d, N) == 2:
            p = (e * d - 1) // kb + 1
            q = (e * d - 1) // ka + 1
            return p, q, d

    return None
