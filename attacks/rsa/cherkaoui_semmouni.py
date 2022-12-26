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
    alpha = log(e, N)
    assert not check_bounds or delta < 2 - sqrt(2 * alpha * beta), "Bound check failed."

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
