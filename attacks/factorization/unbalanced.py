import logging
import os
import sys

from sage.all import Zmod

path = os.path.dirname(os.path.dirname(os.path.dirname(os.path.realpath(os.path.abspath(__file__)))))
if sys.path[1] != path:
    sys.path.insert(1, path)

from shared.small_roots import herrmann_may


def factorize(N, W, L, v, Q, m_start=1):
    """
    Recovers the prime factors from a modulus if the modulus is unbalanced and bits are known.
    More information: Brier E. et al., "Factoring Unbalanced Moduli with Known Bits" (Section 4)
    :param N: the modulus: N = p * q > q ** 3
    :param W: the amount of unknown least significant bits of p
    :param L: the amount of known bits of p
    :param v: the known bits of p: p = u * 2^(W + L) + v * 2^W + y
    :param Q: the amount of bits of q
    :param m_start: the m value to start at for the small roots method (default: 1)
    :return: a tuple containing the prime factors
    """
    assert 3 * L ** 2 + (4 * W - 6 * Q) * L + 3 * Q ** 2 - 8 * Q * W > 0, "Bound check failed."
    delta = Q / (W + L)

    x, y = Zmod(2 ** (W + L))["x, y"].gens()
    a = v * 2 ** W
    f = x * (a + y) - N
    X = 2 ** Q
    Y = 2 ** W
    m = m_start
    while True:
        t = int((1 - 2 * delta) * m)
        logging.info(f"Trying m = {m}, t = {t}...")
        for x0, y0 in herrmann_may.modular_bivariate(f, 2 ** (W + L), m, t, X, Y):
            q = x0
            if q != 0 and N % q == 0:
                return N // q, q

        m += 1
