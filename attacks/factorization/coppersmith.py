import logging
import os
import sys
from math import ceil
from math import floor
from math import log
from math import pi
from math import sqrt

from sage.all import ZZ
from sage.all import Zmod

import shared.small_roots

path = os.path.dirname(os.path.dirname(os.path.dirname(os.path.realpath(os.path.abspath(__file__)))))
if sys.path[1] != path:
    sys.path.insert(1, path)

from shared.small_roots import coron_direct
from shared.small_roots import herrmann_may_multivariate
from shared.small_roots import howgrave_graham


def factorize_p(N, partial_p, beta=0.5, epsilon=0.125, m=None, t=None):
    """
    Recover the prime factors from a modulus using Coppersmith's method and bits of one prime factor p are known.
    More information: May A., "New RSA Vulnerabilities Using Lattice Reduction Methods" (Section 3.2)
    More information: Herrmann M., May A., "Solving Linear Equations Modulo Divisors: On Factoring Given Any Bits" (Section 3 and 4)
    :param N: the modulus
    :param partial_p: the partial prime factor p (PartialInteger)
    :param beta: the parameter beta (default: 0.5)
    :param epsilon: the parameter epsilon (default: 0.125)
    :param m: the number of normal shifts to use (default: automatically computed using beta and epsilon)
    :param t: the number of additional shifts to use (default: automatically computed using beta and epsilon)
    :return: a tuple containing the prime factors, or None if the factors could not be found
    """
    n = partial_p.unknowns
    assert n > 0
    if n == 1:
        m = ceil(max(beta ** 2 / epsilon, 7 * beta)) if m is None else m
        t = floor(m * (1 / beta - 1)) if t is None else t
        small_roots = howgrave_graham.modular_univariate
    elif n == 2:
        m = ceil((3 * beta * (1 + sqrt(1 - beta))) / epsilon) if m is None else m
        t = floor(m * (1 - sqrt(1 - beta))) if t is None else t
        small_roots = herrmann_may_multivariate.modular_multivariate
    else:
        m = ceil((n * (1 / pi * (1 - beta) ** (-0.278465) - beta * log(1 - beta))) / epsilon) if m is None else m
        t = floor(m * (1 - (1 - beta) ** (1 / n))) if t is None else t
        small_roots = herrmann_may_multivariate.modular_multivariate

    x = Zmod(N)[tuple(f"x{i}" for i in range(n))].gens()
    f = partial_p.sub(x)
    X = partial_p.get_unknown_bounds()
    logging.info(f"Trying m = {m}, t = {t}...")
    for roots in small_roots(f, N, m, t, X):
        p = partial_p.sub(roots)
        if p != 0 and N % p == 0:
            return p, N // p

    return None


def factorize_bivariate(N, p_bitsize, p_msb_known, p_msb, p_lsb_known, p_lsb, q_bitsize, q_msb_known, q_msb, q_lsb_known, q_lsb, k_start=1):
    """
    Recovers the prime factors from a modulus using Coppersmith's method.
    For more complex combinations of known bits, the coron_direct module in the shared/small_roots package should be used directly.
    :param N: the modulus
    :param p_bitsize: the amount of bits of the first prime factor
    :param p_msb_known: the amount of known most significant bits of the first prime factor
    :param p_msb: the known most significant bits of the first prime factor
    :param p_lsb_known: the amount of known least significant bits of the first prime factor
    :param p_lsb: the known least significant bits of the first prime factor
    :param q_bitsize: the amount of bits of the second prime factor
    :param q_msb_known: the amount of known most significant bits of the second prime factor
    :param q_msb: the known most significant bits of the second prime factor
    :param q_lsb_known: the amount of known least significant bits of the second prime factor
    :param q_lsb: the known least significant bits of the second prime factor
    :param k_start: the k value to start at for the Coron small roots method (default: 1)
    :return: a tuple containing the prime factors
    """
    x, y = ZZ["x, y"].gens()
    f_p = p_msb * 2 ** (p_bitsize - p_msb_known) + x * 2 ** p_lsb_known + p_lsb
    f_q = q_msb * 2 ** (q_bitsize - q_msb_known) + y * 2 ** q_lsb_known + q_lsb
    f = f_p * f_q - N
    X = 2 ** (p_bitsize - p_msb_known - p_lsb_known)
    Y = 2 ** (q_bitsize - q_msb_known - q_lsb_known)
    k = k_start
    while True:
        logging.info(f"Trying k = {k}...")
        for x0, y0 in coron_direct.integer_bivariate(f, k, X, Y):
            p = int(f_p(x0, 0))
            q = int(f_q(0, y0))
            if p * q == N:
                return p, q

        k += 1
