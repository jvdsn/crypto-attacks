import logging
import os
import sys
from math import ceil
from math import floor

from sage.all import ZZ
from sage.all import Zmod

path = os.path.dirname(os.path.dirname(os.path.dirname(os.path.realpath(os.path.abspath(__file__)))))
if sys.path[1] != path:
    sys.path.insert(1, path)

from shared.small_roots import coron_direct
from shared.small_roots import howgrave_graham


def factorize_univariate(N, bitsize, msb_known, msb, lsb_known, lsb, beta=0.5):
    """
    Recovers the prime factors from a modulus using Coppersmith's method.
    :param N: the modulus
    :param bitsize: the amount of bits of the target prime factor
    :param msb_known: the amount of known most significant bits of the target prime factor
    :param msb: the known most significant bits of the target prime factor
    :param lsb_known: the amount of known least significant bits of the target prime factor
    :param lsb: the known least significant bits of the target prime factor
    :param beta: the beta value: the target prime factor is less than or equal to N^beta (default: 0.5)
    :return: a tuple containing the prime factors
    """
    x = Zmod(N)["x"].gen()
    f = msb * 2 ** (bitsize - msb_known) + x * 2 ** lsb_known + lsb
    X = 2 ** (bitsize - msb_known - lsb_known)
    d = f.degree()
    m = ceil(max(beta ** 2 / d, 7 * beta / d))
    while True:
        t = floor(d * m * (1 / beta - 1))
        logging.info(f"Trying m = {m}, t = {t}...")
        for x0, in howgrave_graham.modular_univariate(f, N, m, t, X):
            p = int(f(x0))
            if p != 0 and N % p == 0:
                return p, N // p

        m += 1


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
