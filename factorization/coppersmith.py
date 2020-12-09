import logging
from math import ceil
from math import floor

from sage.all import ZZ
from sage.all import Zmod

from small_roots.coron import integer_bivariate
from small_roots.howgrave_graham import modular_univariate


def factorize_univariate(n, bitsize, msb_known, msb, lsb_known, lsb, beta=0.5):
    """
    Recovers the prime factors from a modulus using Coppersmith's method.
    :param n: the modulus
    :param bitsize: the amount of bits of the target prime factor
    :param msb_known: the amount of known most significant bits of the target prime factor
    :param msb: the known most significant bits of the target prime factor
    :param lsb_known: the amount of known least significant bits of the target prime factor
    :param lsb: the known least significant bits of the target prime factor
    :param beta: the beta value: the target prime factor is less than or equal to N^beta (default: 0.5)
    :return: a tuple containing the prime factors
    """
    x = Zmod(n)["x"].gen()
    f = msb * 2 ** (bitsize - msb_known) + x * 2 ** lsb_known + lsb
    X = 2 ** (bitsize - msb_known - lsb_known)
    d = f.degree()
    m = ceil(max(beta ** 2 / d, 7 * beta / d))
    while True:
        t = floor(d * m * (1 / beta - 1))
        logging.debug(f"Trying m = {m}, t = {t}...")
        for root in modular_univariate(f, n, m, t, X):
            p = msb * 2 ** (bitsize - msb_known) + root * 2 ** lsb_known + lsb
            if p != 0 and n % p == 0:
                return p, n // p

        m += 1


def factorize_bivariate(n, p_bitsize, p_msb_known, p_msb, p_lsb_known, p_lsb, q_bitsize, q_msb_known, q_msb, q_lsb_known, q_lsb, k_start=1):
    """
    Recovers the prime factors from a modulus using Coppersmith's method.
    For more complex combinations of known bits, the coron module in the small_roots package should be used directly.
    :param n: the modulus
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
    f = (p_msb * 2 ** (p_bitsize - p_msb_known) + x * 2 ** p_lsb_known + p_lsb) * (q_msb * 2 ** (q_bitsize - q_msb_known) + y * 2 ** q_lsb_known + q_lsb) - n
    X = 2 ** (p_bitsize - p_msb_known - p_lsb_known)
    Y = 2 ** (q_bitsize - q_msb_known - q_lsb_known)
    k = k_start
    while True:
        logging.debug(f"Trying k = {k}...")
        for x0, y0 in integer_bivariate(f, k, X, Y):
            p = int(p_msb * 2 ** (p_bitsize - p_msb_known) + x0 * 2 ** p_lsb_known + p_lsb)
            q = int(q_msb * 2 ** (q_bitsize - q_msb_known) + y0 * 2 ** q_lsb_known + q_lsb)
            if p * q == n:
                return p, q

        k += 1
