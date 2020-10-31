import logging

from sage.all import Zmod
from sage.all import solve_mod
from sage.all import var

from small_roots.howgrave_graham import modular_univariate


def attack(n, e, bitsize, lsb_known, lsb, m_start=1):
    """
    Recovers the prime factors of a modulus and the private exponent using Coppersmith's method if part of the private exponent is known.
    More information: Boneh D., Durfee G., Frankel Y., "An Attack on RSA Given a Small Fraction of the Private Key Bits"
    :param n: the modulus
    :param e: the public exponent (should be "small": 3, 5, or 7 work best)
    :param bitsize: the amount of bits of the prime factors
    :param lsb_known: the amount of known least significant bits of the private exponent
    :param lsb: the known least significant bits of the private exponent
    :param m_start: the m value to start at for the Howgrave-Graham small roots method (default: 1)
    :return: a tuple containing the prime factors of the modulus and the private exponent
    """
    logging.debug("Generating solutions for k candidates...")
    x = var("x")
    solutions = []
    for k in range(1, e + 1):
        solutions += solve_mod(k * x ** 2 + (e * lsb - k * (n + 1) - 1) * x + k * n == 0, 2 ** lsb_known)

    x = Zmod(n)["x"].gen()
    bound = 2 ** (bitsize - lsb_known) - 1
    m = m_start
    while True:
        t = m
        logging.debug(f"Trying m = {m}, t = {t}...")
        for s in solutions:
            p_lsb = int(s[0])
            f = x * 2 ** lsb_known + p_lsb
            for root in modular_univariate(f, n, m, t, bound):
                p = root * 2 ** lsb_known + p_lsb
                if p != 0 and n % p == 0:
                    q = n // p
                    return p, q, pow(e, -1, (p - 1) * (q - 1))

        m += 1
