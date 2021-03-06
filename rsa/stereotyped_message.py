import logging

from sage.all import Zmod

from small_roots.howgrave_graham import modular_univariate


def attack(n, e, c, bitsize, msb_known, msb, lsb_known, lsb, m_start=1):
    """
    Recovers the plaintext from the ciphertext if some bits of the plaintext are known, using Coppersmith's method.
    :param n: the modulus
    :param e: the public exponent (should be "small": 3, 5, or 7 work best)
    :param c: the encrypted message
    :param bitsize: the amount of bits of the plaintext
    :param msb_known: the amount of known most significant bits of the plaintext
    :param msb: the known most significant bits of the plaintext
    :param lsb_known: the amount of known least significant bits of the plaintext
    :param lsb: the known least significant bits of the plaintext
    :param m_start: the m value to start at for the Howgrave-Graham small roots method (default: 1)
    :return: the plaintext
    """
    x = Zmod(n)["x"].gen()
    f = (msb * 2 ** (bitsize - msb_known) + x * 2 ** lsb_known + lsb) ** e - c
    bound = 2 ** (bitsize - msb_known - lsb_known) - 1
    m = m_start
    while True:
        t = m
        logging.debug(f"Trying m = {m}, t = {t}...")
        for root in modular_univariate(f, n, m, t, bound):
            return msb * 2 ** (bitsize - msb_known) + root * 2 ** lsb_known + lsb

        m += 1
