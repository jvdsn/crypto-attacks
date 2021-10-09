import logging
import os
import sys

from sage.all import Zmod

path = os.path.dirname(os.path.dirname(os.path.dirname(os.path.realpath(os.path.abspath(__file__)))))
if sys.path[1] != path:
    sys.path.insert(1, path)

from shared.small_roots import howgrave_graham


def attack(N, e, c, bitsize, msb_known, msb, lsb_known, lsb, m_start=1):
    """
    Recovers the plaintext from the ciphertext if some bits of the plaintext are known, using Coppersmith's method.
    :param N: the modulus
    :param e: the public exponent (should be "small": 3, 5, or 7 work best)
    :param c: the encrypted message
    :param bitsize: the amount of bits of the plaintext
    :param msb_known: the amount of known most significant bits of the plaintext
    :param msb: the known most significant bits of the plaintext
    :param lsb_known: the amount of known least significant bits of the plaintext
    :param lsb: the known least significant bits of the plaintext
    :param m_start: the m value to start at for the small roots method (default: 1)
    :return: the plaintext
    """
    x = Zmod(N)["x"].gen()
    f_pt = msb * 2 ** (bitsize - msb_known) + x * 2 ** lsb_known + lsb
    f = f_pt ** e - c
    X = 2 ** (bitsize - msb_known - lsb_known) - 1
    m = m_start
    while True:
        t = m
        logging.info(f"Trying m = {m}, t = {t}...")
        for x0 in howgrave_graham.modular_univariate(f, N, m, t, X):
            if x0 != 0:
                return int(f_pt(x0))

        m += 1
