import logging
import os
import sys

from sage.all import Zmod

path = os.path.dirname(os.path.dirname(os.path.dirname(os.path.realpath(os.path.abspath(__file__)))))
if sys.path[1] != path:
    sys.path.insert(1, path)

from shared.small_roots import howgrave_graham


def attack(N, e, c, partial_m, m=1, t=0):
    """
    Recovers the plaintext from the ciphertext if some bits of the plaintext are known, using Coppersmith's method.
    :param N: the modulus
    :param e: the public exponent (should be "small": 3, 5, or 7 work best)
    :param c: the encrypted message
    :param partial_m: the partial plaintext message (PartialInteger)
    :param m: the m value to use for the small roots method (default: 1)
    :param t: the t value to use for the small roots method (default: 0)
    :return: the plaintext
    """
    x = Zmod(N)["x"].gen()
    f = (partial_m.sub([x])) ** e - c
    X = partial_m.get_unknown_bounds()
    logging.info(f"Trying m = {m}, t = {t}...")
    for x0, in howgrave_graham.modular_univariate(f, N, m, t, X):
        if x0 != 0:
            return int(partial_m.sub([x0]))

    return None
