import os
import sys

from sage.all import Zmod

path = os.path.dirname(os.path.dirname(os.path.dirname(os.path.realpath(os.path.abspath(__file__)))))
if sys.path[1] != path:
    sys.path.insert(1, path)

from shared.polynomial import fast_polynomial_gcd


def attack(N, e, c1, c2, f1, f2):
    """
    Recovers the shared secret if p1 and p2 are related and encrypted with the same modulus and exponent.
    Uses a fast GCD algorithm from "Polynomial Division and Greatest Common Divisors"
    :param N: the modulus
    :param e: the public exponent
    :param c1: the ciphertext of the first encryption
    :param c2: the ciphertext of the second encryption
    :param f1: the first function to apply to the shared secret
    :param f2: the second function to apply to the shared secret
    :return: the shared secret
    """
    x = Zmod(N)["x"].gen()
    g1 = f1(x) ** e - c1
    g2 = f2(x) ** e - c2
    g = -fast_polynomial_gcd(g1, g2).monic()
    return int(g[0])
