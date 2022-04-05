import logging
import os
import sys
from itertools import product

from sage.all import Zmod

path = os.path.dirname(os.path.dirname(os.path.dirname(os.path.realpath(os.path.abspath(__file__)))))
if sys.path[1] != path:
    sys.path.insert(1, path)

from shared.polynomial import fast_polynomial_gcd


def attack(N, e, c1, c2, f1, f2):
    """
    Recovers the shared secret if p1 and p2 are affinely related and encrypted with the same modulus and exponent.
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


def attack_xor(N, e, c1, c2, x):
    """
    Recovers the shared secret if p1 = p2 ^ x and encrypted with the same modulus and exponent.
    The complexity of this attack is 2^l, with l the hamming weight of x.
    :param N: the modulus
    :param e: the public exponent
    :param c1: the ciphertext of the first encryption
    :param c2: the ciphertext of the second encryption
    :param x: the XOR difference
    :return: a generator generating possible values of the shared secret
    """
    shifts = []
    for i in range(x.bit_length()):
        if (x >> i) & 1 == 1:
            shifts.append(1 << i)

    logging.info(f"Brute forcing 2^{len(shifts)} possibilities, this might take some time...")
    for signs in product([-1, 1], repeat=len(shifts)):
        difference = sum(sign * shift for sign, shift in zip(signs, shifts))
        yield attack(N, e, c1, c2, lambda x: x, lambda x: x + difference)
