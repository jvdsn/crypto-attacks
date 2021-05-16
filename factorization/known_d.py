from math import gcd
from random import randint


def factorize(n, e, d):
    """
    Recovers the prime factors from a modulus if the public exponent and private exponent are known.
    :param n: the modulus
    :param e: the public exponent
    :param d: the private exponent
    :return: a tuple containing the prime factors, or None if the factors were not found
    """
    k = e * d - 1
    t = 0
    while k % (2 ** t) == 0:
        t += 1

    while True:
        g = randint(1, n)
        for s in range(1, t + 1):
            x = pow(g, k // (2 ** s), n)
            p = gcd(x - 1, n)
            if p != 1 and p != n and n % p == 0:
                return p, n // p
