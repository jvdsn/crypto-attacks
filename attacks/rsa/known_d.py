from math import gcd
from random import randrange


def attack(N, e, d):
    """
    Recovers the prime factors from a modulus if the public exponent and private exponent are known.
    :param N: the modulus
    :param e: the public exponent
    :param d: the private exponent
    :return: a tuple containing the prime factors, or None if the factors were not found
    """
    k = e * d - 1
    t = 0
    while k % (2 ** t) == 0:
        t += 1

    while True:
        g = randrange(1, N)
        for s in range(1, t + 1):
            x = pow(g, k // (2 ** s), N)
            p = gcd(x - 1, N)
            if 1 < p < N and N % p == 0:
                return p, N // p
