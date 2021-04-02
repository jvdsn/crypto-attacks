from math import ceil

from sage.all import ZZ
from sage.all import sqrt


def factorize(n, r_p, r_q):
    """
    Recovers the prime factors from a modulus using the Ghafar-Ariffin-Asbullah attack.
    More information: Ghafar AHA. et al., "A New LSB Attack on Special-Structured RSA Primes"
    :param n: the modulus
    :param r_p: the value r_p
    :param r_q: the value r_q
    :return: a tuple containing the prime factors
    """
    i = ceil(sqrt(r_p * r_q))
    x = ZZ["x"].gen()
    while True:
        sigma = (round(int(sqrt(n))) - i) ** 2
        z = (n - (r_p * r_q)) % sigma
        f = x ** 2 - z * x + sigma * r_p * r_q
        for root, _ in f.roots():
            if root % r_p == 0:
                p = int((root // r_p) + r_q)
                assert n % p == 0
                return p, n // p
            if root % r_q == 0:
                p = int((root // r_q) + r_p)
                assert n % p == 0
                return p, n // p

        i += 1
