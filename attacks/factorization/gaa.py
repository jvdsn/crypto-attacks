from math import ceil

from sage.all import ZZ
from sage.all import sqrt


def factorize(N, rp, rq):
    """
    Recovers the prime factors from a modulus using the Ghafar-Ariffin-Asbullah attack.
    More information: Ghafar AHA. et al., "A New LSB Attack on Special-Structured RSA Primes"
    :param N: the modulus
    :param rp: the value rp
    :param rq: the value rq
    :return: a tuple containing the prime factors
    """
    i = ceil(sqrt(rp * rq))
    x = ZZ["x"].gen()
    while True:
        sigma = (round(int(sqrt(N))) - i) ** 2
        z = (N - (rp * rq)) % sigma
        f = x ** 2 - z * x + sigma * rp * rq
        for x0 in f.roots(multiplicities=False):
            if x0 % rp == 0:
                p = int((x0 // rp) + rq)
                assert N % p == 0
                return p, N // p
            if x0 % rq == 0:
                p = int((x0 // rq) + rp)
                assert N % p == 0
                return p, N // p

        i += 1
