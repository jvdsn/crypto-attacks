from math import gcd

from sage.all import divisors


def factorize(N, a, s):
    """
    Recovers the prime factors from a modulus if the order of a mod n is known.
    More information: M. Johnston A., "Shor's Algorithm and Factoring: Don't Throw Away the Odd Orders"
    :param N: the modulus
    :param a: the base
    :param s: the order of a
    :return: a tuple containing the prime factors, or None if the factors were not found
    """
    assert pow(a, s, N) == 1, "s must be the order of a mod N"

    for r in divisors(s):
        b_r = pow(a, s // r, N)
        p = gcd(b_r - 1, N)
        if 1 < p < N and N % p == 0:
            return p, N // p

    return None
