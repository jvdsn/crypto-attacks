from math import gcd

from sage.all import divisors


def factorize(n, a, s):
    """
    Recovers the prime factors from a modulus if the order of a mod n is known.
    More information: M. Johnston A., "Shor’s Algorithm and Factoring: Don’t Throw Away the Odd Orders"
    :param n: the modulus
    :param a: the base
    :param s: the order of a
    :return: a tuple containing the prime factors, or None if the factors were not found
    """
    assert pow(a, s, n) == 1, "s must be the order of a mod n"

    for r in divisors(s):
        b_r = pow(a, s // r, n)
        p = gcd(b_r - 1, n)
        if p != 1 and p != n and n % p == 0:
            return p, n // p
