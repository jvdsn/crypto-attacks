from math import isqrt


def factorize(n):
    """
    Recovers the prime factors from a modulus if the factors are twin primes.
    :param n: the modulus
    :return: a tuple containing the prime factors, or None if there is no factorization
    """
    p = isqrt(n + 1) - 1
    q = isqrt(n + 1) + 1
    if p * q == n:
        return p, q
