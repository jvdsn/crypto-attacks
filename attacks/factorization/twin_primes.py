from math import isqrt


def factorize(N):
    """
    Recovers the prime factors from a modulus if the factors are twin primes.
    :param N: the modulus
    :return: a tuple containing the prime factors, or None if there is no factorization
    """
    p = isqrt(N + 1) - 1
    q = isqrt(N + 1) + 1
    return p, q if p * q == N else None
