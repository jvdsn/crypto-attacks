from math import isqrt


def factorize(n):
    """
    Recovers the prime factors from a modulus if the factors are twin primes.
    :param n: the modulus
    :return: a tuple containing the prime factors
    """
    return isqrt(n + 1) - 1, isqrt(n + 1) + 1
