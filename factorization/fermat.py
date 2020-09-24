from math import isqrt


def factorize(n):
    """
    Recovers the prime factors from a modulus using Fermat's factorization method.
    :param n: the modulus
    :return: a tuple containing the prime factors, or None if the factors were not found
    """
    a = isqrt(n)
    b = a * a - n
    while b < 0 or isqrt(b) ** 2 != b:
        a += 1
        b = a * a - n

    p = a - isqrt(b)
    q = n // p
    if p * q == n:
        return p, q
