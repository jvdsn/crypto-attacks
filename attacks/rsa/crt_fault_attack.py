from math import gcd


def attack(n, e, sign):
    """
    Recovers the prime factors from a modulus using a faulty RSA-CRT signing function.
    :param n: the modulus
    :param e: the public exponent
    :param sign: the faulty RSA-CRT signing function
    :return: a tuple containing the prime factors
    """
    m = 2
    s = sign(m)
    g = gcd(m - pow(s, e, n), n)
    return g, n // g
