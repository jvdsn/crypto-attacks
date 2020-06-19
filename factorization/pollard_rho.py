from math import gcd


def factorize(n, g=lambda x, n: (x ** 2 + 1) % n, start=2):
    """
    Recovers the prime factors from a modulus using Pollard's Rho algorithm.
    :param n: the modulus
    :param g: the polynomial (default: (x ** 2 + 1) % n)
    :param start: the starting value (default: 2)
    :return: a tuple containing the prime factors
    """
    x = start
    y = start
    d = 1
    while d == 1:
        x = g(x, n)
        y = g(g(y, n), n)
        d = gcd(abs(x - y), n)

    if d == n:
        raise ValueError(f"Failed to factorize (starting value: {start}).")

    return d, n // d
