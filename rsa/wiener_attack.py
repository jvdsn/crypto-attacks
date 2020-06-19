from math import isqrt

from sage.all import Integer
from sage.all import continued_fraction


def _solve_quadratic(a, b, c):
    d = b ** 2 - 4 * a * c
    if d < 0:
        return 0, 0
    else:
        return (-b + isqrt(d)) // (2 * a), (-b - isqrt(d)) // (2 * a)


def wiener_attack(n, e):
    """
    Recovers the prime factors of a modulus and the private exponent if the private exponent is too small.
    :param n: the modulus
    :param e: the public exponent
    :return: a tuple containing the prime factors of the modulus and the private exponent
    """
    convergents = continued_fraction(Integer(e) / Integer(n)).convergents()
    for c in convergents:
        k = c.numerator()
        d = c.denominator()
        if k == 0 or (e * d - 1) % k != 0:
            continue

        phi = (e * d - 1) // k
        p, q = _solve_quadratic(1, -n + phi - 1, n)
        if p * q == n:
            return p, q, d

    raise ValueError("Failed to find private exponent.")
