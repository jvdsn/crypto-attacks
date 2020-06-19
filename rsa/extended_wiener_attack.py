from math import isqrt

from sage.all import Integer
from sage.all import RealNumber
from sage.all import continued_fraction


def _solve_quadratic(a, b, c):
    d = b ** 2 - 4 * a * c
    if d < 0:
        return 0, 0
    else:
        return (-b + isqrt(d)) // (2 * a), (-b - isqrt(d)) // (2 * a)


def attack(n, e, max_s=20000, max_r=100, max_t=100):
    """
    Recovers the prime factors of a modulus and the private exponent if the private exponent is too small.
    More information: Dujella A., "Continued fractions and RSA with small secret exponent"
    :param n: the modulus
    :param e: the public exponent
    :param max_s: the amount of s values to try (default: 20000)
    :param max_r: the amount of r values to try for each s value (default: 100)
    :param max_t: the amount of t values to try for each s value (default: 100)
    :return: a tuple containing the prime factors of the modulus and the private exponent
    """
    i_n = Integer(n)
    i_e = Integer(e)
    threshold = i_e / i_n + (RealNumber(2.122) * i_e) / (i_n * i_n.sqrt())
    convergents = continued_fraction(i_e / i_n).convergents()
    for i in range(1, len(convergents) - 2, 2):
        if convergents[i + 2] < threshold < convergents[i]:
            m = i
            break

    for s in range(max_s):
        for r in range(max_r):
            k = r * convergents[m + 1].numerator() + s * convergents[m + 1].numerator()
            d = r * convergents[m + 1].denominator() + s * convergents[m + 1].denominator()
            if k == 0 or (e * d - 1) % k != 0:
                continue

            phi = (e * d - 1) // k
            p, q = _solve_quadratic(1, -n + phi - 1, n)
            if p * q == n:
                return p, q, d

        for t in range(max_t):
            k = s * convergents[m + 2].numerator() - t * convergents[m + 1].numerator()
            d = s * convergents[m + 2].denominator() - t * convergents[m + 1].denominator()
            if k == 0 or (e * d - 1) % k != 0:
                continue

            phi = (e * d - 1) // k
            p, q = _solve_quadratic(1, -n + phi - 1, n)
            if p * q == n:
                return p, q, d

    raise ValueError(f"Failed to find private exponent (max s = {max_s}, max r = {max_r}, max t = {max_t}).")
