import os
import sys

from sage.all import RR
from sage.all import ZZ
from sage.all import continued_fraction

path = os.path.dirname(os.path.dirname(os.path.dirname(os.path.realpath(os.path.abspath(__file__)))))
if sys.path[1] != path:
    sys.path.insert(1, path)

from attacks.factorization import known_phi


def attack(n, e, max_s=20000, max_r=100, max_t=100):
    """
    Recovers the prime factors if the private exponent is too small.
    More information: Dujella A., "Continued fractions and RSA with small secret exponent"
    :param n: the modulus
    :param e: the public exponent
    :param max_s: the amount of s values to try (default: 20000)
    :param max_r: the amount of r values to try for each s value (default: 100)
    :param max_t: the amount of t values to try for each s value (default: 100)
    :return: a tuple containing the prime factors of the modulus and the private exponent, or None if the private exponent was not found
    """
    i_n = ZZ(n)
    i_e = ZZ(e)
    threshold = i_e / i_n + (RR(2.122) * i_e) / (i_n * i_n.sqrt())
    convergents = continued_fraction(i_e / i_n).convergents()
    for i in range(1, len(convergents) - 2, 2):
        if convergents[i + 2] < threshold < convergents[i]:
            m = i
            break

    for s in range(max_s):
        for r in range(max_r):
            k = r * convergents[m + 1].numerator() + s * convergents[m + 1].numerator()
            d = r * convergents[m + 1].denominator() + s * convergents[m + 1].denominator()
            if pow(pow(2, e, n), d, n) != 2:
                continue

            phi = (e * d - 1) // k
            factors = known_phi.factorize(n, phi)
            if factors:
                return *factors, int(d)

        for t in range(max_t):
            k = s * convergents[m + 2].numerator() - t * convergents[m + 1].numerator()
            d = s * convergents[m + 2].denominator() - t * convergents[m + 1].denominator()
            if pow(pow(2, e, n), d, n) != 2:
                continue

            phi = (e * d - 1) // k
            factors = known_phi.factorize(n, phi)
            if factors:
                return *factors, int(d)
