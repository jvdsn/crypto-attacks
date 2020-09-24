from sage.all import Integer
from sage.all import continued_fraction

from factorization import known_phi


def attack(n, e):
    """
    Recovers the prime factors of a modulus and the private exponent if the private exponent is too small.
    :param n: the modulus
    :param e: the public exponent
    :return: a tuple containing the prime factors of the modulus and the private exponent, or None if the private exponent was not found
    """
    convergents = continued_fraction(Integer(e) / Integer(n)).convergents()
    for c in convergents:
        k = c.numerator()
        d = c.denominator()
        if k == 0 or (e * d - 1) % k != 0:
            continue

        phi = (e * d - 1) // k
        factors = known_phi.factorize(n, phi)
        if factors:
            return *factors, d
