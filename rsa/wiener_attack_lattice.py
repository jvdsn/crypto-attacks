from math import isqrt

from sage.all import Matrix

from factorization import known_phi


def attack(n, e):
    """
    Recovers the prime factors of a modulus and the private exponent if the private exponent is too small.
    More information: Nguyen P. Q., "Public-Key Cryptanalysis"
    :param n: the modulus
    :param e: the public exponent
    :return: a tuple containing the prime factors of the modulus and the private exponent, or None if the private exponent was not found
    """
    s = isqrt(n)
    lattice = Matrix([[e, s], [n, 0]])

    basis = lattice.LLL()

    for row in basis.rows():
        d = row[1] // s
        k = abs(row[0] - e * d) // n
        d = abs(d)
        phi = (e * d - 1) // k
        factors = known_phi.factorize(n, phi)
        if factors:
            return *factors, d
