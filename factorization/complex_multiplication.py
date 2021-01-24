import logging
from math import gcd

from sage.all import EllipticCurve
from sage.all import Zmod
from sage.all import hilbert_class_polynomial


# Extended Euclid's algorithm for polynomials.
def _polynomial_xgcd(a, b):
    assert a.base_ring() == b.base_ring()

    r_prev, r = a, b
    s_prev, s = 1, 0
    t_prev, t = 0, 1

    while r:
        try:
            q = r_prev // r
            r_prev, r = r, r_prev - q * r
            s_prev, s = s, s_prev - q * s
            t_prev, t = t, t_prev - q * t
        except RuntimeError:
            raise ArithmeticError("r is not invertible", r)

    return r_prev, s_prev, t_prev


# Calculating the polynomial inverse using the extended GCD.
def _polynomial_inverse(poly, modulus):
    g, s, t = _polynomial_xgcd(poly, modulus)
    return s * g.lc() ** -1


def factorize(n, D):
    """
    Recovers the prime factors from a modulus using Cheng's elliptic curve complex multiplication method.
    More information: Sedlacek V. et al., "I want to break square-free: The 4p - 1 factorization method and its RSA backdoor viability"
    :param n: the modulus
    :param D: the discriminant to use to generate the Hilbert polynomial
    :return: a tuple containing the prime factors
    """
    assert D % 8 == 3, "D should be square-free"

    zmodn = Zmod(n)
    pr = zmodn["x"]

    H = pr(hilbert_class_polynomial(-D))
    Q = pr.quotient(H)
    j = Q.gen()

    try:
        k = j * _polynomial_inverse((1728 - j).lift(), H)
    except ArithmeticError as err:
        # If some polynomial was not invertible during XGCD calculation, we can factor n.
        p = gcd(int(err.args[1].lc()), n)
        return int(p), int(n // p)

    E = EllipticCurve(Q, [3 * k, 2 * k])
    while True:
        x = zmodn.random_element()

        logging.debug(f"Calculating division polynomial of Q{x}...")
        z = E.division_polynomial(n, x=Q(x))

        try:
            d, _, _ = _polynomial_xgcd(z.lift(), H)
        except ArithmeticError as err:
            # If some polynomial was not invertible during XGCD calculation, we can factor n.
            p = gcd(int(err.args[1].lc()), n)
            return int(p), int(n // p)

        p = gcd(int(d), n)
        if 1 < p < n:
            return int(p), int(n // p)
