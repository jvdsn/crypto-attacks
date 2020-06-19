from sage.all import PolynomialRing
from sage.all import Zmod


def _polynomial_gcd(a, b):
    while b:
        a, b = b, a % b

    return a.monic()


def attack(n, e, c1, c2, f1, f2):
    """
    Recovers the shared secret from two plaintext messages encrypted with the same modulus.
    :param n: the modulus
    :param e: the public exponent
    :param c1: the ciphertext of the first encryption
    :param c2: the ciphertext of the second encryption
    :param f1: the polynomial encoding the shared secret into the first plaintext
    :param f2: the polynomial encoding the shared secret into the second plaintext
    :return: the shared secret
    """
    pr = PolynomialRing(Zmod(n), "x")
    x = pr.gen()
    g1 = f1(x) ** e - c1
    g2 = f2(x) ** e - c2
    g = -_polynomial_gcd(g1, g2)
    return g[0]
