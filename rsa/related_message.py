from sage.all import Zmod


# Euclid's algorithm for polynomials
def _polynomial_gcd(a, b):
    assert a.base_ring() == b.base_ring()

    while b:
        try:
            a, b = b, a % b
        except RuntimeError:
            raise ArithmeticError("b is not invertible", b)

    return a


def attack(n, e, c1, c2, f1, f2):
    """
    Recovers the shared secret from two plaintext messages encrypted with the same modulus.
    :param n: the modulus
    :param e: the public exponent
    :param c1: the ciphertext of the first encryption
    :param c2: the ciphertext of the second encryption
    :param f1: the function encoding the shared secret into the first plaintext
    :param f2: the function encoding the shared secret into the second plaintext
    :return: the shared secret
    """
    x = Zmod(n)["x"].gen()
    g1 = f1(x) ** e - c1
    g2 = f2(x) ** e - c2
    g = -_polynomial_gcd(g1, g2).monic()
    return g[0]
