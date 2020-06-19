from math import gcd


def attack(n1, e1, c1, n2, e2, c2):
    """
    Recovers the plaintexts from two ciphertexts, encrypted using two moduli which share a prime factor.
    :param n1: the first modulus
    :param e1: the first public exponent
    :param c1: the ciphertext of the first encryption
    :param n2: the second modulus
    :param e2: the second public exponent
    :param c2: the ciphertext of the second encryption
    :return: a tuple containing the shared prime factor, the second prime factor of the first modulus, the first plaintext, the second prime factor of the second modulus, the second plaintext
    """
    p = gcd(n1, n2)
    q1 = n1 // p
    q2 = n2 // p
    d1 = pow(e1, -1, (p - 1) * (q1 - 1))
    d2 = pow(e2, -1, (p - 1) * (q2 - 1))
    return p, q1, pow(c1, d1, n1), q2, pow(c2, d2, n2)
