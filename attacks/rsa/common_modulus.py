from sage.all import xgcd


def attack(n, e1, c1, e2, c2):
    """
    Recovers the plaintext from two ciphertexts, encrypted using the same modulus and different public exponents.
    :param n: the common modulus
    :param e1: the first public exponent
    :param c1: the ciphertext of the first encryption
    :param e2: the second public exponent
    :param c2: the ciphertext of the second encryption
    :return: the plaintext
    """
    _, u, v = xgcd(e1, e2)
    p1 = pow(c1, u, n) if u > 0 else pow(pow(c1, -1, n), -u, n)
    p2 = pow(c2, v, n) if v > 0 else pow(pow(c2, -1, n), -v, n)
    return int(p1 * p2) % n
