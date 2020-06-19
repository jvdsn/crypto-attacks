from sage.all import Integer


def attack(e, c):
    """
    Recovers the plaintext from a ciphertext, encrypted using a very small public exponent (e.g. e = 3).
    :param e: the public exponent
    :param c: the ciphertext
    :return: the plaintext
    """
    return Integer(c).nth_root(e)
