from sage.all import legendre_symbol


def attack(p, h, c1, c2):
    """
    Returns the Legendre symbol of the message encrypted using an unsafe generator.
    :param p: the prime used in the ElGamal scheme
    :param h: the public key
    :param c1: the ciphertext
    :param c2: the ciphertext
    :return: the Legendre symbol
    """
    return int(legendre_symbol(c2, p) // max(legendre_symbol(h, p), legendre_symbol(c1, p)))
