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
    kx = legendre_symbol(h, p)
    ky = legendre_symbol(c1, p)
    k = legendre_symbol(c2, p)
    return k if kx == 1 or ky == 1 else -k
