from sage.all import ZZ


def factorize(n, phi):
    """
    Recovers the prime factors from a modulus if Euler's totient is known.
    :param n: the modulus
    :param phi: Euler's totient, the order of the multiplicative group modulo n
    :return: a tuple containing the prime factors, or None if the factors were not found
    """
    s = n + 1 - phi
    x = ZZ["x"].gen()
    f = x ** 2 - s * x + n
    for p, _ in f.roots():
        p = int(p)
        if n % p == 0:
            return p, n // p
