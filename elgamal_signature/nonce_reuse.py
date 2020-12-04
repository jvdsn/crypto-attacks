from math import gcd


# Solves a congruence of the form ax = b mod n
def _solve_congruence(a, b, n):
    g = gcd(a, n)
    a //= g
    b //= g
    m = n // g
    for i in range(g):
        yield (pow(a, -1, m) * b + i * m) % n


def attack(p, m1, r1, s1, m2, r2, s2):
    """
    Recovers the nonce and private key from two messages signed using the same nonce.
    :param p: the prime used in the ElGamal scheme
    :param m1: the first message
    :param r1: the signature of the first message
    :param s1: the signature of the first message
    :param m2: the second message
    :param r2: the signature of the second message
    :param s2: the signature of the second message
    :return: generates tuples containing the possible nonce and private key
    """
    for l in _solve_congruence(int(s1 - s2), int(m1 - m2), int(p - 1)):
        for d in _solve_congruence(int(r1), int(m1 - l * s1), int(p - 1)):
            yield int(l), int(d)
