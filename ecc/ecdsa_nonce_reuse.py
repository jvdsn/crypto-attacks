from math import gcd


# Solves a congruence of the form ax = b mod n
def solve_congruence(a, b, n):
    g = gcd(a, n)
    a //= g
    b //= g
    m = n // g
    for i in range(g):
        yield (pow(a, -1, m) * b + i * m) % n


def attack(m1, r1, s1, m2, r2, s2, n):
    """
    Recovers the nonce and private key from two messages signed using the same nonce.
    :param m1: the first message
    :param r1: the signature of the first message
    :param s1: the signature of the first message
    :param m2: the second message
    :param r2: the signature of the second message
    :param s2: the signature of the second message
    :param n: the order of the elliptic curve
    :return: tuples containing the possible nonce and private key
    """
    for k in solve_congruence(s1 - s2, m1 - m2, n):
        for d in solve_congruence(r1, k * s1 - m1, n):
            yield k, d
