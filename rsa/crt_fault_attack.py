from math import gcd

from sage.all import crt


# An example faulty signing function
def _faulty_sign(m, p, q, d_p, d_q):
    s_p = pow(m, d_p, p)
    s_q = pow(m, d_q, q)
    s_q ^= 1
    return crt([s_p, s_q], [p, q])


def attack(n, e, sign):
    """
    Recovers the prime factors from a modulus using a faulty RSA-CRT signing function.
    :param n: the modulus
    :param e: the public exponent
    :param sign: the faulty RSA-CRT signing function
    :return: a tuple containing the prime factors
    """
    m = 2
    s = sign(m)
    g = gcd(m - pow(s, e, n), n)
    return g, n // g
