from math import gcd


def attack_known_m(n, e, m, s):
    """
    Recovers the prime factors from a modulus using a known message and its faulty signature.
    :param n: the modulus
    :param e: the public exponent
    :param m: the message
    :param s: the faulty signature
    :return: a tuple containing the prime factors, or None if the signature wasn't actually faulty
    """
    g = gcd(m - pow(s, e, n), n)
    return None if g == 1 else (g, n // g)


def attack_unknown_m(n, e, sv, sf):
    """
    Recovers the prime factors from a modulus using a correct valid and a faulty signature from the same (unknown) message.
    :param n: the modulus
    :param e: the public exponent
    :param sv: the valid signature
    :param sf: the faulty signature
    :return: a tuple containing the prime factors, or None if the signatures were both valid, or both faulty
    """
    assert sv != sf
    g = gcd(sv - sf, n)
    return None if g == 1 else (g, n // g)
