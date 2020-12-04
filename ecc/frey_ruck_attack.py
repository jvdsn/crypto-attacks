import logging
from math import gcd
from math import lcm

from sage.all import GF
from sage.all import crt


def attack(base, multiplication_result):
    """
    Solves the discrete logarithm problem using the Frey-Ruck attack.
    :param base: the base point
    :param multiplication_result: the point multiplication result
    :return: l such that l * base == multiplication_result
    """
    curve = base.curve()
    p = curve.base_ring().order()
    n = base.order()

    assert gcd(n, p) == 1, "GCD of curve base ring order and generator order should be 1."

    logging.debug("Calculating embedding degree...")

    # Embedding degree k.
    k = 1
    while (p ** k - 1) % n != 0:
        k += 1

    logging.debug(f"Found embedding degree {k}, computing discrete logarithm...")

    pairing_curve = curve.base_extend(GF(p ** k))
    pairing_base = pairing_curve(base)
    pairing_multiplication_result = pairing_curve(multiplication_result)

    ls = []
    ds = []
    while lcm(*ds) != n:
        rand = pairing_curve.random_point()
        o = rand.order()
        d = gcd(o, n)
        rand = (o // d) * rand
        assert rand.order() == d

        u = pairing_base.tate_pairing(rand, n, k)
        v = pairing_multiplication_result.tate_pairing(rand, n, k)
        l = v.log(u)
        logging.debug(f"Found discrete log {l} modulo {d}")
        ls.append(int(l))
        ds.append(int(d))

    return ls[0] if len(ls) == 1 else int(crt(ls, ds))
