from math import gcd

from sage.all import EllipticCurve
from sage.all import GF
from sage.all import ZZ
from sage.all import crt
from sage.all import lcm


def attack(P, Q):
    """
    Solves the discrete logarithm problem using the MOV attack.
    :param P: the base point
    :param Q: the point multiplication result
    :return: k such that k * P == Q
    """
    E = P.curve()
    gf = E.base_ring()
    p = gf.order()
    m = 1
    while (p ** m - 1) % E.order() != 0:
        m += 1

    gf_ = GF(p ** m)
    E_ = EllipticCurve(gf_, E.a_invariants())
    P_ = E_(P)
    Q_ = E_(Q)

    n = P.order()
    ks = []
    ds = []
    while lcm(ds) != n:
        T_ = E_.random_point()
        o = T_.order()
        d = gcd(o, n)
        T_ *= (o // d)
        a = P_.weil_pairing(T_, n)
        b = Q_.weil_pairing(T_, n)
        k = b.log(a)
        ks.append(k)
        ds.append(ZZ(d))

    return int(crt(ks, ds))
