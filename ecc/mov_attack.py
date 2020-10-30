from sage.all import EllipticCurve
from sage.all import GF


def attack(P, Q):
    """
    Solves the discrete logarithm problem using the MOV attack.
    :param P: the base point
    :param Q: the point multiplication result
    :return: l such that l * P == Q
    """
    E = P.curve()
    q = E.base_ring().order()
    n = P.order()

    k = 1
    while (q ** k - 1) % n != 0:
        k += 1

    E = EllipticCurve(GF(q ** k), E.a_invariants())
    P = E(P)
    Q = E(Q)
    while True:
        R = E.random_point()
        if R == P or R == Q or R.order() != n ** k:
            continue

        a = P.weil_pairing(R, n)
        b = Q.weil_pairing(R, n)
        l = b.log(a)
        if l * P == Q:
            return l
