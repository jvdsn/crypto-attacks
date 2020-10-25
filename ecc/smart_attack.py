from sage.all import EllipticCurve
from sage.all import Qp
from sage.all import ZZ


# Lifts a point to the p-adic numbers.
def lift_(E, P, gf):
    x, y = map(ZZ, P.xy())
    for P_ in E.lift_x(x, all=True):
        x_, y_ = map(gf, P_.xy())
        if y == y_:
            return P_


def attack(P, Q):
    """
    Solves the discrete logarithm problem using Smart's attack.
    More information: Smart N. P., "The discrete logarithm problem on elliptic curves of trace one"
    :param P: the base point
    :param Q: the point multiplication result
    :return: l such that l * P == Q
    """
    E = P.curve()
    gf = E.base_ring()
    p = gf.order()
    assert E.order() == P, f"Order of curve {E.order()} should be equal to the order of the field {p}."

    E = EllipticCurve(Qp(p), list(map(lambda a: int(a) + p * ZZ.random_element(1, p), E.a_invariants())))
    P = p * lift_(E, P, gf)
    Q = p * lift_(E, Q, gf)
    Px, Py = P.xy()
    Qx, Qy = Q.xy()
    return int(gf((Qx / Qy) / (Px / Py)))
