from sage.all import EllipticCurve
from sage.all import Qp
from sage.all import ZZ


# Lifts a point to the p-adic numbers.
def _lift(curve, point, gf):
    x, y = map(ZZ, point.xy())
    for point_ in curve.lift_x(x, all=True):
        x_, y_ = map(gf, point_.xy())
        if y == y_:
            return point_


def attack(base, multiplication_result):
    """
    Solves the discrete logarithm problem using Smart's attack.
    More information: Smart N. P., "The discrete logarithm problem on elliptic curves of trace one"
    :param base: the base point
    :param multiplication_result: the point multiplication result
    :return: l such that l * base == multiplication_result
    """
    curve = base.curve()
    gf = curve.base_ring()
    p = gf.order()
    assert curve.trace_of_frobenius() == 1, f"Curve should have trace of Frobenius = 1."

    lift_curve = EllipticCurve(Qp(p), list(map(lambda a: int(a) + p * ZZ.random_element(1, p), curve.a_invariants())))
    lifted_base = p * _lift(lift_curve, base, gf)
    lifted_multiplication_result = p * _lift(lift_curve, multiplication_result, gf)
    lb_x, lb_y = lifted_base.xy()
    lmr_x, lmr_y = lifted_multiplication_result.xy()
    return int(gf((lmr_x / lmr_y) / (lb_x / lb_y)))
