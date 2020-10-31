from sage.all import GF
from sage.all import discrete_log


def attack(p, a, b, Px, Py, Qx, Qy):
    """
    Solves the discrete logarithm problem on a singular curve with a node.
    :param p: the prime
    :param a: the a parameter of the curve
    :param b: the b parameter of the curve
    :param Px: the base point x value
    :param Py: the base point y value
    :param Qx: the point multiplication result x value
    :param Qy: the point multiplication result y value
    :return: l such that l * P == Q
    """
    gf = GF(p)
    x = gf["x"].gen()
    f = x ** 3 + a * x + b

    # Move curve if necessary
    x_ = (gf(-a) / gf(3)).sqrt()
    f_ = f.subs(x=x + x_)
    t = f_[2].sqrt()

    p = (Py + t * (Px - x_)) / (Py - t * (Px - x_))
    q = (Qy + t * (Qx - x_)) / (Qy - t * (Qx - x_))
    return int(discrete_log(q, p))
