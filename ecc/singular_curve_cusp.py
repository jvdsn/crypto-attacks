from sage.all import GF
from sage.all import discrete_log


def attack(p, Px, Py, Qx, Qy):
    """
    Solves the discrete logarithm problem on a singular curve with a cusp.
    :param p: the prime
    :param Px: the base point x value
    :param Py: the base point y value
    :param Qx: the point multiplication result x value
    :param Qy: the point multiplication result y value
    :return: k such that k * P == Q
    """
    gf = GF(p)
    p = 1 - gf(1) / (Px - Py)
    q = 1 - gf(1) / (Qx - Qy)
    return int(discrete_log(q, p))
