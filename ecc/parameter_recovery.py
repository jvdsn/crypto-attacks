from sage.all import GF
from sage.all import matrix
from sage.all import vector


def attack(p, x1, y1, x2, y2):
    """
    Recovers the a and b parameters from an elliptic curve when two points are known.
    :param p: the prime of the curve base ring
    :param x1: the x coordinate of the first point
    :param y1: the y coordinate of the first point
    :param x2: the x coordinate of the second point
    :param y2: the y coordinate of the second point
    :return: a tuple containing the a and b parameters of the elliptic curve
    """
    m = matrix(GF(p), [[x1, 1], [x2, 1]])
    v = vector(GF(p), [y1 ** 2 - x1 ** 3, y2 ** 2 - x2 ** 3])
    a, b = m.solve_right(v)
    return int(a), int(b)
