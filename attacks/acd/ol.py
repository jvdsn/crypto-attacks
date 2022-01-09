import os
import sys

from sage.all import ZZ
from sage.all import matrix

path = os.path.dirname(os.path.dirname(os.path.dirname(os.path.realpath(os.path.abspath(__file__)))))
if sys.path[1] != path:
    sys.path.insert(1, path)

from shared import symmetric_mod


def attack(x, rho):
    """
    Solves the ACD problem using the orthogonal based approach.
    More information: Galbraith D. S. et al., "Algorithms for the Approximate Common Divisor Problem" (Section 4)
    :param x: the x samples, with xi = p * qi + ri
    :param rho: the bit length of the r values
    :return: the secret integer p and a list containing the r values, or None if p could not be found
    """
    assert len(x) >= 2, "At least two x values are required."

    R = 2 ** rho

    B = matrix(ZZ, len(x), len(x) + 1)
    for i, xi in enumerate(x):
        B[i, 0] = xi
        B[i, i + 1] = R

    B = B.LLL()

    K = B.submatrix(row=0, col=1, nrows=len(x) - 1, ncols=len(x)).right_kernel()
    q = K.an_element()
    r0 = symmetric_mod(x[0], q[0])
    p = abs((x[0] - r0) // q[0])
    r = [symmetric_mod(xi, p) for xi in x]
    if all(-R < ri < R for ri in r):
        return int(p), r
