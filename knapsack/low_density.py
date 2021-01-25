from math import ceil
from math import log2
from math import sqrt

from sage.all import matrix
from sage.all import QQ


def attack(a, s):
    """
    Tries to find e_i values such that sum(e_i * a_i) = s.
    This attack only works if the density of the a_i values is < 0.9048.
    More information: Coster M. J. et al., "Improved low-density subset sum algorithms"
    :param a: the a_i values
    :param s: the s value
    :return: the e_i values, or None if the e_i values were not found
    """
    n = len(a)
    d = n / log2(max(a))
    N = ceil(sqrt(1 / 2 * n))
    assert d < 0.9408, f"Density should be less than 0.9408 but was {d}."

    M = matrix(QQ, n + 1, n + 1)
    for i in range(n):
        M[i, i] = 1
        M[i, n] = N * a[i]

    M[n] = [1 / 2] * n + [N * s]

    L = M.LLL()

    for row in L.rows():
        s_ = 0
        e = []
        for i in range(n):
            ei = 1 - (row[i] + 1 / 2)
            if ei != 0 and ei != 1:
                break

            ei = int(ei)
            s_ += ei * a[i]
            e.append(ei)

        if s_ == s:
            return e
