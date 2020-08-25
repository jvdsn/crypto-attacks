from sage.all import Matrix
from sage.all import QQ


def attack(t, a, p, bound):
    """
    Solves the hidden number problem using an attack based on the shortest vector problem.
    The hidden number problem is defined as finding alpha such that {x - t * alpha + a = 0 mod p}.
    :param t: the t values
    :param a: the a values
    :param p: the prime
    :param bound: a bound on the x values
    :return: a tuple containing alpha, and a list of x values
    """
    m = len(t)
    basis = Matrix(QQ, m + 2, m + 2)
    for i in range(m):
        basis[i, i] = p

    basis[m] = t + [bound / QQ(p), 0]
    basis[m + 1] = a + [0, bound]

    basis = basis.LLL()

    for row in basis.rows():
        alpha = (int(row[m] * p) // bound) % p
        if alpha != 0:
            return alpha, list(map(int, row[:m]))
