import logging

from sage.all import Matrix
from sage.all import ZZ


def modular_univariate(f, N, m, t, X, early_return=True):
    """
    Computes small modular roots of a univariate polynomial.
    More information: May A., "New RSA Vulnerabilities Using Lattice Reduction Methods (Section 3.2)"
    :param f: the polynomial
    :param N: the modulus
    :param m: the amount of g shifts to use
    :param t: the amount of h shifts to use
    :param X: an approximate bound on the roots
    :param early_return: try to return as early as possible (default: true)
    :return: a generator generating small roots of the polynomial
    """
    f = f.monic().change_ring(ZZ)
    x = f.parent().gen()
    d = f.degree()

    B = Matrix(ZZ, d * m + t)
    row = 0
    logging.debug("Generating g shifts...")
    for i in range(m):
        for j in range(d):
            g = x ** j * N ** (m - i) * f ** i
            for col in range(row + 1):
                B[row, col] = g(x * X)[col]

            row += 1

    logging.debug("Generating h shifts...")
    for i in range(t):
        h = x ** i * f ** m
        h = h(x * X)
        for col in range(row + 1):
            B[row, col] = h[col]

        row += 1

    logging.debug("Executing the LLL algorithm...")
    B = B.LLL()

    logging.debug("Reconstructing polynomials...")
    for row in range(B.nrows()):
        new_polynomial = 0
        for col in range(B.ncols()):
            new_polynomial += B[row, col] * x ** col

        if new_polynomial.is_constant():
            continue

        new_polynomial = new_polynomial(x / X).change_ring(ZZ)
        for x0, _ in new_polynomial.roots():
            yield int(x0)

        if early_return:
            # Assuming that the first "good" polynomial in the lattice doesn't provide roots, we return.
            return
