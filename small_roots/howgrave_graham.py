import logging

from sage.all import Matrix
from sage.all import ZZ


def modular_univariate(p, modulus, m, t, bound, early_return=True):
    """
    Computes small modular roots of a univariate polynomial.
    More information: May A., "New RSA Vulnerabilities Using Lattice Reduction Methods"
    :param p: the polynomial
    :param modulus: the modulus
    :param m: the amount of normal shifts to use
    :param t: the amount of additional shifts to use
    :param bound: an approximate bound on the roots
    :param early_return: try to return as early as possible (default: true)
    :return: a generator generating small roots of the polynomial
    """
    p = p.monic().change_ring(ZZ)
    x = p.parent().gen()
    d = p.degree()

    lattice = Matrix(d * m + t)
    row = 0
    logging.debug("Generating normal shifts...")
    for i in range(m):
        for j in range(d):
            shift = (x * bound) ** j * modulus ** (m - i) * p(x * bound) ** i
            for col in range(row + 1):
                lattice[row, col] = shift[col]

            row += 1

    logging.debug("Generating additional shifts...")
    for i in range(t):
        shift = (x * bound) ** i * p(x * bound) ** m
        for col in range(row + 1):
            lattice[row, col] = shift[col]

        row += 1

    logging.debug("Executing the LLL algorithm...")
    basis = lattice.LLL()

    logging.debug("Reconstructing polynomials...")
    for row in range(basis.nrows()):
        new_polynomial = 0
        for col in range(basis.ncols()):
            new_polynomial += (basis[row, col] // bound ** col) * x ** col

        for xroot, _ in new_polynomial.roots():
            yield int(xroot)

        if early_return:
            return
