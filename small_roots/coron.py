import logging

from sage.all import Matrix
from sage.all import ZZ


def integer_bivariate(p, k, X, Y, early_return=True):
    """
    Computes small integer roots of a bivariate polynomial.
    More information: Coron J., "Finding Small Roots of Bivariate Integer Polynomial Equations: a Direct Approach"
    :param p: the polynomial
    :param k: the amount of shifts to use
    :param X: an approximate bound on the x roots
    :param Y: an approximate bound on the y roots
    :param early_return: try to return as early as possible (default: true)
    :return: a generator generating small roots (tuples of x and y roots) of the polynomial
    """
    x, y = p.parent().gens()
    d = max(p.degrees())

    W = 0
    i0 = 0
    j0 = 0
    for i in range(d + 1):
        for j in range(d + 1):
            w = abs(int(p.coefficient([i, j]))) * X ** i * Y ** j
            if w > W:
                W = w
                i0 = i
                j0 = j

    logging.debug("Calculating n...")
    S = Matrix(k ** 2)
    for a in range(k):
        for b in range(k):
            s = x ** a * y ** b * p
            for i in range(k):
                for j in range(k):
                    S[a * k + b, i * k + j] = s.coefficient([i0 + i, j0 + j])

    n = abs(S.det())
    logging.debug(f"Found n = {n}")

    # Monomials are collected in "left" and "right" lists, which determine where the columns are in relation to eachother
    # This partition ensures the Hermite form will set desired monomial coefficients to zero
    logging.debug("Generating monomials...")
    left_monomials = []
    right_monomials = []
    for i in range(k + d):
        for j in range(k + d):
            if 0 <= i - i0 < k and 0 <= j - j0 < k:
                left_monomials.append(x ** i * y ** j)
            else:
                right_monomials.append(x ** i * y ** j)

    assert len(left_monomials) == k ** 2
    monomials = left_monomials + right_monomials

    L = Matrix(k ** 2 + (k + d) ** 2, (k + d) ** 2)
    row = 0
    logging.debug("Generating s shifts...")
    for a in range(k):
        for b in range(k):
            s = x ** a * y ** b * p
            s = s(x * X, y * Y)
            for col, monomial in enumerate(monomials):
                L[row, col] = s.monomial_coefficient(monomial)

            row += 1

    logging.debug("Generating additional shifts...")
    for col, monomial in enumerate(monomials):
        r = monomial * n
        r = r(x * X, y * Y)
        L[row, col] = r.monomial_coefficient(monomial)
        row += 1

    logging.debug(f"Lattice size: {L.nrows()} x {L.ncols()}")
    logging.debug("Generating Echelon form...")
    L = L.echelon_form(algorithm="pari0")

    logging.debug(f"Executing the LLL algorithm on the sublattice ({k ** 2} x {k ** 2})...")
    L2 = L.submatrix(k ** 2, k ** 2, (k + d) ** 2 - k ** 2).LLL()

    logging.debug("Reconstructing polynomials...")
    for row in range(L2.nrows()):
        h = 0
        # Only use right monomials now (corresponding the the sublattice)
        for col, monomial in enumerate(right_monomials):
            h += L2[row, col] * monomial

        if h.is_constant():
            continue

        h = h(x / X, y / Y).change_ring(ZZ)
        res = h.resultant(p, y)
        if not res.is_constant():
            for x0, _ in res.univariate_polynomial().roots():
                x0 = int(x0)
                p_ = p(x0, y)
                if not p_.is_constant():
                    for y0, _ in p_.univariate_polynomial().roots():
                        y0 = int(y0)
                        yield x0, y0

                        if early_return:
                            return
