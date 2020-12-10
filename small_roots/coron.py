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
    delta = max(p.degrees())

    (i0, j0), W = max(map(lambda kv: (kv[0], abs(kv[1])), p(x * X, y * Y).dict().items()), key=lambda kv: kv[1])

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
    for i in range(k + delta):
        for j in range(k + delta):
            if 0 <= i - i0 < k and 0 <= j - j0 < k:
                left_monomials.append(x ** i * y ** j)
            else:
                right_monomials.append(x ** i * y ** j)

    assert len(left_monomials) == k ** 2
    monomials = left_monomials + right_monomials

    L = Matrix(k ** 2 + (k + delta) ** 2, (k + delta) ** 2)
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
    L2 = L.submatrix(k ** 2, k ** 2, (k + delta) ** 2 - k ** 2).LLL()

    new_polynomials = []
    logging.debug("Reconstructing polynomials...")
    for row in range(L2.nrows()):
        new_polynomial = 0
        # Only use right monomials now (corresponding the the sublattice)
        for col, monomial in enumerate(right_monomials):
            new_polynomial += L2[row, col] * monomial

        if new_polynomial.is_constant():
            continue

        new_polynomial = new_polynomial(x / X, y / Y).change_ring(ZZ)
        new_polynomials.append(new_polynomial)

    logging.debug("Calculating resultants...")
    for h in new_polynomials:
        res = p.resultant(h, y)
        if res.is_constant():
            continue

        for x0, _ in res.univariate_polynomial().roots():
            h_ = p.subs(x=x0)
            if h_.is_constant():
                continue

            for y0, _ in h_.univariate_polynomial().roots():
                yield int(x0), int(y0)

        if early_return:
            # Assuming that the first "good" polynomial in the lattice doesn't provide roots, we return.
            return
