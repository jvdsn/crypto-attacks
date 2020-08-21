import logging

from sage.all import Matrix


def integer_bivariate(p, k, xbound, ybound, early_return=True):
    """
    Computes small integer roots of a bivariate polynomial.
    More information: Coron J., "Finding Small Roots of Bivariate Integer Polynomial Equations: a Direct Approach"
    :param p: the polynomial
    :param k: the amount of shifts to use
    :param xbound: an approximate bound on the x roots
    :param ybound: an approximate bound on the y roots
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
            w = abs(int(p.coefficient([i, j]))) * xbound ** i * ybound ** j
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
                    S[a * k + b, i * k + j] = int(s.coefficient([i0 + i, j0 + j]))

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

    lattice = Matrix(k ** 2 + (k + d) ** 2, (k + d) ** 2)
    row = 0
    logging.debug("Generating normal shifts...")
    for a in range(k):
        for b in range(k):
            shift = x ** a * y ** b * p
            for col, monomial in enumerate(monomials):
                lattice[row, col] = shift.monomial_coefficient(monomial) * monomial(xbound, ybound)

            row += 1

    logging.debug("Generating additional shifts...")
    for col, monomial in enumerate(monomials):
        lattice[row, col] = n * monomial(xbound, ybound)
        row += 1

    logging.debug(f"Lattice size: {lattice.nrows()} x {lattice.ncols()}")
    logging.debug("Generating Echelon form...")
    lattice = lattice.echelon_form(algorithm="pari0")

    logging.debug(f"Executing the LLL algorithm on the sublattice ({k ** 2} x {k ** 2})...")
    basis = lattice.submatrix(k ** 2, k ** 2, (k + d) ** 2 - k ** 2).LLL()

    logging.debug("Reconstructing polynomials...")
    for row in range(basis.nrows()):
        new_polynomial = 0
        # Only use right monomials now (corresponding the the sublattice)
        for col, monomial in enumerate(right_monomials):
            new_polynomial += basis[row, col] * monomial // monomial(xbound, ybound)

        resultant = new_polynomial.resultant(p, y)
        if not resultant.is_constant():
            for xroot, _ in resultant.univariate_polynomial().roots():
                xroot = int(xroot)
                p = p.subs({x: xroot})
                if not p.is_constant():
                    for yroot, _ in p.univariate_polynomial().roots():
                        yroot = int(yroot)
                        yield xroot, yroot

                        if early_return:
                            return
