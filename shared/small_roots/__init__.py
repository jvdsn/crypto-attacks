import logging
from itertools import combinations

from sage.all import QQ
from sage.all import Sequence
from sage.all import ZZ
from sage.all import matrix


def fill_lattice(shifts, monomials, bounds):
    """
    Creates a lattice basis containing the coefficients of the shifts in the monomials.
    :param shifts: the shifts
    :param monomials: the monomials
    :param bounds: the bounds
    :return: the lattice basis
    """
    logging.debug(f"Filling the lattice ({len(shifts)} x {len(monomials)})...")
    B = matrix(ZZ, len(shifts), len(monomials))
    for row, shift in enumerate(shifts):
        for col, monomial in enumerate(monomials):
            B[row, col] = shift.monomial_coefficient(monomial) * monomial(*bounds)

    return B


def reduce(B):
    """
    Reduces a lattice basis using a lattice reduction algorithm (currently LLL).
    :param B: the lattice basis
    :return: the reduced basis
    """
    logging.debug("Executing the LLL algorithm...")
    return B.LLL()


def reconstruct_polynomials(B, monomials, bounds):
    """
    Reconstructs polynomials from the lattice basis in the monomials.
    :param B: the lattice basis
    :param monomials: the monomials
    :param bounds: the bounds
    :return: a list of polynomials
    """
    logging.debug("Reconstructing polynomials...")
    polynomials = []
    for row in range(B.nrows()):
        polynomial = 0
        for col, monomial in enumerate(monomials):
            assert B[row, col] % monomial(*bounds) == 0
            polynomial += B[row, col] * monomial // monomial(*bounds)

        polynomials.append(polynomial)

    return polynomials


def find_roots_univariate(polynomial, x):
    """
    Returns a generator generating all roots of a univariate polynomial in an unknown.
    :param polynomial: the polynomial
    :param x: the unknown
    :return: a generator generating dicts of (x: root) entries
    """
    if polynomial.is_constant():
        return

    for root in polynomial.roots(multiplicities=False):
        if root != 0:
            yield {x: int(root)}


def find_roots_resultants(f, polynomials, xs):
    """
    Returns a generator generating all roots of a polynomial in some unknowns.
    Recursively computes resultants to find the roots.
    :param f: the original polynomial
    :param polynomials: the reconstructed polynomials
    :param xs: the unknowns
    :return: a generator generating dicts of (x0: x0root, x1: x1root, ...) entries
    """
    if len(xs) == 1:
        yield from find_roots_univariate(f.univariate_polynomial(), xs[0])
    else:
        for comb in combinations(polynomials, len(xs) - 1):
            resultants = [p.resultant(f, xs[0]) for p in comb]
            for i in range(len(resultants)):
                for roots in find_roots_resultants(resultants[i], resultants[i + 1:], xs[1:]):
                    for p in comb:
                        for root in find_roots_univariate(p.subs(roots).univariate_polynomial(), xs[0]):
                            yield root | roots


def find_roots_groebner(polynomials, pr):
    """
    Returns a generator generating all roots of a polynomial in some unknowns.
    Uses Groebner bases to find the roots.
    :param polynomials: the reconstructed polynomials
    :param pr: the polynomial ring
    :return: a generator generating dicts of (x0: x0root, x1: x1root, ...) entries
    """
    # We need to change the ring to QQ because variety requires a field.
    s = Sequence([], pr.change_ring(QQ))
    for polynomial in polynomials:
        s.append(polynomial)
        I = s.ideal()
        if I.dimension() == -1:
            s.pop()
        elif I.dimension() == 0:
            logging.debug("Found ideal with dimension 0, computing variety...")
            for roots in I.variety(ring=ZZ):
                yield {k: int(v) for k, v in roots.items()}

            return


def find_roots(f, polynomials, pr, method="resultants"):
    """
    Returns a generator generating all roots of a polynomial in some unknowns.
    The method used depends on the method parameter.
    :param f: the original polynomial
    :param polynomials: the reconstructed polynomials
    :param method: the method to use, can be "resultantss" or "groebner" (default: "resultants")
    :return: a generator generating dicts of (x0: x0root, x1: x1root, ...) entries
    """
    polynomials = [p for p in polynomials if p % f != 0]
    if pr.ngens() == 1:
        logging.debug("Using univariate polynomial to find roots...")
        for polynomial in polynomials:
            yield from find_roots_univariate(polynomial, pr.gen())
    else:
        if method == "resultants":
            logging.debug("Using resultants method to find roots...")
            # TODO: should we use f here or not?
            # Sometimes, when f is used, it does not find the solution (jochemsz_may_modular). However, if only the polynomials are used, it does find the solution.
            # On the other hand, sometimes it does not find the solution if only the polynomials are used (ernst), but it does find the solution, when f is used.
            yield from find_roots_resultants(f, polynomials, pr.gens())
        elif method == "groebner":
            logging.debug("Using Groebner basis method to find roots...")
            yield from find_roots_groebner(polynomials, pr)
