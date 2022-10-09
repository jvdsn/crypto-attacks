import logging

from sage.all import QQ
from sage.all import Sequence
from sage.all import ZZ
from sage.all import gcd
from sage.all import matrix
from sage.all import solve
from sage.all import var

DEBUG_ROOTS = None


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


def reconstruct_polynomials(B, f, monomials, bounds, preprocess_polynomial=lambda x: x, divide_original=True, divide_gcd=True):
    """
    Reconstructs polynomials from the lattice basis in the monomials.
    :param B: the lattice basis
    :param f: the original polynomial
    :param monomials: the monomials
    :param bounds: the bounds
    :param preprocess_polynomial: a function which preprocesses a polynomial before it is added to the list (default: identity function)
    :param divide_original: if set to True, polynomials will be divided by f if possible (default: True)
    :return: a list of polynomials
    """
    logging.debug("Reconstructing polynomials...")
    polynomials = []
    for row in range(B.nrows()):
        polynomial = 0
        for col, monomial in enumerate(monomials):
            assert B[row, col] % monomial(*bounds) == 0
            polynomial += B[row, col] * monomial // monomial(*bounds)

        polynomial = preprocess_polynomial(polynomial)

        if divide_original and polynomial % f == 0:
            logging.debug(f"Original polynomial divides reconstructed polynomial at row {row}, dividing...")
            polynomial //= f

        if divide_gcd:
            for i in range(len(polynomials)):
                g = gcd(polynomial, polynomials[i])
                # TODO: why are we only allowed to divide out g if it is constant?
                if g != 1 and g.is_constant():
                    logging.debug(f"Reconstructed polynomial has gcd {g} with polynomial at {i}, dividing...")
                    polynomial //= g
                    polynomials[i] //= g

        if polynomial.is_constant():
            logging.debug(f"Polynomial at row {row} is constant, ignoring...")
            continue

        if DEBUG_ROOTS is not None:
            logging.debug(f"Polynomial at row {row} roots check: {polynomial(*DEBUG_ROOTS)}")

        polynomials.append(polynomial)

    logging.debug(f"Reconstructed {len(polynomials)} polynomials")
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


def find_roots_gcd(polynomials, pr):
    """
    Returns a generator generating all roots of a polynomial in some unknowns.
    Uses pairwise gcds to find trivial roots.
    :param polynomials: the reconstructed polynomials
    :param pr: the polynomial ring
    :return: a generator generating dicts of (x0: x0root, x1: x1root, ...) entries
    """
    if pr.ngens() != 2:
        return

    logging.debug("Computing pairwise gcds to find trivial roots...")
    x, y = pr.gens()
    for i in range(len(polynomials)):
        for j in range(i):
            g = gcd(polynomials[i], polynomials[j])
            if g.degree() == 1 and g.nvariables() == 2 and g.constant_coefficient() == 0:
                # g = ax + by
                a = int(g.monomial_coefficient(x))
                b = int(g.monomial_coefficient(y))
                yield {x: b, y: a}
                yield {x: -b, y: a}


def find_roots_groebner(polynomials, pr):
    """
    Returns a generator generating all roots of a polynomial in some unknowns.
    Uses Groebner bases to find the roots.
    :param polynomials: the reconstructed polynomials
    :param pr: the polynomial ring
    :return: a generator generating dicts of (x0: x0root, x1: x1root, ...) entries
    """
    # We need to change the ring to QQ because groebner_basis is much faster over a field.
    # We also need to change the term order to lexicographic to allow for elimination.
    gens = pr.gens()
    s = Sequence(polynomials, pr.change_ring(QQ, order="lex"))
    while len(s) > 0:
        G = s.groebner_basis()
        logging.debug(f"Sequence length: {len(s)}, Groebner basis length: {len(G)}")
        if len(G) == len(gens):
            logging.debug(f"Found Groebner basis with length {len(gens)}, trying to find roots...")
            roots = {}
            for polynomial in G:
                vars = polynomial.variables()
                if len(vars) == 1:
                    for root in find_roots_univariate(polynomial.univariate_polynomial(), vars[0]):
                        roots |= root

            if len(roots) == pr.ngens():
                yield roots
                return

            logging.debug(f"System is underdetermined, trying to find constant root...")
            G = Sequence(s, pr.change_ring(ZZ, order="lex")).groebner_basis()
            vars = tuple(map(lambda x: var(x), gens))
            for solution_dict in solve([polynomial(*vars) for polynomial in G], vars, solution_dict=True):
                logging.debug(solution_dict)
                found = False
                roots = {}
                for i, v in enumerate(vars):
                    s = solution_dict[v]
                    if s.is_constant():
                        if not s.is_zero():
                            found = True
                        roots[gens[i]] = int(s) if s.is_integer() else int(s) + 1
                    else:
                        roots[gens[i]] = 0
                if found:
                    yield roots
                    return

            return
        else:
            # Remove last element (the biggest vector) and try again.
            s.pop()


def find_roots_resultants(polynomials, gens):
    """
    Returns a generator generating all roots of a polynomial in some unknowns.
    Recursively computes resultants to find the roots.
    :param polynomials: the reconstructed polynomials
    :param gens: the unknowns
    :return: a generator generating dicts of (x0: x0root, x1: x1root, ...) entries
    """
    if len(gens) == 1:
        if polynomials[0].is_univariate():
            yield from find_roots_univariate(polynomials[0].univariate_polynomial(), gens[0])
    else:
        resultants = [polynomials[0].resultant(polynomials[i], gens[0]) for i in range(1, len(gens))]
        for roots in find_roots_resultants(resultants, gens[1:]):
            for polynomial in polynomials:
                polynomial = polynomial.subs(roots)
                if polynomial.is_univariate():
                    for root in find_roots_univariate(polynomial.univariate_polynomial(), gens[0]):
                        yield roots | root


def find_roots_variety(polynomials, pr):
    """
    Returns a generator generating all roots of a polynomial in some unknowns.
    Uses the Sage variety (triangular decomposition) method to find the roots.
    :param polynomials: the reconstructed polynomials
    :param pr: the polynomial ring
    :return: a generator generating dicts of (x0: x0root, x1: x1root, ...) entries
    """
    # We need to change the ring to QQ because variety requires a field.
    s = Sequence([], pr.change_ring(QQ))
    for polynomial in polynomials:
        s.append(polynomial)
        I = s.ideal()
        dim = I.dimension()
        logging.debug(f"Sequence length: {len(s)}, Ideal dimension : {dim}")
        if dim == -1:
            s.pop()
        elif dim == 0:
            logging.debug("Found ideal with dimension 0, computing variety...")
            for roots in I.variety(ring=ZZ):
                yield {k: int(v) for k, v in roots.items()}

            return


def find_roots(polynomials, pr, method="groebner"):
    """
    Returns a generator generating all roots of a polynomial in some unknowns.
    The method used depends on the method parameter.
    :param polynomials: the reconstructed polynomials
    :param pr: the polynomial ring
    :param method: the method to use, can be "groebner", "resultants", or "variety" (default: "groebner")
    :return: a generator generating dicts of (x0: x0root, x1: x1root, ...) entries
    """
    if pr.ngens() == 1:
        logging.debug("Using univariate polynomial to find roots...")
        for polynomial in polynomials:
            yield from find_roots_univariate(polynomial, pr.gen())
    else:
        # Always try this method because it can find roots the others can't.
        yield from find_roots_gcd(polynomials, pr)

        if method == "groebner":
            logging.debug("Using Groebner basis method to find roots...")
            yield from find_roots_groebner(polynomials, pr)
        elif method == "resultants":
            logging.debug("Using resultants method to find roots...")
            yield from find_roots_resultants(polynomials, pr.gens())
        elif method == "variety":
            logging.debug("Using variety method to find roots...")
            yield from find_roots_variety(polynomials, pr)
