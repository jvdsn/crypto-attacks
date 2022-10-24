import logging
from itertools import product
from math import prod

from sage.all import ZZ
from sage.all import xgcd

from shared import small_roots


def integer_multivariate(F, e, m, X, roots_method="groebner"):
    """
    Computes small integer roots of a list of polynomials.
    More information: Aono Y., "Minkowski sum based lattice construction for multivariate simultaneous Coppersmith's technique and applications to RSA" (Section 4)
    :param F: the list of polynomials
    :param e: the list of e values
    :param m: the parameter m
    :param X: an approximate bound on the x roots
    :param roots_method: the method to use to find roots (default: "groebner")
    :return: a generator generating small roots (dicts of (x0: x0root, x1: x1root, ..., y: yroot) entries) of the polynomials
    """
    # We need lexicographic ordering for .lc() below.
    pr = F[0].parent().change_ring(ZZ, order="lex")
    x = pr.gens()

    l = len(e)
    for k in range(l):
        F[k] = pr(F[k])

    logging.debug("Generating shifts...")

    g = []
    for k in range(l):
        gk = {}
        for i in range(m + 1):
            for j in range(i + 1):
                gk[i, j] = x[k] ** (i - j) * F[k] ** j * e[k] ** (m - j)
        g.append(gk)

    Ig = {}
    for tup in product(*g):
        g_ = prod(g[k][tup[k]] for k in range(l))
        index = tuple(g_.exponents()[0])
        if index not in Ig:
            Ig[index] = []
        Ig[index].append(g_)

    shifts = []
    for g in Ig.values():
        gp = g[0]
        lc = gp.lc()
        for gi in g[1:]:
            lc, s, t = xgcd(lc, gi.lc())
            gp = s * gp + t * gi
        shifts.append(gp)

    L, monomials = small_roots.create_lattice(pr, shifts, X)
    L = small_roots.reduce_lattice(L)
    polynomials = small_roots.reconstruct_polynomials(L, None, prod(e) ** m, monomials, X)
    yield from small_roots.find_roots(pr, polynomials, method=roots_method)
