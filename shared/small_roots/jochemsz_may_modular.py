import logging
from abc import ABCMeta
from abc import abstractmethod
from math import gcd

from sage.all import ZZ

from shared import small_roots


class Strategy(metaclass=ABCMeta):
    @abstractmethod
    def generate_M(self, f, l, m):
        """
        Generates the M dict.
        :param f: the polynomial
        :param l: the leading monomial
        :param m: the amount of normal shifts to use
        :return: the M dict
        """
        pass


class BasicStrategy(Strategy):
    def generate_M(self, f, l, m):
        M = {}
        fm_monomials = (f ** m).monomials()
        for k in range(m + 1):
            M[k] = set()
            fmk_monomials = (f ** (m - k)).monomials()
            for monomial in fm_monomials:
                if monomial // (l ** k) in fmk_monomials:
                    M[k].add(monomial)

        M[m + 1] = []
        return M


class ExtendedStrategy(Strategy):
    def __init__(self, t):
        self.t = t

    def generate_M(self, f, l, m):
        x = f.parent().gens()
        assert len(x) == len(self.t)

        M = {}
        fm_monomials = (f ** m).monomials()
        for k in range(m + 1):
            M[k] = set()
            fmk_monomials = (f ** (m - k)).monomials()
            for monomial in fm_monomials:
                if monomial // (l ** k) in fmk_monomials:
                    for xi, ti in zip(x, self.t):
                        for j in range(ti + 1):
                            M[k].add(monomial * xi ** j)

        M[m + 1] = []
        return M


class BonehDurfeeStrategy(Strategy):
    def __init__(self, t):
        self.t = t

    def generate_M(self, f, l, m):
        x1, x2 = f.parent().gens()

        M = {}
        for k in range(m + 1):
            M[k] = set()
            for i1 in range(k, m + 1):
                for i2 in range(k, i1 + self.t + 1):
                    M[k].add(x1 ** i1 * x2 ** i2)

        M[m + 1] = []
        return M


class BlomerMayStrategy(Strategy):
    def __init__(self, t):
        self.t = t

    def generate_M(self, f, l, m):
        x1, x2, x3 = f.parent().gens()

        M = {}
        for k in range(m + 1):
            M[k] = set()
            for i1 in range(k, m + 1):
                for i2 in range(m - i1 + 1):
                    for i3 in range(i2 + self.t - 1):
                        M[k].add(x1 ** i1 * x2 ** i2 * x3 ** i3)

        M[m + 1] = []
        return M


def modular_multivariate(f, N, m, X, strategy, roots_method="groebner"):
    """
    Computes small integer roots of a multivariate polynomial.
    More information: Jochemsz E., May A., "A Strategy for Finding Roots of Multivariate Polynomials with New Applications in Attacking RSA Variants" (Section 2.1)
    :param f: the polynomial
    :param N: the modulus
    :param m: the parameter m
    :param X: a list of approximate bounds on the roots for each variable
    :param strategy: the strategy to use (Appendix A)
    :param roots_method: the method to use to find roots (default: "groebner")
    :return: a generator generating small roots (tuples) of the polynomial
    """
    f = f.change_ring(ZZ)
    pr = f.parent()
    x = pr.gens()
    assert len(x) > 1

    # Sage lm method depends on the term ordering
    l = 1
    for monomial in f.monomials():
        if monomial % l == 0:
            l = monomial

    al = int(f.coefficient(l))
    assert gcd(al, N) == 1
    f_ = (pow(al, -1, N) * f % N).change_ring(ZZ)

    logging.debug("Generating shifts...")

    M = strategy.generate_M(f, l, m)
    shifts = []
    monomials = set()
    for k in range(m + 1):
        for monomial in M[k]:
            if monomial not in M[k + 1]:
                shifts.append(monomial // (l ** k) * f_ ** k * N ** (m - k))
                monomials.add(monomial)

    L, monomials = small_roots.create_lattice(pr, shifts, X)
    L = small_roots.reduce_lattice(L)
    polynomials = small_roots.reconstruct_polynomials(L, f, N ** m, monomials, X)
    for roots in small_roots.find_roots(pr, polynomials, method=roots_method):
        yield tuple(roots[xi] for xi in x)
