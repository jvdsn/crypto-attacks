import logging
from abc import ABCMeta
from abc import abstractmethod
from math import gcd

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
    shifts = set()
    monomials = set()
    for k in range(m + 1):
        for monomial in M[k]:
            if monomial not in M[k + 1]:
                shifts.add(monomial // (l ** k) * f_ ** k * N ** (m - k))
                monomials.add(monomial)

    L = small_roots.fill_lattice(shifts, monomials, X)
    L = small_roots.reduce(L)
    polynomials = small_roots.reconstruct_polynomials(L, monomials, X)
    for roots in small_roots.find_roots(f_, polynomials, pr, method=roots_method):
        yield tuple(roots[xi] for xi in x)
