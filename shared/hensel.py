from sage.all import ZZ
from sage.all import Zmod


def hensel_lift_linear(f, p, k, roots):
    """
    Uses Hensel lifting to lift the roots of f mod p^k to f mod p^(k + 1)
    :param f: the polynomial
    :param p: the prime
    :param k: the power
    :param roots: the roots of f mod p^k
    :return: a generator generating the roots of f mod p^k
    """
    pk = p ** k
    pk1 = p ** (k + 1)
    for root in roots:
        for i in range(p):
            new_root = root + i * pk
            if f(new_root) % pk1 == 0:
                yield new_root


def hensel_roots(f, p, k):
    """
    Uses Hensel lifting to generate the roots of f mod p^k.
    :param f: the polynomial
    :param p: the prime
    :param k: the power
    :return: a list containing the roots of f mod p^k, or an empty list if no roots were found
    """
    f_ = f.change_ring(Zmod(p))
    if f_ == 0:
        roots = list(range(p))
    elif f_.is_constant():
        return []
    else:
        roots = []
        for root in f_.roots(multiplicities=False):
            roots.append(int(root))

    f = f.change_ring(ZZ)
    for i in range(1, k):
        roots = list(hensel_lift_linear(f, p, i, roots))
        if len(roots) == 0:
            return []

    return roots
