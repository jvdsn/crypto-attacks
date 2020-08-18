from sage.all import Integer
from sage.all import var


def factorize(n, coefficient_threshold=50):
    """
    Recovers the prime factors from a modulus by converting it to different bases.
    :param n: the modulus
    :param coefficient_threshold: the threshold of coefficients below which we will try to factor a base k polynomial
    :return: a tuple containing the prime factors
    """
    x = var("x")
    base = 2
    while True:
        p = 0
        for i, e in enumerate(Integer(n).digits(base)):
            p += e * x ** i

        if len(p.coefficients()) < coefficient_threshold:
            (p, _), (q, _) = p.factor_list()
            return p.subs(x=base), q.subs(x=base)

        base += 1
