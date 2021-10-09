import logging

from sage.all import ZZ
from sage.all import var


def factorize(N, coefficient_threshold=50):
    """
    Recovers the prime factors from a modulus by converting it to different bases.
    :param N: the modulus
    :param coefficient_threshold: the threshold of coefficients below which we will try to factor a base k polynomial
    :return: a tuple containing the prime factors
    """
    x = var("x")
    base = 2
    while True:
        logging.debug(f"Trying base {base}...")

        polynomial = 0
        for i, e in enumerate(ZZ(N).digits(base)):
            polynomial += e * x ** i

        if len(polynomial.coefficients()) < coefficient_threshold:
            return tuple(map(lambda f: int(f[0].subs(x=base)), polynomial.factor_list()))

        base += 1
