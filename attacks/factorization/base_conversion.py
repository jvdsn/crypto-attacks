import logging

from sage.all import ZZ


def factorize(N, coefficient_threshold=32):
    """
    Recovers the prime factors from a modulus by converting it to different bases.
    :param N: the modulus
    :param coefficient_threshold: the threshold of coefficients below which we will try to factor a base k polynomial
    :return: a tuple containing the prime factors
    """
    R = ZZ["x"]
    base = 2
    while True:
        logging.debug(f"Trying {base = }...")
        poly = R(ZZ(N).digits(base))
        logging.debug(f"Got {len(poly.coefficients())} coefficients")
        if len(poly.coefficients()) < coefficient_threshold:
            facs = poly.factor()
            return tuple(map(lambda f: int(f[0](base)), facs))

        base += 1


def factorize_base_2x(N):
    """
    Recovers the prime factors from a modulus by converting it to different bases of the form 2^x.
    :param N: the modulus
    :return: a tuple containing the prime factors
    """
    R = ZZ["x"]
    base = 2
    while True:
        logging.debug(f"Trying {base = }...")
        poly = R(ZZ(N).digits(base))
        facs = poly.factor()
        if len(facs) > 1:
            return tuple(map(lambda f: int(f[0](base)), facs))

        base *= 2
