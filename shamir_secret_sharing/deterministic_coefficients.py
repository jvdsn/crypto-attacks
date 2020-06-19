def attack(p, k, a1, f, x, y):
    """
    Recovers the shared secret if the coefficients are generated deterministically, and a single share is given.
    :param p: the prime used for Shamir's secret sharing
    :param k: the amount of shares needed to unlock the secret
    :param a1: the first coefficient of the polynomial
    :param f: a function which takes a coefficient and returns the next coefficient in the polynomial
    :param x: the x coordinate of the given share
    :param y: the y coordinate of the given share
    :return: the shared secret
    """
    s = y
    a = a1
    for i in range(1, k):
        s -= a * x ** i
        a = f(a)

    return s % p
