def attack(p, s, s_, x, y, xs):
    """
    Forges a share to recombine into a new shared secret, s', if a single share and the x coordinates of the other participants are given.
    :param p: the prime used for Shamir's secret sharing
    :param s: the original shared secret
    :param s_: the target shared secret, s'
    :param x: the x coordinate of the given share
    :param y: the y coordinate of the given share
    :param xs: the x coordinates of the other participants (excluding the x coordinate of the given share)
    :return: the forged share
    """
    const = 1
    for i in xs:
        const *= i * pow(i - x, -1, p)

    return ((s_ - s) * pow(const, -1, p) + y) % p
