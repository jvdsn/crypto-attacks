from sage.all import GF


def attack(p, a2, a4, a6, base_x, base_y, multiplication_result_x, multiplication_result_y):
    """
    Solves the discrete logarithm problem on a singular curve.
    :param p: the prime of the curve base ring
    :param a2: the a2 parameter of the curve
    :param a4: the a4 parameter of the curve
    :param a6: the a6 parameter of the curve
    :param base_x: the base point x value
    :param base_y: the base point y value
    :param multiplication_result_x: the point multiplication result x value
    :param multiplication_result_y: the point multiplication result y value
    :return: l such that l * base == multiplication_result
    """
    gf = GF(p)
    x = gf["x"].gen()
    f = x ** 3 + a2 * x ** 2 + a4 * x + a6
    roots = f.roots()

    # Singular point is a cusp.
    if len(roots) == 1:
        alpha = roots[0][0]
        u = (base_x - alpha) / base_y
        v = (multiplication_result_x - alpha) / multiplication_result_y
        return int(v / u)

    # Singular point is a node.
    if len(roots) == 2:
        if roots[0][1] == 2:
            alpha = roots[0][0]
            beta = roots[1][0]
        elif roots[1][1] == 2:
            alpha = roots[1][0]
            beta = roots[0][0]
        else:
            raise ValueError("Expected root with multiplicity 2.")

        t = (alpha - beta).sqrt()
        u = (base_y + t * (base_x - alpha)) / (base_y - t * (base_x - alpha))
        v = (multiplication_result_y + t * (multiplication_result_x - alpha)) / (multiplication_result_y - t * (multiplication_result_x - alpha))
        return int(v.log(u))

    raise ValueError(f"Unexpected number of roots {len(roots)}.")
