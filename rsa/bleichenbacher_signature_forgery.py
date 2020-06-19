def attack(suffix):
    """
    Returns a number s for which s^3 ends with the provided suffix.
    :param suffix: the suffix
    :return: the number s
    """
    s = 1
    c = 1
    i = 0
    while (1 << i) <= suffix:
        if ((c >> i) & 1) != ((suffix >> i) & 1):
            s ^= (1 << i)
            c = s ** 3

        i += 1

    return s
