def attack(suffix_bits, suffix):
    """
    Returns a number s for which s^3 ends with the provided suffix.
    :param suffix_bits: the amount of bits in the suffix
    :param suffix: the suffix
    :return: the number s
    """
    s = 1
    for i in range(suffix_bits):
        if (((s ** 3) >> i) & 1) != ((suffix >> i) & 1):
            s |= (1 << i)

    return s
