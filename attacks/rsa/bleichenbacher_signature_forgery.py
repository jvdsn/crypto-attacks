def attack(suffix, suffix_bit_length):
    """
    Returns a number s for which s^3 ends with the provided suffix.
    :param suffix: the suffix
    :param suffix_bit_length: the bit length of the suffix
    :return: the number s
    """
    assert suffix % 2 == 1, "Target suffix must be odd"

    s = 1
    for i in range(suffix_bit_length):
        if (((s ** 3) >> i) & 1) != ((suffix >> i) & 1):
            s |= (1 << i)

    return s
