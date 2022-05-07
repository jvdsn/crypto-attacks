def attack(c, pos, p, p_):
    """
    Replaces the original plaintext with a new plaintext at a position in the ciphertext.
    :param c: the ciphertext
    :param pos: the position to modify at
    :param p: the original plaintext
    :param p_: the new plaintext
    :return: the modified ciphertext
    """
    c_ = bytearray(c)
    for i in range(len(p)):
        c_[pos + i] = c[pos + i] ^ p[i] ^ p_[i]

    return c_
