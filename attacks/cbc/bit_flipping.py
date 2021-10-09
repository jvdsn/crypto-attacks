def attack(iv, c, pos, p, p_):
    """
    Replaces the original plaintext with a new plaintext at a position in the ciphertext.
    :param iv: the initialization vector
    :param c: the ciphertext
    :param pos: the position to modify at
    :param p: the original plaintext
    :param p_: the new plaintext
    :return: a tuple containing the modified initialization vector and the modified ciphertext
    """
    iv_ = bytearray(iv)
    c_ = bytearray(c)
    for i in range(len(p)):
        if pos + i < 16:
            iv_[pos + i] = iv[pos + i] ^ p[i] ^ p_[i]
        else:
            c_[pos + i - 16] = c[pos + i - 16] ^ p[i] ^ p_[i]

    return iv_, c_
