def attack(encrypt_oracle, decrypt_oracle, iv, c, t):
    """
    Uses a chosen-ciphertext attack to decrypt the ciphertext.
    :param encrypt_oracle: the encryption oracle
    :param decrypt_oracle: the decryption oracle
    :param iv: the initialization vector
    :param c: the ciphertext
    :param t: the tag corresponding to the ciphertext
    :return: the plaintext
    """
    p_ = bytes(16) + iv + c
    iv_, c_, t_ = encrypt_oracle(p_)
    c__ = iv + c
    p__ = decrypt_oracle(iv_, c__, c_[-32:-16])
    return p__[16:]
