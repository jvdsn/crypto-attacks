def attack(decrypt_oracle, iv, c, t):
    """
    Uses a chosen-ciphertext attack to decrypt the ciphertext.
    :param decrypt_oracle: the decryption oracle
    :param iv: the initialization vector
    :param c: the ciphertext
    :param t: the tag corresponding to the ciphertext
    :return: the plaintext
    """
    c_ = iv + c
    p_ = decrypt_oracle(bytes(16), c_, c[-16:])
    return p_[16:]
