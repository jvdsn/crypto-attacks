def attack(decrypt_oracle, iv, c, encrypted_zeroes):
    """
    Uses a chosen-ciphertext attack to decrypt the ciphertext.
    Prior knowledge of E_k(0^16) is required for this attack to work.
    :param decrypt_oracle: the decryption oracle
    :param iv: the initialization vector
    :param c: the ciphertext
    :param encrypted_zeroes: a full zero block encrypted using the key
    :return: the plaintext
    """
    c_ = iv + c[:-16] + encrypted_zeroes
    p_ = decrypt_oracle(bytes(16), c_)
    return p_[16:]
