from Crypto.Util.strxor import strxor


def attack(decrypt_oracle):
    """
    Recovers the initialization vector using a chosen-ciphertext attack.
    :param decrypt_oracle: the decryption oracle to decrypt ciphertexts
    :return: the initialization vector
    """
    p = decrypt_oracle(bytes(32))
    return strxor(p[:16], p[16:])
