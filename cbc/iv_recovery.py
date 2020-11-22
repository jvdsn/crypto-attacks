from Crypto.Util.strxor import strxor


def attack(oracle):
    """
    Recovers the initialization vector using a chosen-ciphertext attack.
    :param oracle: the decryption oracle to decrypt ciphertexts
    :return: the initialization vector
    """
    p = oracle(bytes(32))
    return strxor(p[:16], p[16:])
