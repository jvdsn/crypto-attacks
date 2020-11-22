from Crypto.Util.strxor import strxor


def _attack_block(oracle, iv, c):
    r = bytes()
    for i in reversed(range(16)):
        s = bytes([16 - i] * (16 - i))
        for b in range(256):
            iv_ = bytes(i) + strxor(s, bytes([b]) + r)
            if oracle(iv_, c):
                r = bytes([b]) + r
                break
        else:
            raise ValueError(f"Unable to find decryption for {iv} and {c}")

    return strxor(iv, r)


def attack(oracle, iv, c):
    """
    Recovers the plaintext using the padding oracle attack.
    :param oracle: the padding oracle to check ciphertext padding
    :param iv: the initialization vector
    :param c: the ciphertext
    :return: the (padded) plaintext
    """
    p = _attack_block(oracle, iv, c[0:16])
    for i in range(16, len(c), 16):
        p += _attack_block(oracle, c[i - 16:i], c[i:i + 16])

    return p
