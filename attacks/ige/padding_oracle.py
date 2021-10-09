import logging

from Crypto.Util.strxor import strxor


def _attack_block(padding_oracle, p0, c0, c):
    logging.info(f"Attacking block {c.hex()}...")
    r = bytes()
    for i in reversed(range(16)):
        s = bytes([16 - i] * (16 - i))
        for b in range(256):
            c0_ = bytes(i) + strxor(s, bytes([b]) + r)
            if padding_oracle(p0, c0_, c):
                r = bytes([b]) + r
                break
        else:
            raise ValueError(f"Unable to find decryption for {s}, {p0}, {c0}, and {c}")

    return strxor(c0, r)


def attack(padding_oracle, p0, c0, c):
    """
    Recovers the plaintext using the padding oracle attack.
    :param padding_oracle: the padding oracle, returns True if the padding is correct, False otherwise
    :param p0: the initial plaintext block
    :param c0: the initial ciphertext block
    :param c: the ciphertext
    :return: the (padded) plaintext
    """
    p = _attack_block(padding_oracle, p0, c0, c[0:16])
    for i in range(16, len(c), 16):
        p += _attack_block(padding_oracle, p[i - 16:i], c[i - 16:i], c[i:i + 16])

    return p
