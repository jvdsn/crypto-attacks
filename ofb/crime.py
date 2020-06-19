import zlib

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

key = get_random_bytes(16)
secret = get_random_bytes(16)


def _encrypt(p):
    return AES.new(key, AES.MODE_OFB).encrypt(zlib.compress(p + secret))


def attack(secret_len):
    """
    Recovers a secret using the CRIME attack (OFB version).
    :param secret_len: the length of the secret to recover
    :return: the secret
    """
    padding = bytearray()
    for i in range(secret_len):
        padding.append(i)

    s = bytearray()
    for i in range(secret_len):
        min = None
        for j in range(256):
            l = len(_encrypt(padding + s + bytes([j]) + padding))
            if min is None or l < min[0]:
                min = (l, j)

        s.append(min[1])

    return bytes(s)
