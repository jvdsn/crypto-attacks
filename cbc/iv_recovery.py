from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.strxor import strxor

key = get_random_bytes(16)


def _encrypt(p):
    return AES.new(key, AES.MODE_CBC, key).encrypt(p)


def _decrypt(c):
    return AES.new(key, AES.MODE_CBC, key).decrypt(c)


def attack():
    """
    Recovers the initialization vector using a chosen-ciphertext attack.
    :return: the initialization vector
    """
    p = _decrypt(bytes(32))
    return strxor(p[:16], p[16:])
