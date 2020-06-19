from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad
from Crypto.Util.Padding import unpad

zero_iv = bytes(16)
key = get_random_bytes(16)


# Notice how the key is used for encryption and authentication...
def _encrypt(p):
    p = pad(p, 16)
    iv = get_random_bytes(16)
    c = AES.new(key, AES.MODE_CBC, iv).encrypt(p)
    # Encrypt-and-MAC using CBC-MAC to prevent chosen-ciphertext attacks.
    t = AES.new(key, AES.MODE_CBC, zero_iv).encrypt(p)[-16:]
    return iv, c, t


def _decrypt(iv, c, t):
    p = AES.new(key, AES.MODE_CBC, iv).decrypt(c)
    t_ = AES.new(key, AES.MODE_CBC, zero_iv).encrypt(p)[-16:]
    # Check the MAC to be sure the message isn't forged.
    if t != t_:
        return None

    return unpad(p, 16)


def attack(iv, c, t):
    """
    Uses a chosen-ciphertext attack to decrypt the ciphertext.
    :param iv: the initialization vector
    :param c: the ciphertext
    :param t: the tag corresponding to the ciphertext
    :return: the plaintext
    """
    c_ = iv + c
    p_ = _decrypt(bytes(16), c_, c[-16:])
    return p_[16:]
