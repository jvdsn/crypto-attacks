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
    # MAC-then-encrypt using CBC-MAC to prevent chosen-ciphertext attacks.
    t = AES.new(key, AES.MODE_CBC, zero_iv).encrypt(p)[-16:]
    c = AES.new(key, AES.MODE_CBC, iv).encrypt(p + t)
    return iv, c


def _decrypt(iv, c):
    d = AES.new(key, AES.MODE_CBC, iv).decrypt(c)
    p = d[:-16]
    t = d[-16:]
    t_ = AES.new(key, AES.MODE_CBC, zero_iv).encrypt(p)[-16:]
    # Check the MAC to be sure the message isn't forged.
    if t != t_:
        return None

    return unpad(p, 16)


def attack(iv, c, encrypted_zeroes):
    """
    Uses a chosen-ciphertext attack to decrypt the ciphertext.
    Prior knowledge of E_k(0^16) is required for this attack to work.
    :param iv: the initialization vector
    :param c: the ciphertext
    :param encrypted_zeroes: a full zero block encrypted using the key
    :return: the plaintext
    """
    c_ = iv + c[:-16] + encrypted_zeroes
    p_ = _decrypt(bytes(16), c_)
    return p_[16:]
