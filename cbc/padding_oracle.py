from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad
from Crypto.Util.Padding import unpad

key = get_random_bytes(16)


def _encrypt(p):
    iv = get_random_bytes(16)
    return iv, AES.new(key, AES.MODE_CBC, iv).encrypt(pad(p, 16))


def _valid_padding(iv, c):
    try:
        unpad(AES.new(key, AES.MODE_CBC, iv).decrypt(c), 16)
        return True
    except ValueError:
        return False


def _correct_padding(iv, c, i):
    if not _valid_padding(iv, c):
        return False

    # Special handling for last byte of last block
    if i == 15:
        iv[14] ^= 1
        return _valid_padding(iv, c)

    return True


def _attack_block(iv, c):
    dc = bytearray(16)
    p = bytearray(16)
    iv_ = bytearray(iv)
    for i in reversed(range(16)):
        # The padding byte for this position.
        pb = 16 - i
        # Apply padding byte to iv.
        for j in reversed(range(i + 1, 16)):
            iv_[j] = dc[j] ^ pb

        # Try every byte until padding is correct.
        for b in range(256):
            iv_[i] = b
            if _correct_padding(iv_, c, i):
                dc[i] = b ^ pb
                p[i] = dc[i] ^ iv[i]

    return p


def attack(iv, c):
    """
    Recovers the plaintext using the padding oracle attack.
    :param iv: the initialization vector
    :param c: the ciphertext
    :return: the plaintext
    """
    p = _attack_block(iv, c)
    for i in range(16, len(c), 16):
        p += _attack_block(c[i - 16:i], c[i:i + 16])

    return unpad(p, 16)
