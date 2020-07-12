from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad
from Crypto.Util.Padding import unpad
from Crypto.Util.strxor import strxor

key = get_random_bytes(16)


def _encrypt(p):
    aes = AES.new(key, AES.MODE_ECB)
    p = pad(p, 16)
    p0 = get_random_bytes(16)
    c0 = get_random_bytes(16)

    p_last = p0
    c_last = c0
    c = bytearray()
    for i in range(0, len(p), 16):
        p_i = p[i:i + 16]
        c_i = strxor(aes.encrypt(strxor(p_i, c_last)), p_last)
        p_last = p_i
        c_last = c_i
        c += c_i

    return p0, c0, c


def _decrypt(p0, c0, c):
    aes = AES.new(key, AES.MODE_ECB)

    p_last = p0
    c_last = c0
    p = bytearray()
    for i in range(0, len(c), 16):
        c_i = c[i:i + 16]
        p_i = strxor(aes.decrypt(strxor(c_i, p_last)), c_last)
        p_last = p_i
        c_last = c_i
        p += p_i

    return unpad(p, 16)


def _valid_padding(p0, c0, c):
    try:
        _decrypt(p0, c0, c)
        return True
    except ValueError:
        return False


def _correct_padding(p0, c0, c, i):
    if not _valid_padding(p0, c0, c):
        return False

    # Special handling for last byte of last block
    if i == 15:
        c0[14] ^= 1
        return _valid_padding(p0, c0, c)

    return True


def _attack_block(p0, c0, c):
    dc = bytearray(16)
    p = bytearray(16)
    c0_ = bytearray(c0)
    for i in reversed(range(16)):
        # The padding byte for this position.
        pb = 16 - i
        # Apply padding byte to c0.
        for j in reversed(range(i + 1, 16)):
            c0_[j] = dc[j] ^ pb

        # Try every byte until padding is correct.
        for b in range(256):
            c0_[i] = b
            if _correct_padding(p0, c0_, c, i):
                dc[i] = b ^ pb
                p[i] = dc[i] ^ c0[i]

    return p


def attack(p0, c0, c):
    """
    Recovers the plaintext using the padding oracle attack.
    :param p0: the initial plaintext block
    :param c0: the initial ciphertext block
    :param c: the ciphertext
    :return: the plaintext
    """
    p = _attack_block(p0, c0, c[0:16])
    for i in range(16, len(c), 16):
        p += _attack_block(p[i - 16:i], c[i - 16:i], c[i:i + 16])

    return unpad(p, 16)
