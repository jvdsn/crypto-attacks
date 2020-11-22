import random
from unittest import TestCase

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Util.Padding import unpad


def _randbytes(n):
    # TODO: replace this with random.randbytes when python 3.9 is widely available.
    return bytes(random.getrandbits(8) for _ in range(n))


class TestCBC(TestCase):
    from cbc import bit_flipping
    from cbc import iv_recovery
    from cbc import padding_oracle

    def _encrypt_cbc(self, key, p):
        iv = _randbytes(16)
        cipher = AES.new(key, mode=AES.MODE_CBC, iv=iv)
        c = cipher.encrypt(pad(p, 16))
        return iv, c

    def _decrypt_cbc(self, key, iv, c):
        cipher = AES.new(key, mode=AES.MODE_CBC, iv=iv)
        p = unpad(cipher.decrypt(c), 16)
        return p

    def _valid_padding(self, key, iv, c):
        try:
            cipher = AES.new(key, mode=AES.MODE_CBC, iv=iv)
            unpad(cipher.decrypt(c), 16)
            return True
        except ValueError:
            return False

    def test_bit_flipping(self):
        key = _randbytes(16)
        p = _randbytes(32)
        p_ = _randbytes(16)
        iv, c = self._encrypt_cbc(key, p)

        iv_, c_ = self.bit_flipping.attack(iv, c, 16, p[16:16 + len(p_)], p_)

        p__ = self._decrypt_cbc(key, iv_, c_)
        self.assertEqual(p_, p__[16:16 + len(p_)])

    def test_iv_recovery(self):
        key = _randbytes(16)
        iv = _randbytes(16)

        iv_ = self.iv_recovery.attack(lambda c: self._decrypt_cbc(key, iv, c))
        self.assertEqual(iv, iv_)

    def test_padding_oracle(self):
        key = _randbytes(16)

        for i in range(16):
            p = _randbytes(i + 1)
            iv, c = self._encrypt_cbc(key, p)
            p_ = self.padding_oracle.attack(lambda iv_, c_: self._valid_padding(key, iv_, c_), iv, c)
            self.assertEqual(pad(p, 16), p_)
