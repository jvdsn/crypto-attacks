import os
import sys
from random import randbytes
from unittest import TestCase

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Util.Padding import unpad

path = os.path.dirname(os.path.dirname(os.path.realpath(os.path.abspath(__file__))))
if sys.path[1] != path:
    sys.path.insert(1, path)

from attacks.cbc import bit_flipping
from attacks.cbc import iv_recovery
from attacks.cbc import padding_oracle


class TestCBC(TestCase):
    def _encrypt(self, key, p):
        iv = randbytes(16)
        cipher = AES.new(key, mode=AES.MODE_CBC, iv=iv)
        c = cipher.encrypt(p)
        return iv, c

    def _decrypt(self, key, iv, c):
        cipher = AES.new(key, mode=AES.MODE_CBC, iv=iv)
        p = cipher.decrypt(c)
        return p

    def _valid_padding(self, key, iv, c):
        try:
            cipher = AES.new(key, mode=AES.MODE_CBC, iv=iv)
            unpad(cipher.decrypt(c), 16)
            return True
        except ValueError:
            return False

    def test_bit_flipping(self):
        key = randbytes(16)
        p = randbytes(32)
        p_ = randbytes(16)
        iv, c = self._encrypt(key, p)

        iv_, c_ = bit_flipping.attack(iv, c, 0, p[0:len(p_)], p_)
        p__ = self._decrypt(key, iv_, c_)
        self.assertEqual(p_, p__[0:len(p_)])

        iv_, c_ = bit_flipping.attack(iv, c, 16, p[16:16 + len(p_)], p_)
        p__ = self._decrypt(key, iv_, c_)
        self.assertEqual(p_, p__[16:16 + len(p_)])

    def test_iv_recovery(self):
        key = randbytes(16)
        iv = randbytes(16)
        iv_ = iv_recovery.attack(lambda c: self._decrypt(key, iv, c))
        self.assertEqual(iv, iv_)

    def test_padding_oracle(self):
        key = randbytes(16)
        for i in range(16):
            p = pad(randbytes(i + 1), 16)
            iv, c = self._encrypt(key, p)
            p_ = padding_oracle.attack(lambda iv, c: self._valid_padding(key, iv, c), iv, c)
            self.assertEqual(p, p_)
