import os
import sys
from random import randbytes
from unittest import TestCase

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Util.Padding import unpad
from Crypto.Util.strxor import strxor

path = os.path.dirname(os.path.dirname(os.path.realpath(os.path.abspath(__file__))))
if sys.path[1] != path:
    sys.path.insert(1, path)

from attacks.ige import padding_oracle


class TestIGE(TestCase):
    def _encrypt(self, key, p):
        p0 = randbytes(16)
        c0 = randbytes(16)
        cipher = AES.new(key, mode=AES.MODE_ECB)

        p_last = p0
        c_last = c0
        c = bytearray()
        for i in range(0, len(p), 16):
            p_i = p[i:i + 16]
            c_i = strxor(cipher.encrypt(strxor(p_i, c_last)), p_last)
            p_last = p_i
            c_last = c_i
            c += c_i

        return p0, c0, c

    def _valid_padding(self, key, p0, c0, c):
        try:
            cipher = AES.new(key, mode=AES.MODE_ECB)
            p_last = p0
            c_last = c0
            p = bytearray()
            for i in range(0, len(c), 16):
                c_i = c[i:i + 16]
                p_i = strxor(cipher.decrypt(strxor(c_i, p_last)), c_last)
                p_last = p_i
                c_last = c_i
                p += p_i

            unpad(p, 16)
            return True
        except ValueError:
            return False

    def test_padding_oracle(self):
        key = randbytes(16)

        for i in range(16):
            p = pad(randbytes(i + 1), 16)
            p0, c0, c = self._encrypt(key, p)
            p_ = padding_oracle.attack(lambda p0, c0, c: self._valid_padding(key, p0, c0, c), p0, c0, c)
            self.assertEqual(p, p_)
