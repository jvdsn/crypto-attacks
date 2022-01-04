import os
import sys
from random import randbytes
from unittest import TestCase

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

path = os.path.dirname(os.path.dirname(os.path.realpath(os.path.abspath(__file__))))
if sys.path[1] != path:
    sys.path.insert(1, path)

from attacks.ecb import plaintext_recovery


class TestECB(TestCase):
    def _encrypt(self, key, p):
        return AES.new(key, AES.MODE_ECB).encrypt(p)

    def test_plaintext_recovery(self):
        for i in range(33):
            key = randbytes(16)
            s = randbytes(i)

            s_ = plaintext_recovery.attack(lambda p: self._encrypt(key, pad(p + s, 16)))
            self.assertEqual(s, s_)
