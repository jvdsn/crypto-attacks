import os
import sys
from random import randbytes
from unittest import TestCase

from Crypto.Cipher import AES

path = os.path.dirname(os.path.dirname(os.path.realpath(os.path.abspath(__file__))))
if sys.path[1] != path:
    sys.path.insert(1, path)

from attacks.cbc_mac import length_extension


class TestCBCMAC(TestCase):
    def _compute_tag(self, key, m):
        return AES.new(key, AES.MODE_CBC, bytes(16)).encrypt(m)[-16:]

    def _verify_tag(self, key, m, t):
        t_ = AES.new(key, AES.MODE_CBC, bytes(16)).encrypt(m)[-16:]
        return t == t_

    def test_length_extension(self):
        key = randbytes(16)
        m1 = randbytes(32)
        t1 = self._compute_tag(key, m1)
        m2 = randbytes(32)
        t2 = self._compute_tag(key, m2)

        m3, t3 = length_extension.attack(m1, t1, m2, t2)
        self.assertTrue(self._verify_tag(key, m3, t3))
