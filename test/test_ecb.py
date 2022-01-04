import os
import sys
from random import choices
from random import randint
from unittest import TestCase

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

path = os.path.dirname(os.path.dirname(os.path.realpath(os.path.abspath(__file__))))
if sys.path[1] != path:
    sys.path.insert(1, path)

from attacks.ecb import plaintext_recovery
from attacks.ecb import plaintext_recovery_harder
from attacks.ecb import plaintext_recovery_hardest


class TestECB(TestCase):
    bytes = list(range(1, 256))

    def _randbytes(self, k):
        return bytes(choices(self.bytes, k=k))

    def _encrypt(self, key, p):
        return AES.new(key, AES.MODE_ECB).encrypt(p)

    def test_plaintext_recovery(self):
        key = self._randbytes(16)
        for i in [0, 1, 2, 15, 16, 17, 31, 32]:
            s = self._randbytes(i)
            s_ = plaintext_recovery.attack(lambda p: self._encrypt(key, pad(p + s, 16)))
            self.assertEqual(s, s_)

    def test_plaintext_recovery_harder(self):
        key = self._randbytes(16)
        for i in range(16):
            prefix = self._randbytes(i)
            for j in [0, 1, 2, 15, 16, 17, 31, 32]:
                s = self._randbytes(j)
                s_ = plaintext_recovery_harder.attack(lambda p: self._encrypt(key, pad(prefix + p + s, 16)))
                self.assertEqual(s, s_)

    def test_plaintext_recovery_hardest(self):
        key = self._randbytes(16)
        for i in [0, 1, 2, 15, 16, 17, 31, 32]:
            s = self._randbytes(i)
            s_ = plaintext_recovery_hardest.attack(lambda p: self._encrypt(key, pad(self._randbytes(randint(0, 15)) + p + s, 16)))
            self.assertEqual(s, s_)
