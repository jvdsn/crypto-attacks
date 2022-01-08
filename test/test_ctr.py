import os
import sys
from random import randbytes
from random import randint
from unittest import TestCase

from Crypto.Cipher import AES
from Crypto.Util import Counter

path = os.path.dirname(os.path.dirname(os.path.realpath(os.path.abspath(__file__))))
if sys.path[1] != path:
    sys.path.insert(1, path)

from attacks.ctr import separator_oracle


class TestCTR(TestCase):
    def _encrypt(self, key, p):
        return AES.new(key, AES.MODE_CTR, counter=Counter.new(128)).encrypt(p)

    def _valid_separators(self, separator_byte, separator_count, key, c):
        p = AES.new(key, AES.MODE_CTR, counter=Counter.new(128)).decrypt(c)
        return p.count(separator_byte) == separator_count

    def test_crime(self):
        # TODO: CRIME attack is too inconsistent in unit tests.
        pass

    def test_separator_oracle(self):
        separator_byte = ord("\x00")
        separator_count = randint(1, 10)
        key = randbytes(16)
        # We have to replace separators by some other byte.
        p = randbytes(16).replace(b"\x00", b"\x01")
        for _ in range(separator_count):
            # We have to replace separators by some other byte.
            p += bytes([separator_byte]) + randbytes(16).replace(b"\x00", b"\x01")

        c = self._encrypt(key, p)

        p_ = separator_oracle.attack(lambda c: self._valid_separators(separator_byte, separator_count, key, c), separator_byte, c)
        self.assertEqual(p, p_)
