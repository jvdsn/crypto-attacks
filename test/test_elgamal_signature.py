import os
import sys
from math import gcd
from random import getrandbits
from random import randint
from unittest import TestCase

path = os.path.dirname(os.path.dirname(os.path.realpath(os.path.abspath(__file__))))
if sys.path[1] != path:
    sys.path.insert(1, path)

from attacks.elgamal_signature import nonce_reuse


class TestElgamalSignature(TestCase):
    def test_nonce_reuse(self):
        # Safe prime.
        p = 16902648776703029279
        g = 3
        x = randint(1, p - 2)
        k = p - 1
        while gcd(k, p - 1) != 1:
            k = randint(2, p - 2)

        r = pow(g, k, p)
        m1 = getrandbits(p.bit_length())
        s1 = pow(k, -1, p - 1) * (m1 - r * x) % (p - 1)
        m2 = getrandbits(p.bit_length())
        s2 = pow(k, -1, p - 1) * (m2 - r * x) % (p - 1)
        for k_, x_ in nonce_reuse.attack(p, m1, r, s1, m2, r, s2):
            self.assertIsInstance(k_, int)
            self.assertIsInstance(x_, int)
            if k_ == k and x_ == x:
                break
        else:
            self.fail()
