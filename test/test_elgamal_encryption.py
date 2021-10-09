import os
import sys
from random import getrandbits
from random import randint
from unittest import TestCase

from sage.all import legendre_symbol

path = os.path.dirname(os.path.dirname(os.path.realpath(os.path.abspath(__file__))))
if sys.path[1] != path:
    sys.path.insert(1, path)

from attacks.elgamal_encryption import nonce_reuse
from attacks.elgamal_encryption import unsafe_generator


class TestElgamalEncryption(TestCase):
    def test_nonce_reuse(self):
        # Safe prime.
        p = 16902648776703029279
        g = 3
        d = randint(1, p - 1)
        h = pow(g, d, p)
        l = randint(1, p - 1)
        s = pow(h, p, l)
        c = pow(g, l, p)
        m1 = getrandbits(p.bit_length())
        d1 = m1 * s % p
        m2 = getrandbits(p.bit_length())
        d2 = m2 * s % p
        m2_ = nonce_reuse.attack(p, m1, c, d1, c, d2)
        self.assertIsInstance(m2_, int)
        self.assertEqual(m2, m2_)

    def test_unsafe_generator(self):
        # Safe prime.
        p = 16902648776703029279
        # Unsafe generator, generates the entire group.
        g = 7
        for i in range(100):
            x = randint(1, p - 1)
            h = pow(g, x, p)
            y = randint(1, p - 1)
            s = pow(h, y, p)
            c1 = pow(g, y, p)
            m = randint(1, p - 1)
            c2 = m * s % p
            k = unsafe_generator.attack(p, h, c1, c2)
            self.assertIsInstance(k, int)
            self.assertEqual(legendre_symbol(m, p), k)
