import os
import sys
from random import randrange
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
        for _ in range(100):
            x = randrange(1, p)
            h = pow(g, x, p)
            y = randrange(1, p)
            s = pow(h, y, p)
            m = randrange(1, p)
            c1 = pow(g, y, p)
            c2 = m * s % p
            m_ = randrange(1, p)
            c1_ = pow(g, y, p)
            c2_ = m_ * s % p
            m__ = nonce_reuse.attack(p, m, c1, c2, c1_, c2_)
            self.assertIsInstance(m__, int)
            self.assertEqual(m_, m__)

    def test_unsafe_generator(self):
        # Safe prime.
        p = 16902648776703029279
        # Unsafe generator, generates the entire group.
        g = 7
        for _ in range(100):
            x = randrange(1, p)
            h = pow(g, x, p)
            y = randrange(1, p)
            s = pow(h, y, p)
            m = randrange(1, p)
            c1 = pow(g, y, p)
            c2 = m * s % p
            k = unsafe_generator.attack(p, h, c1, c2)
            self.assertIsInstance(k, int)
            self.assertEqual(legendre_symbol(m, p), k)
