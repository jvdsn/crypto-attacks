import os
import sys
from unittest import TestCase

path = os.path.dirname(os.path.dirname(os.path.realpath(os.path.abspath(__file__))))
if sys.path[1] != path:
    sys.path.insert(1, path)

from attacks.pseudoprimes import miller_rabin


class Pseudoprimes(TestCase):
    def test_miller_rabin(self):
        bases = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31]
        p, p1, p2, p3 = miller_rabin.generate_pseudoprime(bases, min_bitsize=512)
        self.assertIsInstance(p, int)
        self.assertIsInstance(p1, int)
        self.assertIsInstance(p2, int)
        self.assertIsInstance(p3, int)
        self.assertGreaterEqual(p.bit_length(), 512)
        self.assertEqual(p, p1 * p2 * p3)

        r = 0
        d = p - 1
        while d % 2 == 0:
            r += 1
            d //= 2

        for base in bases:
            self.assertTrue(pow(base, d, p) == 1 or pow(base, d, p) == p - 1)
