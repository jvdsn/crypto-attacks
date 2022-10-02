import os
import sys
from unittest import TestCase

path = os.path.dirname(os.path.dirname(os.path.realpath(os.path.abspath(__file__))))
if sys.path[1] != path:
    sys.path.insert(1, path)

from attacks.pseudoprimes import miller_rabin


class TestPseudoprimes(TestCase):
    def _miller_rabin(self, n, bases):
        assert n > 3
        r = 0
        d = n - 1
        while d % 2 == 0:
            r += 1
            d //= 2

        for a in bases:
            x = pow(a, d, n)
            if x == 1 or x == n - 1:
                continue
            for _ in range(r - 1):
                x = pow(x, 2, n)
                if x == n - 1:
                    break
            else:
                return False
        return True

    def test_miller_rabin(self):
        bases = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31]
        n, p1, p2, p3 = miller_rabin.generate_pseudoprime(bases, min_bit_length=400)
        self.assertIsInstance(n, int)
        self.assertIsInstance(p1, int)
        self.assertIsInstance(p2, int)
        self.assertIsInstance(p3, int)
        self.assertGreaterEqual(n.bit_length(), 400)
        self.assertEqual(n, p1 * p2 * p3)
        self.assertTrue(self._miller_rabin(n, bases))

        bases = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61]
        n, p1, p2, p3 = miller_rabin.generate_pseudoprime(bases, min_bit_length=600)
        self.assertIsInstance(n, int)
        self.assertIsInstance(p1, int)
        self.assertIsInstance(p2, int)
        self.assertIsInstance(p3, int)
        self.assertGreaterEqual(n.bit_length(), 600)
        self.assertEqual(n, p1 * p2 * p3)
        self.assertTrue(self._miller_rabin(n, bases))
