import os
import sys
from hashlib import sha256
from random import randrange
from unittest import TestCase

from sage.all import GF

path = os.path.dirname(os.path.dirname(os.path.realpath(os.path.abspath(__file__))))
if sys.path[1] != path:
    sys.path.insert(1, path)

from attacks.shamir_secret_sharing import deterministic_coefficients
from attacks.shamir_secret_sharing import share_forgery


class TestShamirSecretSharing(TestCase):
    def _eval(self, p, a, x):
        y = 0
        for i, ai in enumerate(a):
            y += ai * x ** i
        return y % p

    def test_deterministic_coefficients(self):
        p = 3615438361
        k = 15
        n = 20
        s = randrange(1, p)
        f = lambda ai: int.from_bytes(sha256(ai.to_bytes(32, byteorder="big")).digest(), byteorder="big")

        a = [s]
        for i in range(1, n + 1):
            a.append(f(a[i - 1]))
        a = a[:k]

        xs = []
        ys = []
        for i in range(n):
            x = randrange(1, p)
            xs.append(x)
            y = self._eval(p, a, x)
            ys.append(y)

        s_ = deterministic_coefficients.attack(p, k, a[1], f, xs[0], ys[0])
        self.assertIsInstance(s_, int)
        self.assertEqual(s_, s)

    def test_share_forgery(self):
        p = 4224273359
        k = 15
        n = 20
        s = randrange(1, p)
        s_ = randrange(1, p)

        a = [s]
        for i in range(1, n + 1):
            a.append(randrange(1, p))
        a = a[:k]

        xs = []
        ys = []
        for i in range(n):
            x = randrange(1, p)
            xs.append(x)
            y = self._eval(p, a, x)
            ys.append(y)

        ys[0] = share_forgery.attack(p, s, s_, xs[0], ys[0], xs[1:])
        self.assertIsInstance(ys[0], int)
        self.assertEqual(s_, GF(p)["x"].lagrange_polynomial(zip(xs, ys)).constant_coefficient())
