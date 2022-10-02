import os
import sys
from random import choice
from random import choices
from random import randrange
from unittest import TestCase

path = os.path.dirname(os.path.dirname(os.path.realpath(os.path.abspath(__file__))))
if sys.path[1] != path:
    sys.path.insert(1, path)

from attacks.lwe import arora_ge


class TestLWE(TestCase):
    def _generate_samples(self, q, m, n, E, s):
        A = []
        b = []
        for i in range(m):
            e = choice(E)
            A.append([randrange(0, q) for _ in range(n)])
            b.append(e)
            for j in range(n):
                b[i] = (b[i] + A[i][j] * s[j]) % q
        return A, b

    def test_arora_ge(self):
        q = 65537
        m = 200
        n = 10
        E = list(range(-1, 2))
        S = list(range(q))
        s = choices(S, k=n)
        A, b = self._generate_samples(q, m, n, E, s)
        s_ = arora_ge.attack(q, A, b, E)
        for i in range(n):
            self.assertIsInstance(s_[i], int)
            self.assertEqual(s[i], s_[i])

        m = 10
        n = 10
        E = list(range(-1, 2))
        S = list(range(2))
        s = choices(S, k=n)
        A, b = self._generate_samples(q, m, n, E, s)
        s_ = arora_ge.attack(q, A, b, E, S)
        for i in range(n):
            self.assertIsInstance(s_[i], int)
            self.assertEqual(s[i], s_[i])

        m = 150
        n = 10
        E = list(range(-2, 3))
        S = list(range(2))
        s = choices(S, k=n)
        A, b = self._generate_samples(q, m, n, E, s)
        s_ = arora_ge.attack(q, A, b, E, S)
        for i in range(n):
            self.assertIsInstance(s_[i], int)
            self.assertEqual(s[i], s_[i])
