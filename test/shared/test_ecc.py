import os
import sys
from unittest import TestCase

path = os.path.dirname(os.path.dirname(os.path.dirname(os.path.realpath(os.path.abspath(__file__)))))
if sys.path[1] != path:
    sys.path.insert(1, path)

from shared.ecc import generate_anomalous
from shared.ecc import generate_anomalous_q
from shared.ecc import generate_supersingular
from shared.ecc import generate_with_order
from shared.ecc import generate_with_order_q
from shared.ecc import generate_with_trace
from shared.ecc import generate_with_trace_q


class TestECC(TestCase):
    def test_generate_anomalous_q(self):
        q = 214667031558479219841849884722475668069
        gen = generate_anomalous_q(q)
        for _ in range(4):
            E = next(gen)
            self.assertEqual(E.trace_of_frobenius(), 1)

    def test_generate_anomalous(self):
        gen = generate_anomalous(128)
        for _ in range(4):
            E = next(gen)
            self.assertEqual(E.trace_of_frobenius(), 1)

    def test_generate_with_trace_q(self):
        t = 1234
        q = 548567
        gen = generate_with_trace_q(t, q)
        for _ in range(4):
            E = next(gen)
            self.assertEqual(E.trace_of_frobenius(), t)

    def test_generate_with_trace(self):
        t = 1234
        gen = generate_with_trace(t, 128)
        for _ in range(4):
            E = next(gen)
            self.assertEqual(E.trace_of_frobenius(), t)

    def test_generate_with_order_q(self):
        m = 548567 + 1 - 1234
        q = 548567
        gen = generate_with_order_q(m, q)
        for _ in range(4):
            E = next(gen)
            self.assertEqual(E.order(), m)

    def test_generate_with_order(self):
        m = 2 ** 64 + 1
        gen = generate_with_order(m)
        for _ in range(4):
            E = next(gen)
            self.assertEqual(E.order(), m)

    def test_generate_supersingular(self):
        for p in [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71]:
            for n in range(1, 5):
                q = p ** n
                gen = generate_supersingular(q)
                for _ in range(4):
                    E = next(gen)
                    self.assertTrue(E.is_supersingular())

        q = 214667031558479219841849884722475668069
        gen = generate_supersingular(q)
        for _ in range(4):
            E = next(gen)
            self.assertTrue(E.is_supersingular())
