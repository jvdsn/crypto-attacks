import os
import sys
from unittest import TestCase

path = os.path.dirname(os.path.dirname(os.path.dirname(os.path.realpath(os.path.abspath(__file__)))))
if sys.path[1] != path:
    sys.path.insert(1, path)

from shared.ecc import generate_anomalous


class TestECC(TestCase):
    def test_generate_anomalous(self):
        q = 214667031558479219841849884722475668069
        gen = generate_anomalous(q=q)
        for _ in range(4):
            E = next(gen)
            self.assertEqual(E.trace_of_frobenius(), 1)

        gen = generate_anomalous(q_bit_length=128)
        for _ in range(4):
            E = next(gen)
            self.assertEqual(E.trace_of_frobenius(), 1)
