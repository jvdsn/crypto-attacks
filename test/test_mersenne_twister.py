import os
import random
import sys
from unittest import TestCase

path = os.path.dirname(os.path.dirname(os.path.realpath(os.path.abspath(__file__))))
if sys.path[1] != path:
    sys.path.insert(1, path)

from attacks import mersenne_twister
from attacks.mersenne_twister import state_recovery


class TestMersenneTwister(TestCase):
    def test_state_recovery(self):
        mt = mersenne_twister.mt19937()
        mt.seed(1812433253, 0)
        y = [next(mt) for _ in range(mt.n)]
        mt_ = state_recovery.attack_mt19937(y)
        self.assertEqual(mt.mt, mt_.mt)
        self.assertEqual(mt.index, mt_.index)
        for i in range(mt.n):
            self.assertEqual(next(mt), next(mt_))

        mt = mersenne_twister.mt19937()
        mt.seed(1812433253, 1234567)
        y = [next(mt) for _ in range(mt.n)]
        mt_ = state_recovery.attack_mt19937(y)
        self.assertEqual(mt.mt, mt_.mt)
        self.assertEqual(mt.index, mt_.index)
        for i in range(mt.n):
            self.assertEqual(next(mt), next(mt_))

        random.seed(1234567)
        y = [random.getrandbits(32) for _ in range(624)]
        mt_ = state_recovery.attack_mt19937(y)
        for i in range(624):
            self.assertEqual(random.getrandbits(32), next(mt_))

        mt = mersenne_twister.mt19937_64()
        mt.seed(6364136223846793005, 0)
        y = [next(mt) for _ in range(mt.n)]
        mt_ = state_recovery.attack_mt19937_64(y)
        self.assertEqual(mt.mt, mt_.mt)
        self.assertEqual(mt.index, mt_.index)
        for i in range(mt.n):
            self.assertEqual(next(mt), next(mt_))

        mt = mersenne_twister.mt19937_64()
        mt.seed(6364136223846793005, 1234567)
        y = [next(mt) for _ in range(mt.n)]
        mt_ = state_recovery.attack_mt19937_64(y)
        self.assertEqual(mt.mt, mt_.mt)
        self.assertEqual(mt.index, mt_.index)
        for i in range(mt.n):
            self.assertEqual(next(mt), next(mt_))
