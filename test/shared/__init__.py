import os
import sys
from unittest import TestCase

from sage.all import GF

path = os.path.dirname(os.path.dirname(os.path.dirname(os.path.realpath(os.path.abspath(__file__)))))
if sys.path[1] != path:
    sys.path.insert(1, path)

from shared import rth_roots

class TestShared(TestCase):
    def test_rth_roots(self):
        q = 9908484735485245740582755998843475068910570989512225739800304203500256711207262150930812622460031920899674919818007279858208368349928684334780223996774347
        c = 7267288183214469410349447052665186833632058119533973432573869246434984462336560480880459677870106195135869371300420762693116774837763418518542884912967719
        e = 21
        self.assertEqual(len(set(rth_roots(GF(q), c, e))), 7)
