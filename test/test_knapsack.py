import os
import sys
from unittest import TestCase

path = os.path.dirname(os.path.dirname(os.path.realpath(os.path.abspath(__file__))))
if sys.path[1] != path:
    sys.path.insert(1, path)

from attacks.knapsack import low_density


class TestKnapsack(TestCase):
    def test_low_density(self):
        a = [429970831622, 650002882675, 512682138397, 145532365100, 462119415111, 357461497167, 582429951539, 22657777498, 2451348134, 380282710854, 251660920136, 103765486463, 276100153517, 250012242739, 519736909707, 451460714161]
        s = 5398327344820
        e = low_density.attack(a, s)
        for i in range(len(a)):
            self.assertIsInstance(e[i], int)
        self.assertEqual(e, [1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1])

        a = [23449054409, 58564582991, 24739686534, 30995859145, 16274600764, 13384701522, 45782350364, 10685194276, 18864211511, 9594013152, 50215903866, 7952180124, 42094717093, 50866816333, 44318421949, 31143511315]
        s = 42313265920
        e = low_density.attack(a, s)
        for i in range(len(a)):
            self.assertIsInstance(e[i], int)
        self.assertEqual(e, [1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0])
