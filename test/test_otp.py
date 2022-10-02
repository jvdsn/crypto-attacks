import os
import sys
from math import log10
from unittest import TestCase

path = os.path.dirname(os.path.dirname(os.path.realpath(os.path.abspath(__file__))))
if sys.path[1] != path:
    sys.path.insert(1, path)

from attacks.otp import key_reuse


class TestOTP(TestCase):
    def test_key_reuse(self):
        # Source: http://pi.math.cornell.edu/~mec/2003-2004/cryptography/subs/frequencies.html
        char_frequencies = {"a": 8.12, "b": 1.49, "c": 2.71, "d": 4.32, "e": 12.02, "f": 2.30, "g": 2.03, "h": 5.92, "i": 7.31, "j": 0.10, "k": 0.69, "l": 3.98, "m": 2.61, "n": 6.95, "o": 7.68, "p": 1.82, "q": 0.11, "r": 6.02, "s": 6.28, "t": 9.10, "u": 2.88, "v": 1.11, "w": 2.09, "x": 0.17, "y": 2.11, "z": 0.07}
        char_floor = log10(0.01 / 182303)

        key = bytes.fromhex("4d4e2acd3248a5b5ecb106cff94cf10623979966f49a7fd020e395f31c58f0151b9fc78b24b5cf205efee937a8")
        lines = [
            b"I used to rule the world\n",
            b"Seas would rise when I gave the word\n",
            b"Now in the morning, I sleep alone\n",
            b"Sweep the streets I used to own\n",
            b"I used to roll the dice\n",
            b"Feel the fear in my enemy's eyes\n",
            b"Listened as the crowd would sing\n",
            b"Now the old king is dead, long live the king\n",
            b"One minute I held the key\n",
            b"Next, the walls were closed on me\n",
            b"And I discovered that my castles stand\n",
            b"Upon pillars of salt and pillars of sand\n",
            b"I hear Jerusalem bells a-ringing\n",
            b"Roman cavalry choirs are singing\n",
            b"Be my mirror, my sword and shield\n",
            b"My missionaries in a foreign field\n",
            b"For some reason, I can't explain\n",
            b"Once you'd gone, there was never\n",
            b"Never an honest word\n",
            b"And that was when I ruled the world\n",
            b"It was a wicked and wild wind\n",
            b"Blew down the doors to let me in\n",
            b"Shattered windows and the sound of drums\n",
            b"People couldn't believe what I'd become\n",
            b"Revolutionaries wait\n",
            b"For my head on a silver plate\n",
            b"Just a puppet on a lonely string (Mmm, mmm)\n",
            b"Oh, who would ever want to be king?\n",
            b"I hear Jerusalem bells a-ringing\n",
            b"Roman cavalry choirs are singing\n",
            b"Be my mirror, my sword and shield\n",
            b"My missionaries in a foreign field\n",
            b"For some reason, I can't explain\n",
            b"I know Saint Peter won't call my name\n",
            b"Never an honest word\n",
            b"But that was when I ruled the world\n",
        ]

        test_known = {
            1: {1: 0, 2: 0, 4: 1, 5: 3},
            3: {1: 0, 2: 0, 4: 1, 6: 1, 7: 0, 12: 4},
            6: {1: 0, 2: 0, 4: 0, 6: 0, 7: 0, 12: 0, 16: 3},
            36: {1: 0, 2: 0, 4: 0, 6: 0, 7: 0, 12: 0, 16: 0, 24: 0, 30: 0, 36: 3, 45: 12},
        }

        for c_size, key_sizes in test_known.items():
            for key_size, diff in key_sizes.items():
                c = [bytes([b ^ key[i % key_size] for i, b in enumerate(line)]) for line in lines[:c_size]]
                key_ = key_reuse.attack(c, char_frequencies, char_floor, key_size=key_size)
                self.assertEqual(key_size, len(key_))
                self.assertEqual(diff, sum(x != y for x, y in zip(key, key_)))

        test_unknown = {
            1: {5: 3},
            3: {7: 0, 12: 4},
            6: {7: 0, 12: 0, 16: 3},
            36: {4: 0, 6: 0, 7: 0, 12: 0, 16: 0, 24: 0, 30: 0, 36: 3},
        }

        for c_size, key_sizes in test_unknown.items():
            for key_size, diff in key_sizes.items():
                c = [bytes([b ^ key[i % key_size] for i, b in enumerate(line)]) for line in lines[:c_size]]
                key_ = key_reuse.attack(c, char_frequencies, char_floor)
                self.assertEqual(key_size, len(key_))
                self.assertEqual(diff, sum(x != y for x, y in zip(key, key_)))
