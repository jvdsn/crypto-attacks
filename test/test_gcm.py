import os
import sys
from random import randbytes
from unittest import TestCase

from Crypto.Cipher import AES

path = os.path.dirname(os.path.dirname(os.path.realpath(os.path.abspath(__file__))))
if sys.path[1] != path:
    sys.path.insert(1, path)

from attacks.gcm import forbidden_attack


class TestGCM(TestCase):
    def test_forbidden_attack(self):
        key = randbytes(16)
        iv = randbytes(16)
        aes = AES.new(key, AES.MODE_GCM, nonce=iv)
        a1 = randbytes(16)
        p1 = randbytes(16)
        aes.update(a1)
        c1, t1 = aes.encrypt_and_digest(p1)
        aes = AES.new(key, AES.MODE_GCM, nonce=iv)
        a2 = randbytes(16)
        p2 = randbytes(16)
        aes.update(a2)
        c2, t2 = aes.encrypt_and_digest(p2)
        for h in forbidden_attack.recover_possible_auth_keys(a1, c1, t1, a2, c2, t2):
            target_a = randbytes(16)
            target_c = randbytes(16)
            forged_t = forbidden_attack.forge_tag(h, a1, c1, t1, target_a, target_c)
            try:
                aes = AES.new(key, AES.MODE_GCM, nonce=iv)
                aes.update(target_a)
                aes.decrypt_and_verify(target_c, forged_t)
                break
            except ValueError:
                # Authentication failed, so we try the next authentication key.
                continue
        else:
            self.fail()
