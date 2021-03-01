import sys
from math import gcd
from random import getrandbits
from random import randbytes
from random import randint
from unittest import TestCase

from Crypto.Cipher import AES
from Crypto.Util import Counter
from Crypto.Util.Padding import pad
from Crypto.Util.Padding import unpad
from Crypto.Util.strxor import strxor
from sage.all import EllipticCurve
from sage.all import GF
from sage.all import legendre_symbol


class TestCBC(TestCase):
    from cbc import bit_flipping
    from cbc import iv_recovery
    from cbc import padding_oracle

    def _encrypt(self, key, p):
        iv = randbytes(16)
        cipher = AES.new(key, mode=AES.MODE_CBC, iv=iv)
        c = cipher.encrypt(p)
        return iv, c

    def _decrypt(self, key, iv, c):
        cipher = AES.new(key, mode=AES.MODE_CBC, iv=iv)
        p = cipher.decrypt(c)
        return p

    def _valid_padding(self, key, iv, c):
        try:
            cipher = AES.new(key, mode=AES.MODE_CBC, iv=iv)
            unpad(cipher.decrypt(c), 16)
            return True
        except ValueError:
            return False

    def test_bit_flipping(self):
        key = randbytes(16)
        p = randbytes(32)
        p_ = randbytes(16)
        iv, c = self._encrypt(key, p)

        iv_, c_ = self.bit_flipping.attack(iv, c, 0, p[0:len(p_)], p_)

        p__ = self._decrypt(key, iv_, c_)
        self.assertEqual(p_, p__[0:len(p_)])

        iv_, c_ = self.bit_flipping.attack(iv, c, 16, p[16:16 + len(p_)], p_)

        p__ = self._decrypt(key, iv_, c_)
        self.assertEqual(p_, p__[16:16 + len(p_)])

    def test_iv_recovery(self):
        key = randbytes(16)
        iv = randbytes(16)

        iv_ = self.iv_recovery.attack(lambda c: self._decrypt(key, iv, c))
        self.assertEqual(iv, iv_)

    def test_padding_oracle(self):
        key = randbytes(16)

        for i in range(16):
            p = pad(randbytes(i + 1), 16)
            iv, c = self._encrypt(key, p)
            p_ = self.padding_oracle.attack(lambda iv, c: self._valid_padding(key, iv, c), iv, c)
            self.assertEqual(p, p_)


class TestCBCAndCBCMAC(TestCase):
    from cbc_and_cbc_mac import eam_key_reuse
    from cbc_and_cbc_mac import etm_key_reuse
    from cbc_and_cbc_mac import mte_key_reuse

    def _encrypt_eam(self, key, p):
        # Notice how the key is used for encryption and authentication...
        p = pad(p, 16)
        iv = randbytes(16)
        c = AES.new(key, AES.MODE_CBC, iv).encrypt(p)
        # Encrypt-and-MAC using CBC-MAC to prevent chosen-ciphertext attacks.
        t = AES.new(key, AES.MODE_CBC, bytes(16)).encrypt(p)[-16:]
        return iv, c, t

    def _decrypt_eam(self, key, iv, c, t):
        p = AES.new(key, AES.MODE_CBC, iv).decrypt(c)
        t_ = AES.new(key, AES.MODE_CBC, bytes(16)).encrypt(p)[-16:]
        # Check the MAC to be sure the message isn't forged.
        if t != t_:
            return None

        return unpad(p, 16)

    def _encrypt_etm(self, key, p):
        # Notice how the key is used for encryption and authentication...
        p = pad(p, 16)
        iv = randbytes(16)
        c = AES.new(key, AES.MODE_CBC, iv).encrypt(p)
        # Encrypt-then-MAC using CBC-MAC to prevent chosen-ciphertext attacks.
        t = AES.new(key, AES.MODE_CBC, bytes(16)).encrypt(iv + c)[-16:]
        return iv, c, t

    def _decrypt_etm(self, key, iv, c, t):
        t_ = AES.new(key, AES.MODE_CBC, bytes(16)).encrypt(iv + c)[-16:]
        # Check the MAC to be sure the message isn't forged.
        if t != t_:
            return None

        return unpad(AES.new(key, AES.MODE_CBC, iv).decrypt(c), 16)

    def _encrypted_zeroes(self, key):
        return AES.new(key, AES.MODE_ECB).encrypt(bytes(16))

    def _encrypt_mte(self, key, p):
        # Notice how the key is used for encryption and authentication...
        p = pad(p, 16)
        iv = randbytes(16)
        # MAC-then-encrypt using CBC-MAC to prevent chosen-ciphertext attacks.
        t = AES.new(key, AES.MODE_CBC, bytes(16)).encrypt(p)[-16:]
        c = AES.new(key, AES.MODE_CBC, iv).encrypt(p + t)
        return iv, c

    def _decrypt_mte(self, key, iv, c):
        d = AES.new(key, AES.MODE_CBC, iv).decrypt(c)
        p = d[:-16]
        t = d[-16:]
        t_ = AES.new(key, AES.MODE_CBC, bytes(16)).encrypt(p)[-16:]
        # Check the MAC to be sure the message isn't forged.
        if t != t_:
            return None

        return unpad(p, 16)

    def test_eam_key_reuse(self):
        key = randbytes(16)

        for i in range(16):
            p = randbytes(i + 1)
            iv, c, t = self._encrypt_eam(key, p)
            p_ = self.eam_key_reuse.attack(lambda iv, c, t: self._decrypt_eam(key, iv, c, t), iv, c, t)
            self.assertEqual(p, p_)

    def test_etm_key_reuse(self):
        key = randbytes(16)

        for i in range(16):
            p = randbytes(i + 1)
            iv, c, t = self._encrypt_etm(key, p)
            p_ = self.etm_key_reuse.attack(lambda p: self._encrypt_etm(key, p), lambda iv, c, t: self._decrypt_etm(key, iv, c, t), iv, c, t)
            self.assertEqual(p, p_)

    def test_mte_key_reuse(self):
        key = randbytes(16)
        encrypted_zeroes = self._encrypted_zeroes(key)

        for i in range(16):
            p = randbytes(i + 1)
            iv, c = self._encrypt_mte(key, p)
            p_ = self.mte_key_reuse.attack(lambda iv, c: self._decrypt_mte(key, iv, c), iv, c, encrypted_zeroes)
            self.assertEqual(p, p_)


class TestCBCMAC(TestCase):
    from cbc_mac import length_extension

    def _sign(self, key, m):
        return AES.new(key, AES.MODE_CBC, bytes(16)).encrypt(m)[-16:]

    def _verify(self, key, m, t):
        t_ = AES.new(key, AES.MODE_CBC, bytes(16)).encrypt(m)[-16:]
        return t == t_

    def test_length_extension(self):
        key = randbytes(16)
        m1 = randbytes(32)
        t1 = self._sign(key, m1)
        m2 = randbytes(32)
        t2 = self._sign(key, m2)

        m3, t3 = self.length_extension.attack(m1, t1, m2, t2)
        self.assertTrue(self._verify(key, m3, t3))


class TestCTR(TestCase):
    from ctr import separator_oracle

    def _encrypt(self, key, p):
        return AES.new(key, AES.MODE_CTR, counter=Counter.new(128)).encrypt(p)

    def _valid_separators(self, separator_byte, separator_count, key, c):
        p = AES.new(key, AES.MODE_CTR, counter=Counter.new(128)).decrypt(c)
        return p.count(separator_byte) == separator_count

    def test_crime(self):
        # TODO: CRIME attack is too inconsistent in unit tests.
        pass

    def test_separator_oracle(self):
        separator_byte = ord("\0")
        separator_count = randint(1, 10)
        key = randbytes(16)
        # We have to replace separators by some other byte.
        p = randbytes(16).replace(b"\0", b"\1")
        for _ in range(separator_count):
            # We have to replace separators by some other byte.
            p += bytes([separator_byte]) + randbytes(16).replace(b"\0", b"\1")

        c = self._encrypt(key, p)

        p_ = self.separator_oracle.attack(lambda c: self._valid_separators(separator_byte, separator_count, key, c), separator_byte, c)
        self.assertEqual(p, p_)


class TestECB(TestCase):
    from ecb import plaintext_recovery

    def _encrypt(self, key, p):
        return AES.new(key, AES.MODE_ECB).encrypt(p)

    def test_plaintext_recovery(self):
        key = randbytes(16)
        s = randbytes(16)

        s_ = self.plaintext_recovery.attack(lambda p: self._encrypt(key, pad(p + s, 16)))
        self.assertEqual(s, s_)


class TestECC(TestCase):
    from ecc import ecdsa_nonce_reuse
    from ecc import parameter_recovery
    from ecc import singular_curve
    from ecc import smart_attack

    _origin = "origin"

    def _negation(self, p, point):
        if point == self._origin:
            return point

        return point[0], -point[1] % p

    def _add(self, p, a2, a4, point1, point2):
        if point1 == self._origin:
            return point2

        if point2 == self._origin:
            return point1

        if point1 == self._negation(p, point2):
            return self._origin

        if point1 == point2:
            gradient = (3 * point1[0] ** 2 + 2 * a2 * point1[0] + a4) * pow(2 * point1[1], -1, p) % p
        else:
            gradient = (point2[1] - point1[1]) * pow(point2[0] - point1[0], -1, p) % p

        x = (gradient ** 2 - a2 - point1[0] - point2[0]) % p
        y = (gradient * (point1[0] - x) - point1[1]) % p
        return x, y

    def _double_and_add(self, p, a2, a4, base, l):
        multiplication_result = self._origin
        double = base
        while l > 0:
            if l % 2 == 1:
                multiplication_result = self._add(p, a2, a4, multiplication_result, double)

            double = self._add(p, a2, a4, double, double)
            l //= 2

        return multiplication_result

    def test_ecdsa_nonce_reuse(self):
        p = 115792089210356248762697446949407573530086143415290314195533631308867097853951
        a = 115792089210356248762697446949407573530086143415290314195533631308867097853948
        b = 41058363725152142129326129780047268409114441015993725554835256314039467401291
        p_256 = EllipticCurve(GF(p), [a, b])
        gen = p_256.gen(0)
        n = int(gen.order())
        d = randint(1, n - 1)
        l = randint(1, n - 1)
        r = int((l * gen).xy()[0])
        m1 = getrandbits(n.bit_length())
        s1 = pow(l, -1, n) * (m1 + r * d) % n
        m2 = getrandbits(n.bit_length())
        s2 = pow(l, -1, n) * (m2 + r * d) % n
        for l_, d_ in self.ecdsa_nonce_reuse.attack(n, m1, r, s1, m2, r, s2):
            self.assertIsInstance(l_, int)
            self.assertIsInstance(d_, int)
            if l_ == l and d_ == d:
                break
        else:
            self.fail()

    def test_frey_ruck_attack(self):
        # TODO: Frey-Ruck attack is too inconsistent in unit tests.
        pass

    def test_mov_attack(self):
        # TODO: MOV attack is too inconsistent in unit tests.
        pass

    def test_parameter_recovery(self):
        p = 115792089210356248762697446949407573530086143415290314195533631308867097853951
        a = 115792089210356248762697446949407573530086143415290314195533631308867097853948
        b = 41058363725152142129326129780047268409114441015993725554835256314039467401291
        p_256 = EllipticCurve(GF(p), [a, b])
        x1, y1 = p_256.random_point().xy()
        x2, y2 = p_256.random_point().xy()
        a_, b_ = self.parameter_recovery.attack(p, x1, y1, x2, y2)
        self.assertIsInstance(a_, int)
        self.assertIsInstance(b_, int)
        self.assertEqual(a, a_)
        self.assertEqual(b, b_)

    def test_singular_curve(self):
        # Singular point is a cusp.
        p = 29800669538070463271
        a2 = 9813480773723366080
        a4 = 13586186857864981308
        a6 = 18910877985247806581
        base_x = 13284247619583658910
        base_y = 3629049282720081919
        # We don't know the order of the base point, so we keep l pretty low to make sure we don't exceed it.
        l = randint(1, 4096)
        multiplication_result_x, multiplication_result_y = self._double_and_add(p, a2, a4, (base_x, base_y), l)
        l_ = self.singular_curve.attack(p, a2, a4, a6, base_x, base_y, multiplication_result_x, multiplication_result_y)
        self.assertIsInstance(l_, int)
        self.assertEqual(l, l_)

        # Singular point is a node.
        p = 29800669538070463271
        a2 = 13753215131529770662
        a4 = 16713139382466325228
        a6 = 19476075514740408653
        base_x = 16369123140759309684
        base_y = 5098114980663762719
        # We don't know the order of the base point, so we keep l pretty low to make sure we don't exceed it.
        l = randint(1, 4096)
        multiplication_result_x, multiplication_result_y = self._double_and_add(p, a2, a4, (base_x, base_y), l)
        l_ = self.singular_curve.attack(p, a2, a4, a6, base_x, base_y, multiplication_result_x, multiplication_result_y)
        self.assertIsInstance(l_, int)
        self.assertEqual(l, l_)

    def test_smart_attack(self):
        curve = EllipticCurve(GF(23304725718649417969), [8820341459377516260, 5880227639585010840])
        gen = curve.gen(0)
        n = int(gen.order())
        l = randint(1, n - 1)
        l_ = self.smart_attack.attack(gen, l * gen)
        self.assertIsInstance(l_, int)
        self.assertEqual(l, l_)


class TestElgamalEncryption(TestCase):
    from elgamal_encryption import nonce_reuse
    from elgamal_encryption import unsafe_generator

    def test_nonce_reuse(self):
        # Safe prime.
        p = 16902648776703029279
        g = 3
        d = randint(1, p - 1)
        h = pow(g, d, p)
        l = randint(1, p - 1)
        s = pow(h, p, l)
        c = pow(g, l, p)
        m1 = getrandbits(p.bit_length())
        d1 = m1 * s % p
        m2 = getrandbits(p.bit_length())
        d2 = m2 * s % p
        m2_ = self.nonce_reuse.attack(p, m1, c, d1, c, d2)
        self.assertIsInstance(m2_, int)
        self.assertEqual(m2, m2_)

    def test_unsafe_generator(self):
        # Safe prime.
        p = 16902648776703029279
        # Unsafe generator, generates the entire group.
        g = 7
        for i in range(100):
            x = randint(1, p - 1)
            h = pow(g, x, p)
            y = randint(1, p - 1)
            s = pow(h, y, p)
            c1 = pow(g, y, p)
            m = randint(1, p - 1)
            c2 = m * s % p
            k = self.unsafe_generator.attack(p, h, c1, c2)
            self.assertIsInstance(k, int)
            self.assertEqual(legendre_symbol(m, p), k)


class TestElgamalSignature(TestCase):
    from elgamal_signature import nonce_reuse

    def test_nonce_reuse(self):
        # Safe prime.
        p = 16902648776703029279
        g = 3
        d = randint(1, p - 2)
        l = p - 1
        while gcd(l, p - 1) != 1:
            l = randint(2, p - 2)

        r = pow(g, l, p)
        m1 = getrandbits(p.bit_length())
        s1 = pow(l, -1, p - 1) * (m1 - r * d) % (p - 1)
        m2 = getrandbits(p.bit_length())
        s2 = pow(l, -1, p - 1) * (m2 - r * d) % (p - 1)
        for l_, d_ in self.nonce_reuse.attack(p, m1, r, s1, m2, r, s2):
            self.assertIsInstance(l_, int)
            self.assertIsInstance(d_, int)
            if l_ == l and d_ == d:
                break
        else:
            self.fail()


class TestFactorization(TestCase):
    from factorization import base_conversion
    from factorization import branch_and_prune
    from factorization import complex_multiplication
    from factorization import coppersmith
    from factorization import fermat
    from factorization import known_phi
    from factorization import implicit
    from factorization import roca

    def test_base_conversion(self):
        # Base 3, 3 primes.
        p = 21187083124088512843307390152364167522362269594349815270782628323431805003774795906872825415073456706499910412455608669
        q = 15684240429131529254685698284890751184639406145730291592802676915731672495230992603635422093849215077
        r = 40483766026713491645694780188316242859742718066890630967135095358496115350752613236101566589
        n = p * q * r
        p_, q_, r_ = self.base_conversion.factorize(n)
        self.assertIsInstance(p_, int)
        self.assertIsInstance(q_, int)
        self.assertIsInstance(r_, int)
        self.assertEqual(n, p_ * q_ * r_)

        # Base 11, 2 primes.
        p = 5636663100410339050591445485090234548439547400230152507623650956862470951259768771895609021439466657292113515499213261725046751664333428835212665405991848764779073407177219695916181638661604890906124870900657349291343875716114535224623986662673220278594643325664055743877053272540004735452198447411515019043760699779198474382859366389140522851725256493083967381046565218658785408508317
        q = 4637643488084848224165183518002033325616428077917519043195914958210451836010505629755906000122693190713754782092365745897354221494160410767300504260339311867766125480345877257141604490894821710144701103564244398358535542801965838493
        n = p * q
        p_, q_ = self.base_conversion.factorize(n)
        self.assertIsInstance(p_, int)
        self.assertIsInstance(q_, int)
        self.assertEqual(n, p_ * q_)

    def test_branch_and_prune(self):
        # These primes aren't special.
        p = 13139791741351746894866427726721425232688052495714047961128606568137470741236391419984296213524906103377170890688143635009211116727124842849096165421244153
        q = 6705712489981460472010451576220118673766200621788838066168783990030831970269515515674361221085135530331369278172131216566093286615777148021404414538085037
        n = p * q
        phi = (p - 1) * (q - 1)
        e = 65537
        d = pow(e, -1, phi)
        dp = pow(e, -1, p - 1)
        dq = pow(e, -1, q - 1)

        known_prop = 57
        p_bits = []
        for i in reversed(range(512)):
            p_bits.append((p >> i) & 1 if randint(1, 100) <= known_prop else None)
        q_bits = []
        for i in reversed(range(512)):
            q_bits.append((q >> i) & 1 if randint(1, 100) <= known_prop else None)

        p_, q_ = self.branch_and_prune.factorize_pq(n, p_bits, q_bits)
        self.assertIsInstance(p_, int)
        self.assertIsInstance(q_, int)
        self.assertEqual(n, p_ * q_)

        known_prop = 42
        p_bits = []
        for i in reversed(range(512)):
            p_bits.append((p >> i) & 1 if randint(1, 100) <= known_prop else None)
        q_bits = []
        for i in reversed(range(512)):
            q_bits.append((q >> i) & 1 if randint(1, 100) <= known_prop else None)
        d_bits = []
        for i in reversed(range(1024)):
            d_bits.append((d >> i) & 1 if randint(1, 100) <= known_prop else None)

        p_, q_ = self.branch_and_prune.factorize_pqd(n, e, p_bits, q_bits, d_bits)
        self.assertIsInstance(p_, int)
        self.assertIsInstance(q_, int)
        self.assertEqual(n, p_ * q_)

        known_prop = 27
        p_bits = []
        for i in reversed(range(512)):
            p_bits.append((p >> i) & 1 if randint(1, 100) <= known_prop else None)
        q_bits = []
        for i in reversed(range(512)):
            q_bits.append((q >> i) & 1 if randint(1, 100) <= known_prop else None)
        d_bits = []
        for i in reversed(range(1024)):
            d_bits.append((d >> i) & 1 if randint(1, 100) <= known_prop else None)
        dp_bits = []
        # A bit larger than 512 due to implementation details of the branch and prune algorithm.
        for i in reversed(range(516)):
            dp_bits.append((dp >> i) & 1 if randint(1, 100) <= known_prop else None)
        dq_bits = []
        # A bit larger than 512 due to implementation details of the branch and prune algorithm.
        for i in reversed(range(516)):
            dq_bits.append((dq >> i) & 1 if randint(1, 100) <= known_prop else None)

        p_, q_ = self.branch_and_prune.factorize_pqddpdq(n, e, p_bits, q_bits, d_bits, dp_bits, dq_bits)
        self.assertIsInstance(p_, int)
        self.assertIsInstance(q_, int)
        self.assertEqual(n, p_ * q_)

    def test_complex_multiplication(self):
        # Recursion limit is necessary for calculating division polynomials using sage.
        rec_limit = sys.getrecursionlimit()
        sys.setrecursionlimit(5000)

        p = 10577468517212308916917871367410399281392767861135513107255047025555394408598222362847763634342865553142272076186583012471808986419037203678594688627595231
        q = 8925960222192297437450017303748967603715694246793735943594688849877125733026282069058422865132949625288537523520769856912162011383285034969425346137038883
        n = p * q
        D = 427
        p_, q_ = self.complex_multiplication.factorize(n, D)
        self.assertIsInstance(p_, int)
        self.assertIsInstance(q_, int)
        self.assertEqual(n, p_ * q_)

        sys.setrecursionlimit(rec_limit)

    def test_coppersmith(self):
        p = 8294118504611118345546466080325632607801907364697312317242368417303646025896249767645395912291329182895616276681886182303417327463669722370956110678857457
        q = 11472445399871949099065671577613972926185090427303119917183801667878634389108674818205844773744056675054520407290278050115877859333328393928885760892504569
        n = p * q

        p_, q_ = self.coppersmith.factorize_univariate(n, 512, 270, p >> (512 - 270), 0, 0)
        self.assertIsInstance(p_, int)
        self.assertIsInstance(q_, int)
        self.assertEqual(n, p_ * q_)

        p_, q_ = self.coppersmith.factorize_univariate(n, 512, 0, 0, 270, p % (2 ** 270))
        self.assertIsInstance(p_, int)
        self.assertIsInstance(q_, int)
        self.assertEqual(n, p_ * q_)

        p_, q_ = self.coppersmith.factorize_univariate(n, 512, 135, p >> (512 - 135), 135, p % (2 ** 135))
        self.assertIsInstance(p_, int)
        self.assertIsInstance(q_, int)
        self.assertEqual(n, p_ * q_)

        p_, q_ = self.coppersmith.factorize_bivariate(n, 512, 150, p >> (512 - 150), 0, 0, 512, 0, 0, 150, q % (2 ** 150))
        self.assertIsInstance(p_, int)
        self.assertIsInstance(q_, int)
        self.assertEqual(n, p_ * q_)

        p_, q_ = self.coppersmith.factorize_bivariate(n, 512, 0, 0, 150, p % (2 ** 150), 512, 150, q >> (512 - 150), 0, 0)
        self.assertIsInstance(p_, int)
        self.assertIsInstance(q_, int)
        self.assertEqual(n, p_ * q_)

    def test_fermat(self):
        p = 383885088537555147258860631363598239852683844948508219667734507794290658581818891369581578137796842442514517285109997827646844102293746572763236141308659
        q = 383885088537555147258860631363598239852683844948508219667734507794290658581818891369581578137796842442514517285109997827646844102293746572763236141308451
        n = p * q
        p_, q_ = self.fermat.factorize(n)
        self.assertIsInstance(p_, int)
        self.assertIsInstance(q_, int)
        self.assertEqual(n, p_ * q_)

    def test_known_phi(self):
        # These primes aren't special.
        p = 11106026672819778415395265319351312104517763207376765038636473714941732117831488482730793398782365364840624898218935983446211558033147834146885518313145941
        q = 12793494802119353329493630005275969260540058187994460635179617401018719587481122947567147790680079651999077966705114757935833094909655872125005398075725409
        n = p * q
        phi = (p - 1) * (q - 1)
        p_, q_ = self.known_phi.factorize(n, phi)
        self.assertIsInstance(p_, int)
        self.assertIsInstance(q_, int)
        self.assertEqual(n, p_ * q_)

        # Multi-prime case takes longer so there's a separate method.
        p = 10193015828669388212171268316396616412166866643440710733674534917491644123135436050477232002188857603479321547506131679866357093667445348339711929671105733
        q = 8826244874397589965592244959402585690675974843434609869757034692220480232437419549416634170391846191239385439228177059214900435042874545573920364227747261
        r = 7352042777909126576764043061995108196815011736073183321111078742728938275060552442022686305342309076279692633229512445674423158310200668776459828180575601
        s = 9118676262959556930818956921827413198986277995127667203870694452397233225961924996910197904901037135372560207618442015208042298428698343225720163505153059
        n = p * q * r * s
        phi = (p - 1) * (q - 1) * (r - 1) * (s - 1)
        p_, q_, r_, s_ = self.known_phi.factorize_multi_prime(n, phi)
        self.assertIsInstance(p_, int)
        self.assertIsInstance(q_, int)
        self.assertIsInstance(r_, int)
        self.assertIsInstance(s_, int)
        self.assertEqual(n, p_ * q_ * r_ * s_)

    def test_implicit(self):
        p_bitsize = 1024
        q_bitsize = 512
        shared_bitsize = 684
        p1 = 114078116454996138073318170170395300151527904793534256191938789983399536922395777111499295202803369554422196999085171496293035396121701314031895628788412353005299652082324755433547975515470738465391276343421170770833007677775061536204663181723877277783535322237577024424245899108264063112142009298991310208363
        q1 = 12098618010582908146005387418068214530897837924954238474768639057877490835545707924234415267192522442378424554055618356812999593976451240454748132615211091
        p2 = 114078116454996138073318170170395300151527904793534256191938789983399536922395777111499295202803369554422196999085171496293035396121701314031895628788412353005299652082324755433547975515470738465391276343420364306790694479071514320422685064042719135179664690266371525865249047670187055110695514824881157627139
        q2 = 6947349788273330265284965959588633765145668297542467009935686733076998478802274287263210169428313906535572268083136251282544180080959668222544545924665987
        p3 = 114078116454996138073318170170395300151527904793534256191938789983399536922395777111499295202803369554422196999085171496293035396121701314031895628788412353005299652082324755433547975515470738465391276343421225512127678851876291564787861171689610002001450319286946495752591223718157676932258249173072665300213
        q3 = 9266126880388093025412332663804790639778236438889018854356539267369792799981733933428697598363851162957322580350270024369332640344413674817822906997102161
        p4 = 114078116454996138073318170170395300151527904793534256191938789983399536922395777111499295202803369554422196999085171496293035396121701314031895628788412353005299652082324755433547975515470738465391276343421356808531436971239501427225110998678228016324130962852291540962098563998522061844259409194324238072163
        q4 = 9346194396330429861097524187193981265347523161493757436812567448933497111978504926263282763464402757659318174531608519618989854444686100976857830087136899
        moduli = [p1 * q1, p2 * q2, p3 * q3, p4 * q4]
        for i, (p, q) in enumerate(self.implicit.factorize_msb(moduli, p_bitsize + q_bitsize, shared_bitsize)):
            self.assertIsInstance(p, int)
            self.assertIsInstance(q, int)
            self.assertEqual(moduli[i], p * q)

        p_bitsize = 1024
        q_bitsize = 512
        shared_bitsize = 684
        p1 = 137676848178120053804151859930883725890803026594890273621717986880391033552896124307278203769389114417028688066268898176276364165645879838855204653941267370118703755611397682095578076818071918172477401067278492828257626897251549091543352809233324240524137497086302474085899298902638892888908168338819819232793
        q1 = 13166288667078358159532363247770104519199514211373352701434198635956864629466947059508438393840310722732010695913860165840076158141600542903957511858467599
        p2 = 155941871148496045943650517403022286219330266513190620694534749227433871940120353353030481603047425408777193957891989215447984590279121382305371103889682866866611645183334486259197241694690077730091496562828758139564286098307121800141566950170972849436331381375112592397181935508950663666559821018117710798361
        q2 = 8054287780708269262514472947823359228967255917411384941738106945448488928023325871002415540629545474428145043227927492187948846465762213369395150593287629
        p3 = 146542545226083477723264700810318219628590283511298968176573337385538577833243759669492317165475590615268753085678168828004241411544898671318095131587338794716729315057151379325654916607098703691695457183186825995894712193071356602411894624624795802572705076938306979030565015683237625719989339343497095536153
        q3 = 8348967325072059612026168622784453891507881426476603640658340020341944731532364677276401286358233081971838597029494396167050440290022806685890808240656759
        p4 = 167661072178525609874536869751051800065390422834592103113971975955391615118678036572040576294964853025982786705404563191397770270731849495157247117854529039983840787661878167379723898817843318578402737767598910576316837813336887274651599847119701845895279082627804568462120651226573750359206381471191410662937
        q4 = 8145167185335505501783087854760814147233023836090931783403657001079727963955491428876064700621053935085252069162037262941731093071208640285177101456231051
        moduli = [p1 * q1, p2 * q2, p3 * q3, p4 * q4]
        for i, (p, q) in enumerate(self.implicit.factorize_lsb(moduli, p_bitsize + q_bitsize, shared_bitsize)):
            self.assertIsInstance(p, int)
            self.assertIsInstance(q, int)
            self.assertEqual(moduli[i], p * q)

    def test_roca(self):
        # 39th primorial
        M = 962947420735983927056946215901134429196419130606213075415963491270
        # These primes are chosen such that a' is pretty small so it doesn't take too long.
        p = 85179386137518452231354185509698113331528483782580002217930594759662020757433
        q = 121807704694511224555991770528701515984374557330058194205583818929517699002107
        n = p * q
        p_, q_ = self.roca.factorize(n, M, 5, 6)
        self.assertIsInstance(p_, int)
        self.assertIsInstance(q_, int)
        self.assertEqual(n, p_ * q_)

    def test_twin_primes(self):
        p = 4045364040964617981493056570547683620499113851384489798802437290109120991898115799819774088264427282611552038114397865000343325953101387058967136608664303
        q = 4045364040964617981493056570547683620499113851384489798802437290109120991898115799819774088264427282611552038114397865000343325953101387058967136608664301
        n = p * q
        p_, q_ = self.fermat.factorize(n)
        self.assertIsInstance(p_, int)
        self.assertIsInstance(q_, int)
        self.assertEqual(n, p_ * q_)


class TestGCM(TestCase):
    from gcm import forbidden_attack

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
        for h in self.forbidden_attack.recover_possible_auth_keys(a1, c1, t1, a2, c2, t2):
            target_a = randbytes(16)
            target_c = randbytes(16)
            forged_t = self.forbidden_attack.forge_tag(h, a1, c1, t1, target_a, target_c)
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


class TestHNP(TestCase):
    from hnp import lattice_attack

    def _dsa(self, p, g, x):
        h = getrandbits(p.bit_length())
        k = randint(1, p - 1)
        r = pow(g, k, p)
        s = (pow(k, -1, p) * (h + x * r)) % p
        return h, r, s, k

    def test_lattice_attack(self):
        # Not a safe prime, but it doesn't really matter.
        p = 299182277398782807472682876223275635417
        g = 5
        x = randint(1, p - 1)

        nonce_bitsize = p.bit_length()
        msb_known = 7
        n_signatures = 25
        nonces = []
        signatures = []
        for i in range(n_signatures):
            h, r, s, k = self._dsa(p, g, x)
            nonces.append(k)
            signatures.append((h, r, s, k >> (nonce_bitsize - msb_known)))

        x_, nonces_ = self.lattice_attack.dsa_known_msb(p, signatures, nonce_bitsize, msb_known)
        self.assertIsInstance(x_, int)
        self.assertIsInstance(nonces_, list)
        self.assertEqual(x, x_)
        for i in range(n_signatures):
            self.assertIsInstance(nonces_[i], int)
            self.assertEqual(nonces[i], nonces_[i])

        nonce_bitsize = p.bit_length()
        lsb_known = 7
        n_signatures = 25
        nonces = []
        signatures = []
        for i in range(n_signatures):
            h, r, s, k = self._dsa(p, g, x)
            nonces.append(k)
            signatures.append((h, r, s, k % (2 ** lsb_known)))

        x_, nonces_ = self.lattice_attack.dsa_known_lsb(p, signatures, nonce_bitsize, lsb_known)
        self.assertIsInstance(x_, int)
        self.assertIsInstance(nonces_, list)
        self.assertEqual(x, x_)
        for i in range(n_signatures):
            self.assertIsInstance(nonces_[i], int)
            self.assertEqual(nonces[i], nonces_[i])

        nonce_bitsize = p.bit_length()
        msb_unknown = 10
        lsb_unknown = 20
        h1, r1, s1, k1 = self._dsa(p, g, x)
        signature1 = (h1, r1, s1, (k1 >> lsb_unknown) % (2 ** (nonce_bitsize - msb_unknown)))
        h2, r2, s2, k2 = self._dsa(p, g, x)
        signature2 = (h2, r2, s2, (k2 >> lsb_unknown) % (2 ** (nonce_bitsize - msb_unknown)))

        x_, k1_, k2_ = self.lattice_attack.dsa_known_middle(p, signature1, signature2, nonce_bitsize, msb_unknown, lsb_unknown)
        self.assertIsInstance(x_, int)
        self.assertIsInstance(k1_, int)
        self.assertIsInstance(k2_, int)
        self.assertEqual(x, x_)
        self.assertEqual(k1, k1_)
        self.assertEqual(k2, k2_)


class TestIGE(TestCase):
    from ige import padding_oracle

    def _encrypt(self, key, p):
        p0 = randbytes(16)
        c0 = randbytes(16)
        cipher = AES.new(key, mode=AES.MODE_ECB)

        p_last = p0
        c_last = c0
        c = bytearray()
        for i in range(0, len(p), 16):
            p_i = p[i:i + 16]
            c_i = strxor(cipher.encrypt(strxor(p_i, c_last)), p_last)
            p_last = p_i
            c_last = c_i
            c += c_i

        return p0, c0, c

    def _valid_padding(self, key, p0, c0, c):
        try:
            cipher = AES.new(key, mode=AES.MODE_ECB)
            p_last = p0
            c_last = c0
            p = bytearray()
            for i in range(0, len(c), 16):
                c_i = c[i:i + 16]
                p_i = strxor(cipher.decrypt(strxor(c_i, p_last)), c_last)
                p_last = p_i
                c_last = c_i
                p += p_i

            unpad(p, 16)
            return True
        except ValueError:
            return False

    def test_padding_oracle(self):
        key = randbytes(16)

        for i in range(16):
            p = pad(randbytes(i + 1), 16)
            p0, c0, c = self._encrypt(key, p)
            p_ = self.padding_oracle.attack(lambda p0, c0, c: self._valid_padding(key, p0, c0, c), p0, c0, c)
            self.assertEqual(p, p_)


class Knapsack(TestCase):
    from knapsack import low_density

    def test_low_density(self):
        a = [429970831622, 650002882675, 512682138397, 145532365100, 462119415111, 357461497167, 582429951539, 22657777498, 2451348134, 380282710854, 251660920136, 103765486463, 276100153517, 250012242739, 519736909707, 451460714161]
        s = 5398327344820
        e = self.low_density.attack(a, s)
        for i in range(len(a)):
            self.assertIsInstance(e[i], int)
        self.assertEqual(e, [1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1])

        a = [23449054409, 58564582991, 24739686534, 30995859145, 16274600764, 13384701522, 45782350364, 10685194276, 18864211511, 9594013152, 50215903866, 7952180124, 42094717093, 50866816333, 44318421949, 31143511315]
        s = 42313265920
        e = self.low_density.attack(a, s)
        for i in range(len(a)):
            self.assertIsInstance(e[i], int)
        self.assertEqual(e, [1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0])


class LCG(TestCase):
    from lcg import parameter_recovery
    from lcg import truncated_parameter_recovery
    from lcg import truncated_state_recovery

    def test_parameter_recovery(self):
        modulus = 230565400234205371157763985910524799617
        multiplier = 192101630084837332907895369052393213499
        increment = 212252940839553091477500231998099191939
        state = 182679397636465813399296757573664340382
        n_outputs = 10

        outputs = []
        for _ in range(n_outputs):
            state = (multiplier * state + increment) % modulus
            outputs.append(state)

        modulus_, multiplier_, increment_ = self.parameter_recovery.attack(outputs)
        self.assertIsInstance(modulus_, int)
        self.assertEqual(modulus, modulus_)
        self.assertIsInstance(multiplier_, int)
        self.assertEqual(multiplier, multiplier_)
        self.assertIsInstance(increment_, int)
        self.assertEqual(increment, increment_)

        modulus_, multiplier_, increment_ = self.parameter_recovery.attack(outputs, modulus=modulus)
        self.assertIsInstance(modulus_, int)
        self.assertEqual(modulus, modulus_)
        self.assertIsInstance(multiplier_, int)
        self.assertEqual(multiplier, multiplier_)
        self.assertIsInstance(increment_, int)
        self.assertEqual(increment, increment_)

        modulus_, multiplier_, increment_ = self.parameter_recovery.attack(outputs, multiplier=multiplier)
        self.assertIsInstance(modulus_, int)
        self.assertEqual(modulus, modulus_)
        self.assertIsInstance(multiplier_, int)
        self.assertEqual(multiplier, multiplier_)
        self.assertIsInstance(increment_, int)
        self.assertEqual(increment, increment_)

        modulus_, multiplier_, increment_ = self.parameter_recovery.attack(outputs, increment=increment)
        self.assertIsInstance(modulus_, int)
        self.assertEqual(modulus, modulus_)
        self.assertIsInstance(multiplier_, int)
        self.assertEqual(multiplier, multiplier_)
        self.assertIsInstance(increment_, int)
        self.assertEqual(increment, increment_)

        modulus_, multiplier_, increment_ = self.parameter_recovery.attack(outputs, modulus=modulus, multiplier=multiplier)
        self.assertIsInstance(modulus_, int)
        self.assertEqual(modulus, modulus_)
        self.assertIsInstance(multiplier_, int)
        self.assertEqual(multiplier, multiplier_)
        self.assertIsInstance(increment_, int)
        self.assertEqual(increment, increment_)

        modulus_, multiplier_, increment_ = self.parameter_recovery.attack(outputs, modulus=modulus, increment=increment)
        self.assertIsInstance(modulus_, int)
        self.assertEqual(modulus, modulus_)
        self.assertIsInstance(multiplier_, int)
        self.assertEqual(multiplier, multiplier_)
        self.assertIsInstance(increment_, int)
        self.assertEqual(increment, increment_)

        modulus_, multiplier_, increment_ = self.parameter_recovery.attack(outputs, multiplier=multiplier, increment=increment)
        self.assertIsInstance(modulus_, int)
        self.assertEqual(modulus, modulus_)
        self.assertIsInstance(multiplier_, int)
        self.assertEqual(multiplier, multiplier_)
        self.assertIsInstance(increment_, int)
        self.assertEqual(increment, increment_)

        modulus_, multiplier_, increment_ = self.parameter_recovery.attack(outputs, modulus=modulus, multiplier=multiplier, increment=increment)
        self.assertIsInstance(modulus_, int)
        self.assertEqual(modulus, modulus_)
        self.assertIsInstance(multiplier_, int)
        self.assertEqual(multiplier, multiplier_)
        self.assertIsInstance(increment_, int)
        self.assertEqual(increment, increment_)

    def test_truncated_parameter_recovery(self):
        state_bitsize = 128
        output_bitsize = 32
        modulus = 236360717458728691963813082060498623380
        multiplier = 192101630084837332907895369052393213499
        increment = 212252940839553091477500231998099191939
        state = 182679397636465813399296757573664340382
        n_outputs = 40
        # The recovery method is not perfect, so we allow some errors in the generated output.
        n_test = 200
        max_failures = 5

        outputs = []
        states = []
        for _ in range(n_outputs):
            state = (multiplier * state + increment) % modulus
            states.append(state)
            outputs.append(state >> (state_bitsize - output_bitsize))

        for modulus_, multiplier_, increment_, states_ in self.truncated_parameter_recovery.attack(outputs, state_bitsize, output_bitsize, state_bitsize):
            self.assertIsInstance(modulus_, int)
            self.assertIsInstance(multiplier_, int)
            self.assertIsInstance(increment_, int)
            for i in range(n_outputs):
                self.assertIsInstance(states_[i], int)

            s = state
            s_ = states_[n_outputs - 1]
            failures = 0
            for _ in range(n_test):
                s = (multiplier * s + increment) % modulus
                s_ = (multiplier_ * s_ + increment_) % modulus_
                if (s >> (state_bitsize - output_bitsize)) != (s_ >> (state_bitsize - output_bitsize)):
                    failures += 1

            self.assertLessEqual(failures, max_failures)
            break

        for modulus_, multiplier_, increment_, states_ in self.truncated_parameter_recovery.attack(outputs, state_bitsize, output_bitsize, state_bitsize, modulus=modulus):
            self.assertIsInstance(modulus_, int)
            self.assertIsInstance(multiplier_, int)
            self.assertIsInstance(increment_, int)
            for i in range(n_outputs):
                self.assertIsInstance(states_[i], int)

            s = state
            s_ = states_[n_outputs - 1]
            failures = 0
            for _ in range(n_test):
                s = (multiplier * s + increment) % modulus
                s_ = (multiplier_ * s_ + increment_) % modulus_
                if (s >> (state_bitsize - output_bitsize)) != (s_ >> (state_bitsize - output_bitsize)):
                    failures += 1

            self.assertLessEqual(failures, max_failures)
            break

        for modulus_, multiplier_, increment_, states_ in self.truncated_parameter_recovery.attack(outputs, state_bitsize, output_bitsize, state_bitsize, multiplier=multiplier):
            self.assertIsInstance(modulus_, int)
            self.assertIsInstance(multiplier_, int)
            self.assertIsInstance(increment_, int)
            for i in range(n_outputs):
                self.assertIsInstance(states_[i], int)

            s = state
            s_ = states_[n_outputs - 1]
            failures = 0
            for _ in range(n_test):
                s = (multiplier * s + increment) % modulus
                s_ = (multiplier_ * s_ + increment_) % modulus_
                if (s >> (state_bitsize - output_bitsize)) != (s_ >> (state_bitsize - output_bitsize)):
                    failures += 1

            self.assertLessEqual(failures, max_failures)
            break

        for modulus_, multiplier_, increment_, states_ in self.truncated_parameter_recovery.attack(outputs, state_bitsize, output_bitsize, state_bitsize, modulus=modulus, multiplier=multiplier):
            self.assertIsInstance(modulus_, int)
            self.assertIsInstance(multiplier_, int)
            self.assertIsInstance(increment_, int)
            for i in range(n_outputs):
                self.assertIsInstance(states_[i], int)

            s = state
            s_ = states_[n_outputs - 1]
            failures = 0
            for _ in range(n_test):
                s = (multiplier * s + increment) % modulus
                s_ = (multiplier_ * s_ + increment_) % modulus_
                if (s >> (state_bitsize - output_bitsize)) != (s_ >> (state_bitsize - output_bitsize)):
                    failures += 1

            self.assertLessEqual(failures, max_failures)
            break

    def test_truncated_state_recovery(self):
        state_bitsize = 128
        output_bitsize = 32
        modulus = 236360717458728691963813082060498623380
        multiplier = 192101630084837332907895369052393213499
        increment = 212252940839553091477500231998099191939
        state = 182679397636465813399296757573664340382
        n_outputs = 40

        outputs = []
        states = []
        for _ in range(n_outputs):
            state = (multiplier * state + increment) % modulus
            states.append(state)
            outputs.append(state >> (state_bitsize - output_bitsize))

        states_ = self.truncated_state_recovery.attack(outputs, state_bitsize, output_bitsize, modulus, multiplier, increment)
        for i in range(n_outputs):
            self.assertIsInstance(states_[i], int)
            self.assertEqual(states[i], states_[i])
