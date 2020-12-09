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
        p_256 = EllipticCurve(GF(115792089210356248762697446949407573530086143415290314195533631308867097853951), [-3, 41058363725152142129326129780047268409114441015993725554835256314039467401291])
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
        d = randint(1, p - 1)
        h = pow(g, d, p)
        l = randint(1, p - 1)
        s = pow(h, p, l)
        c1 = pow(g, l, p)
        m = getrandbits(p.bit_length())
        c2 = m * s % p
        k = self.unsafe_generator.attack(p, h, c1, c2)
        self.assertIsInstance(k, int)
        self.assertEqual(legendre_symbol(m, p), k)


class TestElgamalSignautre(TestCase):
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
    from factorization import complex_multiplication
    from factorization import coppersmith
    from factorization import fermat
    from factorization import known_phi

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
        import logging
        logging.basicConfig(level=logging.DEBUG)
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

    def test_roca(self):
        # TODO: ROCA takes too long for unit tests.
        pass

    def test_twin_primes(self):
        p = 4045364040964617981493056570547683620499113851384489798802437290109120991898115799819774088264427282611552038114397865000343325953101387058967136608664303
        q = 4045364040964617981493056570547683620499113851384489798802437290109120991898115799819774088264427282611552038114397865000343325953101387058967136608664301
        n = p * q
        p_, q_ = self.fermat.factorize(n)
        self.assertIsInstance(p_, int)
        self.assertIsInstance(q_, int)
        self.assertEqual(n, p_ * q_)
