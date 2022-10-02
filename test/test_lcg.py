import os
import sys
from unittest import TestCase

path = os.path.dirname(os.path.dirname(os.path.realpath(os.path.abspath(__file__))))
if sys.path[1] != path:
    sys.path.insert(1, path)

from attacks.lcg import parameter_recovery
from attacks.lcg import truncated_parameter_recovery
from attacks.lcg import truncated_state_recovery


class TestLCG(TestCase):
    def test_parameter_recovery(self):
        m = 230565400234205371157763985910524799617
        a = 192101630084837332907895369052393213499
        c = 212252940839553091477500231998099191939
        x0 = 182679397636465813399296757573664340382
        n_y = 10

        y = []
        x = x0
        for _ in range(n_y):
            x = (a * x + c) % m
            y.append(x)

        m_, a_, c_ = parameter_recovery.attack(y)
        self.assertIsInstance(m_, int)
        self.assertEqual(m, m_)
        self.assertIsInstance(a_, int)
        self.assertEqual(a, a_)
        self.assertIsInstance(c_, int)
        self.assertEqual(c, c_)

        m_, a_, c_ = parameter_recovery.attack(y, m=m)
        self.assertIsInstance(m_, int)
        self.assertEqual(m, m_)
        self.assertIsInstance(a_, int)
        self.assertEqual(a, a_)
        self.assertIsInstance(c_, int)
        self.assertEqual(c, c_)

        m_, a_, c_ = parameter_recovery.attack(y, a=a)
        self.assertIsInstance(m_, int)
        self.assertEqual(m, m_)
        self.assertIsInstance(a_, int)
        self.assertEqual(a, a_)
        self.assertIsInstance(c_, int)
        self.assertEqual(c, c_)

        m_, a_, c_ = parameter_recovery.attack(y, c=c)
        self.assertIsInstance(m_, int)
        self.assertEqual(m, m_)
        self.assertIsInstance(a_, int)
        self.assertEqual(a, a_)
        self.assertIsInstance(c_, int)
        self.assertEqual(c, c_)

        m_, a_, c_ = parameter_recovery.attack(y, m=m, a=a)
        self.assertIsInstance(m_, int)
        self.assertEqual(m, m_)
        self.assertIsInstance(a_, int)
        self.assertEqual(a, a_)
        self.assertIsInstance(c_, int)
        self.assertEqual(c, c_)

        m_, a_, c_ = parameter_recovery.attack(y, m=m, c=c)
        self.assertIsInstance(m_, int)
        self.assertEqual(m, m_)
        self.assertIsInstance(a_, int)
        self.assertEqual(a, a_)
        self.assertIsInstance(c_, int)
        self.assertEqual(c, c_)

        m_, a_, c_ = parameter_recovery.attack(y, a=a, c=c)
        self.assertIsInstance(m_, int)
        self.assertEqual(m, m_)
        self.assertIsInstance(a_, int)
        self.assertEqual(a, a_)
        self.assertIsInstance(c_, int)
        self.assertEqual(c, c_)

        m_, a_, c_ = parameter_recovery.attack(y, m=m, a=a, c=c)
        self.assertIsInstance(m_, int)
        self.assertEqual(m, m_)
        self.assertIsInstance(a_, int)
        self.assertEqual(a, a_)
        self.assertIsInstance(c_, int)
        self.assertEqual(c, c_)

    def test_truncated_parameter_recovery(self):
        k = 128
        s = 32
        m = 236360717458728691963813082060498623380
        a = 192101630084837332907895369052393213499
        c = 212252940839553091477500231998099191939
        x0 = 182679397636465813399296757573664340382
        n_y = 40
        # The recovery method is not perfect, so we allow some errors in the generated output.
        n_test = 200
        max_failures = 5

        y = []
        for _ in range(n_y):
            x0 = (a * x0 + c) % m
            y.append(x0 >> (k - s))

        m_, a_, c_, x0_ = next(truncated_parameter_recovery.attack(y, k, s))
        self.assertIsInstance(m_, int)
        self.assertIsInstance(a_, int)
        self.assertIsInstance(c_, int)
        self.assertIsInstance(x0_, int)

        x = x0
        x_ = x0_
        for _ in range(n_y):
            x_ = (a_ * x_ + c_) % m_

        failures = 0
        for _ in range(n_test):
            x = (a * x + c) % m
            x_ = (a_ * x_ + c_) % m_
            if (x >> (k - s)) != (x_ >> (k - s)):
                failures += 1

        self.assertLessEqual(failures, max_failures)

        m_, a_, c_, x0_ = next(truncated_parameter_recovery.attack(y, k, s, m=m))
        self.assertIsInstance(m_, int)
        self.assertIsInstance(a_, int)
        self.assertIsInstance(c_, int)
        self.assertIsInstance(x0_, int)

        x = x0
        x_ = x0_
        for _ in range(n_y):
            x_ = (a_ * x_ + c_) % m_

        failures = 0
        for _ in range(n_test):
            x = (a * x + c) % m
            x_ = (a_ * x_ + c_) % m_
            if (x >> (k - s)) != (x_ >> (k - s)):
                failures += 1

        self.assertLessEqual(failures, max_failures)

        m_, a_, c_, x0_ = next(truncated_parameter_recovery.attack(y, k, s, a=a))
        self.assertIsInstance(m_, int)
        self.assertIsInstance(a_, int)
        self.assertIsInstance(c_, int)
        self.assertIsInstance(x0_, int)

        x = x0
        x_ = x0_
        for _ in range(n_y):
            x_ = (a_ * x_ + c_) % m_

        failures = 0
        for _ in range(n_test):
            x = (a * x + c) % m
            x_ = (a_ * x_ + c_) % m_
            if (x >> (k - s)) != (x_ >> (k - s)):
                failures += 1

        self.assertLessEqual(failures, max_failures)

        m_, a_, c_, x0_ = next(truncated_parameter_recovery.attack(y, k, s, m=m, a=a))
        self.assertIsInstance(m_, int)
        self.assertIsInstance(a_, int)
        self.assertIsInstance(c_, int)
        self.assertIsInstance(x0_, int)

        x = x0
        x_ = x0_
        for _ in range(n_y):
            x_ = (a_ * x_ + c_) % m_

        failures = 0
        for _ in range(n_test):
            x = (a * x + c) % m
            x_ = (a_ * x_ + c_) % m_
            if (x >> (k - s)) != (x_ >> (k - s)):
                failures += 1

        self.assertLessEqual(failures, max_failures)

    def test_truncated_state_recovery(self):
        k = 128
        s = 32
        m = 236360717458728691963813082060498623380
        a = 192101630084837332907895369052393213499
        c = 212252940839553091477500231998099191939
        x0 = 182679397636465813399296757573664340382
        n_y = 40

        y = []
        x = []
        for _ in range(n_y):
            x0 = (a * x0 + c) % m
            x.append(x0)
            y.append(x0 >> (k - s))

        x_ = truncated_state_recovery.attack(y, k, s, m, a, c)
        for i in range(n_y):
            self.assertIsInstance(x_[i], int)
            self.assertEqual(x[i], x_[i])
