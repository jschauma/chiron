import unittest
import doctest

import chiron

def load_tests(loader, tests, ignore):
    tests.addTests(doctest.DocTestSuite(chiron))
    return tests
load_tests.__test__ = False

if __name__ == '__main__':
    unittest.main()
