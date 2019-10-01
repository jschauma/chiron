#!/usr/bin/env python
"""Run doctests"""

import doctest
import re
import sys
import unittest

import chiron

# From https://dirkjan.ochtman.nl/writing/2014/07/06/single-source-python-23-doctests.html
class Py23DocChecker(doctest.OutputChecker):
    """Python 2&3 compatible docstring checker"""
    #pylint:disable=no-init
    def check_output(self, want, got, optionflags):
        if sys.version_info[0] > 2:
            want = re.sub("u'(.*?)'", "'\\1'", want)
            want = re.sub('u"(.*?)"', '"\\1"', want)
        return doctest.OutputChecker.check_output(self, want, got, optionflags)

def load_tests(loader, tests, ignore): #pylint:disable=unused-argument
    """Docstring test loader"""
    tests.addTests(doctest.DocTestSuite(chiron, checker=Py23DocChecker()))
    return tests
load_tests.__test__ = False

if __name__ == '__main__':
    unittest.main()
