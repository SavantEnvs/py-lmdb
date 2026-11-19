#!/usr/bin/env python3
"""Run py-lmdb's own unittest suite (tests/*_test.py) and print the counts.

Invoked by mayhem/test.sh through build/mayhem-test/pyrun.  Prints one line
    PYLMDB_RESULT <passed> <failed> <skipped>
Excluded, and why:
  - mdb_layout_test: pytest-only module (imports pytest, which the image does
    not ship); upstream's pyproject also deselects it by default
    (addopts = "-m 'not mdb_layout'").
  - TxnTest.test_cached_txn_across_fork: its forked child never exits, so it
    re-runs the rest of the suite in a second process and both report counts.
"""
import sys
import unittest

EXCLUDE_MODULES = {'mdb_layout_test'}
EXCLUDE_TESTS = {'test_cached_txn_across_fork'}


def flatten(suite):
    for t in suite:
        if isinstance(t, unittest.TestSuite):
            yield from flatten(t)
        else:
            yield t


def main(start):
    loader = unittest.TestLoader()
    tests = []
    for t in flatten(loader.discover(start, pattern='*_test.py', top_level_dir=start)):
        tid = t.id()
        mod = tid.split('.')[0]
        name = tid.rsplit('.', 1)[-1]
        # (a module that fails to import shows up as _FailedTest.<module>)
        if mod in EXCLUDE_MODULES or name in EXCLUDE_MODULES or name in EXCLUDE_TESTS:
            continue
        tests.append(t)
    res = unittest.TextTestRunner(verbosity=1, stream=sys.stderr).run(unittest.TestSuite(tests))
    failed = len(res.failures) + len(res.errors) + len(res.unexpectedSuccesses)
    skipped = len(res.skipped) + len(res.expectedFailures)
    passed = res.testsRun - failed - skipped
    print('PYLMDB_RESULT %d %d %d' % (passed, failed, skipped), flush=True)


if __name__ == "__main__":   # multiprocessing spawn re-imports this file
    main(sys.argv[1])
