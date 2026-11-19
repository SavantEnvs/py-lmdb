#!/usr/bin/env python3
"""Regenerate the committed seed corpora under mayhem/<target>/testsuite/.

Run with the test build of the package (see mayhem/build.sh), e.g. in the image:
    PYTHONPATH=build/mayhem-test/pkg build/mayhem-test/pyrun \
        mayhem/harnesses/make_seeds.py <outdir>
Seeds are small real databases (both on-disk formats: LMDB 0.9 = v1, LMDB 1.0
= v3) covering plain, dupsort, dupfixed, integerkey, overflow values and named
sub-databases, plus op scripts and cdbmake dumps for the other targets.
"""
import os
import shutil
import sys
import tempfile

import lmdb

out = sys.argv[1]


def put(target, name, data):
    d = os.path.join(out, target, 'testsuite')
    os.makedirs(d, exist_ok=True)
    with open(os.path.join(d, name), 'wb') as fp:
        fp.write(data)


def make_db(lib_version, kind):
    d = tempfile.mkdtemp()
    path = os.path.join(d, 'data.mdb')
    env = lmdb.open(path, subdir=False, lock=False, max_dbs=8,
                    map_size=4 << 20, lib_version=lib_version)
    with env.begin(write=True) as txn:
        if kind == 'plain':
            for i in range(40):
                txn.put(b'key%03d' % i, b'value-%d' % i * (i % 5 + 1))
        elif kind == 'named':
            for name, fl in ((b'dups', dict(dupsort=True)),
                             (b'fixed', dict(dupsort=True, dupfixed=True)),
                             (b'ints', dict(integerkey=True)),
                             (b'rev', dict(reverse_key=True))):
                db = env.open_db(name, txn=txn, **fl)
                for i in range(12):
                    k = i.to_bytes(4, 'little') if name == b'ints' else b'k%02d' % (i % 4)
                    v = b'%08d' % i if name == b'fixed' else b'v%d' % i
                    txn.put(k, v, db=db)
            txn.put(b'plainkey', b'plainvalue')
        elif kind == 'overflow':
            txn.put(b'big', b'B' * 9000)
            txn.put(b'small', b's')
        elif kind == 'split':
            for i in range(400):
                txn.put(b'%06d' % (i * 7919 % 400), b'x' * 30)
    if kind == 'split':
        with env.begin(write=True) as txn:   # leave free pages in the freeDB
            for i in range(0, 400, 3):
                txn.delete(b'%06d' % i)
    env.close()
    with open(path, 'rb') as fp:
        data = fp.read()
    shutil.rmtree(d)
    return data


# Op script for mdb*_write: put x3, cursor put, delete, append run, commit,
# named-DB put, drop, lookup (see run_script() in mdb_fuzz.c).
SCRIPT = (bytes([0x00, 3]) + b'abc' + bytes([5]) + b'hello' +
          bytes([0x11, 2]) + b'zz' + bytes([3]) + b'dup' +
          bytes([0x08, 1]) + b'k' + bytes([200]) +
          bytes([0x06, 1]) + b'k' + bytes([0, 4]) + b'newv' + bytes([0]) +
          bytes([0x04, 3]) + b'abc' + bytes([0]) +
          bytes([0x0a]) +
          bytes([0x21, 0xff, 3]) + b'' +
          bytes([0x29, 0]) +
          bytes([0x0d, 3]) + b'abc')

for lib_version, tag in ((0, '09'), (1, '10')):
    for kind in ('plain', 'named', 'overflow', 'split'):
        db = make_db(lib_version, kind)
        name = 'v%s-%s.mdb' % (tag, kind)
        put('mdb%s_read' % tag, name, db)
        put('mdb%s_write' % tag, name, db + SCRIPT + bytes([len(SCRIPT)]))
        put('py_file', name, db)
        put('py_verify', name, db)

put('py_restore', 'plain.cdb', b'\x00+3,5:abc->hello\n+1,0:k->\n\n')
put('py_restore', 'dups.cdb', b'\x02' + b''.join(
    b'+2,%d:kk->%s\n' % (len(b'%d' % i), b'%d' % i) for i in range(20)) + b'\n')
put('py_restore', 'big.cdb', b'\x01+3,5000:big->' + b'Q' * 5000 + b'\n\n')

# ops_target: selector byte, then (op, args...) records (see pyfuzz.py).
put('py_ops', 'puts.bin', bytes([0, 0x00, 3]) + b'abc' + bytes([0, 3]) + b'xyz' +
    bytes([0, 0, 0x09, 1]) + b'a' + bytes([0, 0x11, 1, 0x13, 0, 0x18]))
put('py_ops', 'dups.bin', bytes([1, 0x21, 1]) + b'k' + bytes([0, 1]) + b'1' +
    bytes([0, 0, 0x21, 1]) + b'k' + bytes([0, 1]) + b'2' + bytes([0, 0, 0x28, 0x2c, 2, 1]) +
    b'k' + bytes([0, 1]) + b'3' + bytes([0, 0x2d, 1, 1]) + b'k' + bytes([0, 0, 0x2e, 0x17]))
put('py_ops', 'fixed.bin', bytes([4, 0x48, 0x4c, 3, 1]) + b'a' + bytes([0, 4]) + b'aaaa' +
    bytes([1, 1]) + b'a' + bytes([0, 4]) + b'bbbb' + bytes([1, 1]) + b'b' + bytes([0, 4]) +
    b'cccc' + bytes([1, 0, 0x4d, 2, 1]) + b'a' + bytes([0, 1]) + b'b' + bytes([0, 4]))
