#!/usr/bin/env python3
"""Python-level fuzz targets for py-lmdb, called from mayhem/harnesses/py_fuzz.c.

Every function takes the raw fuzz input (bytes) and returns normally for any
input.  The exceptions caught below are the ones py-lmdb documents for bad
arguments and bad or corrupt files; anything else escaping is treated as a
bug by the C driver (it prints the traceback and aborts).

Each call works on its own temp file / directory under $TMPDIR and closes its
Environment before returning, so no database state carries over between
inputs.
"""
import io
import os
import shutil
import struct
import tempfile

import lmdb
import lmdb.tool
import lmdb.verify

MAP_SIZE = 8 << 20
# Bad input/bad file errors the API documents (lmdb.Error covers every MDB_*
# error, incl. lmdb.CorruptedError / lmdb.BadValsizeError / lmdb.InvalidError).
EXPECTED = (lmdb.Error, TypeError, ValueError, OverflowError)


def _tmpdir():
    return tempfile.mkdtemp(prefix='pylmdbfuzz-')


def _write_db_file(d, data):
    """Write `data` as a single-file environment, sparse-extended to MAP_SIZE
    so pages past a short input read as zero pages (as in a grown map)
    rather than SIGBUS past EOF."""
    path = os.path.join(d, 'data.mdb')
    with open(path, 'wb') as fp:
        fp.write(data)
        if len(data) < MAP_SIZE:
            fp.truncate(MAP_SIZE)
    return path


def _walk(env):
    """Read every DB of an open environment through the binding."""
    env.stat()
    env.info()
    env.flags()
    names = env.dbs()
    with env.begin(buffers=False) as txn:
        dbs = [None]
        for name in names[:8]:
            try:
                dbs.append(env.open_db(name, txn=txn, create=False))
            except EXPECTED:
                pass
        for db in dbs:
            txn.stat(db)
            cur = txn.cursor(db)
            keys = []
            for i, (k, v) in enumerate(cur.iternext(keys=True, values=True)):
                if len(keys) < 16:
                    keys.append(k)
                if i > 20000:
                    break
            for i, k in enumerate(cur.iterprev(keys=True, values=False)):
                if i > 20000:
                    break
            if keys:
                cur.set_range(keys[0])
                cur.count()
                list(cur.iternext_dup())
                cur.getmulti(keys, dupdata=True)
                for k in keys[:4]:
                    txn.get(k, db=db)
                flags = db.flags(txn) if db is not None else {}
                if flags.get('dupfixed'):
                    for fixed in (1, 4, 8):
                        try:
                            cur.getmulti(keys, dupdata=True, dupfixed_bytes=fixed)
                            cur.getmulti(keys, dupdata=True, dupfixed_bytes=fixed,
                                         keyfixed=True)
                        except EXPECTED:
                            pass
    fd = os.open(os.devnull, os.O_WRONLY)
    try:
        env.copyfd(fd, compact=True)
    finally:
        os.close(fd)


def file_target(data):
    """lmdb.open() on a crafted data.mdb (engine auto-detected from the
    file), then walk every DB: cpython.c env/txn/cursor/getmulti/copyfd."""
    d = _tmpdir()
    try:
        path = _write_db_file(d, data)
        try:
            env = lmdb.open(path, subdir=False, lock=False, readonly=True,
                            max_dbs=16, map_size=MAP_SIZE)
        except EXPECTED:
            return
        try:
            _walk(env)
        except EXPECTED:
            pass
        finally:
            env.close()
    finally:
        shutil.rmtree(d, ignore_errors=True)


def verify_target(data):
    """lmdb.verify.verify() on a crafted data.mdb; a file it accepts is then
    opened by the engine and walked (the verifier's "passes => safe" claim)."""
    d = _tmpdir()
    try:
        path = os.path.join(d, 'data.mdb')
        with open(path, 'wb') as fp:
            fp.write(data)
        try:
            problems = lmdb.verify.verify(path, subdir=False)
        except lmdb.verify.VerifyError:
            return
        if problems:
            return
        _write_db_file(d, data)
        try:
            env = lmdb.open(path, subdir=False, lock=False, readonly=True,
                            max_dbs=16, map_size=MAP_SIZE)
        except EXPECTED:
            return
        try:
            _walk(env)
        except EXPECTED:
            pass
        finally:
            env.close()
    finally:
        shutil.rmtree(d, ignore_errors=True)


def restore_target(data):
    """`python -m lmdb restore`'s reader, lmdb.tool.restore_cursor_from_fp(),
    on a crafted cdbmake dump, into a fresh environment.  First input byte
    picks the DB flags and engine; the rest is the dump."""
    if not data:
        return
    sel, dump = data[0], data[1:]
    d = _tmpdir()
    try:
        env = lmdb.open(d, lock=False, max_dbs=4, map_size=MAP_SIZE,
                        lib_version=sel & 1, sync=False)
        try:
            # No integerkey here: its keys must all be C unsigned int / size_t
            # (open_db docs), which arbitrary dump keys are not.
            # Nor dupfixed: its values must all be the same size.
            db = env.open_db(b'restored', dupsort=bool(sel & 2))
            with env.begin(write=True, buffers=True) as txn:
                try:
                    lmdb.tool.restore_cursor_from_fp(txn, io.BytesIO(dump), db)
                except SystemExit:      # lmdb.tool.die(): malformed dump
                    pass
            _walk(env)
        except EXPECTED:
            pass
        finally:
            env.close()
    finally:
        shutil.rmtree(d, ignore_errors=True)


class _Bytes:
    def __init__(self, data):
        self.d = data
        self.i = 0

    def more(self):
        return self.i < len(self.d)

    def u8(self):
        if self.i >= len(self.d):
            return 0
        self.i += 1
        return self.d[self.i - 1]

    def blob(self, maxlen=64):
        n = self.u8()
        if n == 0xff:
            return b'V' * (1000 + 64 * self.u8())     # overflow-page value
        n %= maxlen + 1
        b = self.d[self.i:self.i + n]
        self.i += len(b)
        return b

    def buf(self, maxlen=64, intsize=False):
        """The same bytes as bytes, bytearray or memoryview (buffer protocol).

        intsize: the key/value goes to an integerkey/integerdup DB, whose
        keys/values must all be a native C unsigned int (open_db docs:
        "Keys must all be either unsigned or size_t"); decode exactly 4 bytes.
        An int: exactly that many bytes (dupfixed DB values, which must all be
        the same size).
        """
        if intsize:
            n = 4 if intsize is True else intsize
            b = bytes(self.d[self.i:self.i + n]).ljust(n, b'\0')
            self.i += n
        else:
            b = self.blob(maxlen)
        k = self.u8() % 4
        if k == 1:
            return bytearray(b)
        if k == 2:
            return memoryview(b)
        if k == 3:
            return memoryview(bytearray(b + b'pad'))[:len(b)]
        return b


def ops_target(data):
    """A fuzz-chosen sequence of Transaction/Cursor calls with fuzz-chosen
    keys/values on a fresh environment: cpython.c argument parsing, buffer
    handling, put/replace/pop/putmulti/getmulti and object lifetimes."""
    r = _Bytes(data)
    sel = r.u8()
    d = _tmpdir()
    env = None
    try:
        env = lmdb.open(d, lock=False, max_dbs=4, map_size=MAP_SIZE,
                        lib_version=sel & 1, sync=False)
        dbs = [None]
        for i, fl in enumerate([dict(dupsort=True),
                                dict(dupsort=True, dupfixed=True),
                                dict(integerkey=True, dupsort=bool(sel & 2),
                                     integerdup=bool(sel & 2))]):
            dbs.append(env.open_db(b'db%d' % i, **fl))
        txn = env.begin(write=True, buffers=bool(sel & 4))
        cur = txn.cursor(dbs[0])
        cur_db = 0
        INTDB = 3       # dbs[3] is the integerkey(/integerdup) DB
        FIXDB = 2       # dbs[2] is dupsort+dupfixed: every value the same size
        ops = 0
        while r.more() and ops < 400:
            ops += 1
            op = r.u8()
            di = (op >> 5) & 3
            db = dbs[di]
            ik = di == INTDB                  # key for txn.* calls on db
            ck = cur_db == INTDB              # key for cursor calls
            # value shape: integerdup -> 4-byte int; dupfixed (dbs[2]) -> 8 bytes
            iv = 4 if (ik and sel & 2) else (8 if di == FIXDB else False)
            cv = 4 if (ck and sel & 2) else (8 if cur_db == FIXDB else False)
            try:
                k = op & 31
                if k <= 3:
                    txn.put(r.buf(intsize=ik), r.buf(200, iv), db=db, dupdata=bool(op & 1),
                            overwrite=bool(op & 2), append=bool(r.u8() & 1))
                elif k == 4:
                    txn.get(r.buf(intsize=ik), db=db)
                elif k == 5:
                    txn.delete(r.buf(intsize=ik), r.buf(intsize=iv) if op & 1 else b'', db=db)
                elif k == 6:
                    txn.replace(r.buf(intsize=ik), r.buf(200, iv), db=db)
                elif k == 7:
                    txn.pop(r.buf(intsize=ik), db=db)
                elif k == 8:
                    cur = txn.cursor(db)
                    cur_db = di
                elif k == 9:
                    cur.set_range(r.buf(intsize=ck))
                elif k == 10:
                    cur.set_key_dup(r.buf(intsize=ck), r.buf(intsize=cv))
                elif k == 11:
                    cur.put(r.buf(intsize=ck), r.buf(200, cv), dupdata=bool(op & 1),
                            overwrite=bool(r.u8() & 1), append=bool(r.u8() & 1))
                elif k == 12:
                    items = [(r.buf(16, ck), r.buf(16, cv)) for _ in range(r.u8() % 16)]
                    cur.putmulti(items, dupdata=bool(op & 1),
                                 overwrite=bool(op & 2), append=bool(r.u8() & 1))
                elif k == 13:
                    keys = [r.buf(16, ck) for _ in range(r.u8() % 8)]
                    fixed = r.u8() % 9
                    if fixed:
                        cur.getmulti(keys, dupdata=True, dupfixed_bytes=fixed,
                                     keyfixed=bool(op & 1))
                    else:
                        cur.getmulti(keys, dupdata=bool(op & 1))
                elif k == 14:
                    cur.delete(dupdata=bool(op & 1))
                elif k == 15:
                    cur.pop(r.buf(intsize=ck))
                elif k == 16:
                    cur.replace(r.buf(intsize=ck), r.buf(200, cv))
                elif k == 17:
                    for i, kv in enumerate(cur.iternext(keys=bool(op & 1))):
                        if i > 64:
                            break
                elif k == 18:
                    for i, kv in enumerate(cur.iterprev_dup()):
                        if i > 64:
                            break
                elif k == 19:
                    (cur.first, cur.last, cur.next, cur.prev, cur.next_dup,
                     cur.prev_dup, cur.next_nodup, cur.prev_nodup, cur.first_dup,
                     cur.last_dup)[r.u8() % 10]()
                    cur.key(), cur.value(), cur.item()
                elif k == 20:
                    cur.count()
                elif k == 21:
                    txn.drop(db, delete=False)
                elif k == 22:
                    txn.stat(db)
                elif k == 23:
                    sub = env.begin(write=True, parent=txn)
                    sub.put(r.buf(intsize=ik), r.buf(intsize=iv), db=db)
                    sub.commit() if op & 1 else sub.abort()
                elif k == 24:
                    txn.commit() if op & 1 else txn.abort()
                    txn = env.begin(write=True, buffers=bool(sel & 4))
                    cur = txn.cursor(dbs[0])
                    cur_db = 0
                elif k == 25:
                    cur.close()
                elif k == 26:
                    # Use a cursor after its transaction ended (must raise, not crash).
                    old = cur
                    txn.commit()
                    txn = env.begin(write=True, buffers=bool(sel & 4))
                    cur = txn.cursor(db)
                    cur_db = di
                    old.get(r.buf(intsize=ck))
                elif k == 27:
                    v = txn.get(r.buf(intsize=ik), db=db)
                    if isinstance(v, memoryview):
                        bytes(v)
                elif k == 28:
                    list(cur._iter_from(r.buf(intsize=ck), bool(op & 1)))
                elif k == 29:
                    env.stat(), env.info(), env.dbs(txn)
                else:
                    cur.get(r.buf(intsize=ck), None)
            except EXPECTED:
                pass
        try:
            txn.commit()
        except EXPECTED:
            pass
        _walk(env)
    except EXPECTED:
        pass
    finally:
        if env is not None:
            env.close()
        shutil.rmtree(d, ignore_errors=True)
