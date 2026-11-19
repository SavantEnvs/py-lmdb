/*
 * libFuzzer harness for the bundled, py-lmdb-patched LMDB engines (lib/ = 0.9,
 * lib1/ = 1.0), driven through the public mdb_* API on a crafted data.mdb.
 *
 * The same source is built once per engine tree, twice per tree:
 *   (default)          read walk: open the file read-only and walk every DB
 *   -DMDB_FUZZ_WRITE   write path: open it read-write, run a short op script
 *                      (put/del/cursor ops/drop/commit), then do the read walk
 *
 * Input layout
 *   read : the whole input is the data.mdb file.
 *   write: <data.mdb bytes> <script bytes> <1 byte: script length>
 *          i.e. the LAST byte says how many bytes before it are the op script;
 *          everything before the script is the file.
 *
 * Per-input state: the input is written to a fresh mkstemp() file in $TMPDIR
 * (fallback /tmp), opened with MDB_NOSUBDIR|MDB_NOLOCK (no lock.mdb / reader
 * table, so nothing is shared between inputs), and unlinked afterwards.  The
 * file is extended (sparse, zero-filled) to MAP_SIZE so pages a valid-looking
 * meta page points at, but which a short input does not contain, read as
 * zero pages instead of SIGBUS on the mapping past EOF; that is what a real
 * environment whose map was grown looks like on disk.
 */
#define _GNU_SOURCE
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "lmdb.h"

#define MAP_SIZE   (8u << 20)   /* 8 MiB map; caps what a crafted meta can ask */
#define MAX_DBS    16
#define MAX_NAMED  8            /* named sub-DBs probed per input */
#define MAX_STEPS  20000        /* cursor steps per DB (bounds exec cost only) */

static int write_input(char *path, size_t pathlen, const uint8_t *data, size_t size)
{
    const char *dir = getenv("TMPDIR");
    if (!dir || !*dir)
        dir = "/tmp";
    snprintf(path, pathlen, "%s/mdbfuzz-XXXXXX", dir);
    int fd = mkstemp(path);
    if (fd < 0)
        return -1;
    size_t off = 0;
    while (off < size) {
        ssize_t n = write(fd, data + off, size - off);
        if (n <= 0) {
            close(fd);
            unlink(path);
            return -1;
        }
        off += (size_t)n;
    }
    if (size < MAP_SIZE && ftruncate(fd, MAP_SIZE) != 0) {
        close(fd);
        unlink(path);
        return -1;
    }
    close(fd);
    return 0;
}

static volatile size_t sink;

static void touch(const MDB_val *v)
{
    /* Read every byte the engine hands back, as a caller would. */
    const unsigned char *p = v->mv_data;
    size_t acc = 0;
    if (!p)
        return;
    for (size_t i = 0; i < v->mv_size; i++)
        acc += p[i];
    sink += acc;
}

static void walk_db(MDB_txn *txn, MDB_dbi dbi)
{
    MDB_stat st;
    unsigned int flags = 0;
    MDB_cursor *c;
    MDB_val k, v, first = {0, NULL};
    size_t cnt;
    int rc, steps;

    mdb_stat(txn, dbi, &st);
    mdb_dbi_flags(txn, dbi, &flags);
    if (mdb_cursor_open(txn, dbi, &c) != MDB_SUCCESS)
        return;

    /* forward over every record (and every duplicate) */
    for (rc = mdb_cursor_get(c, &k, &v, MDB_FIRST), steps = 0;
         rc == MDB_SUCCESS && steps < MAX_STEPS;
         rc = mdb_cursor_get(c, &k, &v, MDB_NEXT), steps++) {
        touch(&k);
        touch(&v);
        if (!first.mv_data)
            first = k;
        if (flags & MDB_DUPSORT) {
            mdb_cursor_count(c, &cnt);
            if (flags & MDB_DUPFIXED) {
                MDB_val mk, mv;
                if (mdb_cursor_get(c, &mk, &mv, MDB_GET_MULTIPLE) == MDB_SUCCESS)
                    touch(&mv);
                while (mdb_cursor_get(c, &mk, &mv, MDB_NEXT_MULTIPLE) == MDB_SUCCESS &&
                       ++steps < MAX_STEPS)
                    touch(&mv);
            }
        }
    }

    /* backwards, by key, then by duplicate */
    for (rc = mdb_cursor_get(c, &k, &v, MDB_LAST), steps = 0;
         rc == MDB_SUCCESS && steps < MAX_STEPS;
         rc = mdb_cursor_get(c, &k, &v, (steps & 1) ? MDB_PREV_NODUP : MDB_PREV), steps++) {
        touch(&k);
        if ((flags & MDB_DUPSORT) && mdb_cursor_get(c, &k, &v, MDB_LAST_DUP) == MDB_SUCCESS)
            touch(&v);
    }

    /* point lookups via the first key */
    if (first.mv_data) {
        MDB_val key = first, data;
        if (mdb_get(txn, dbi, &key, &data) == MDB_SUCCESS)
            touch(&data);
        key = first;
        if (mdb_cursor_get(c, &key, &data, MDB_SET_RANGE) == MDB_SUCCESS) {
            touch(&data);
            mdb_cursor_get(c, &key, &data, MDB_NEXT_NODUP);
        }
        if (flags & MDB_DUPSORT) {
            key = first;
            if (mdb_cursor_get(c, &key, &data, MDB_SET) == MDB_SUCCESS &&
                mdb_cursor_get(c, &key, &data, MDB_LAST_DUP) == MDB_SUCCESS) {
                MDB_val d2 = data;
                mdb_cursor_get(c, &key, &d2, MDB_GET_BOTH_RANGE);
            }
        }
    }
    mdb_cursor_close(c);
}

/* Read walk over the main DB and every named DB it lists. */
static void read_walk(MDB_env *env, unsigned int txn_flags)
{
    MDB_txn *txn;
    MDB_dbi main_dbi, dbis[MAX_NAMED];
    char names[MAX_NAMED][64];
    int nnamed = 0;
    MDB_cursor *c;
    MDB_val k, v;
    MDB_envinfo info;
    MDB_stat est;

    mdb_env_info(env, &info);
    mdb_env_stat(env, &est);
    if (mdb_txn_begin(env, NULL, txn_flags, &txn) != MDB_SUCCESS)
        return;
    if (mdb_dbi_open(txn, NULL, 0, &main_dbi) != MDB_SUCCESS) {
        mdb_txn_abort(txn);
        return;
    }
    walk_db(txn, main_dbi);

    /* Keys of the main DB are the names of the sub-databases. */
    if (mdb_cursor_open(txn, main_dbi, &c) == MDB_SUCCESS) {
        int rc;
        for (rc = mdb_cursor_get(c, &k, &v, MDB_FIRST);
             rc == MDB_SUCCESS && nnamed < MAX_NAMED;
             rc = mdb_cursor_get(c, &k, &v, MDB_NEXT_NODUP)) {
            if (k.mv_size == 0 || k.mv_size >= sizeof(names[0]) ||
                memchr(k.mv_data, 0, k.mv_size))
                continue;
            memcpy(names[nnamed], k.mv_data, k.mv_size);
            names[nnamed][k.mv_size] = 0;
            nnamed++;
        }
        mdb_cursor_close(c);
    }
    for (int i = 0; i < nnamed; i++) {
        if (mdb_dbi_open(txn, names[i], 0, &dbis[i]) == MDB_SUCCESS)
            walk_db(txn, dbis[i]);
    }
    mdb_txn_abort(txn);

    /* A compacting copy walks every tree again, through the copy code. */
    int fd = open("/dev/null", O_WRONLY);
    if (fd >= 0) {
        mdb_env_copyfd2(env, fd, MDB_CP_COMPACT);
        close(fd);
    }
}

#ifdef MDB_FUZZ_WRITE
struct script {
    const uint8_t *p;
    size_t n, i;
};

static uint8_t sbyte(struct script *s)
{
    return s->i < s->n ? s->p[s->i++] : 0;
}

/* Take a length-prefixed byte string from the script. */
static MDB_val sval(struct script *s, size_t maxlen)
{
    MDB_val v;
    size_t len = sbyte(s);
    if (len == 0xff)                    /* big value: overflow pages */
        len = 1000u + 64u * (size_t)sbyte(s);
    else if (len > maxlen)
        len %= maxlen + 1;
    if (len > s->n - s->i && len < 1000u) /* short of bytes: use what is left */
        len = s->n - s->i;
    v.mv_size = len;
    if (len <= s->n - s->i) {
        v.mv_data = (void *)(s->p + s->i);
        s->i += len;
    } else {
        /* big value from a static pattern buffer (contents don't matter) */
        static uint8_t big[1000 + 64 * 255];
        memset(big, 'v', sizeof(big));
        v.mv_data = big;
    }
    return v;
}

/*
 * MDB_INTEGERKEY / MDB_INTEGERDUP: lmdb.h requires those keys / data items to
 * be binary unsigned int or size_t ("The keys must all be of the same size").
 * The caller owns that contract, so for such a DB (flags as the engine
 * reports them, which for an existing DB come from the file) the script
 * yields exactly sizeof(unsigned int) bytes instead of a free-length string.
 */
static MDB_val sint(struct script *s)
{
    static uint8_t zero[sizeof(unsigned int)];
    MDB_val v = {sizeof(unsigned int), zero};
    if (s->n - s->i >= sizeof(unsigned int)) {
        v.mv_data = (void *)(s->p + s->i);
        s->i += sizeof(unsigned int);
    } else {
        s->i = s->n;
    }
    return v;
}

/* MDB_DUPFIXED: "data items are all the same size" (lmdb.h); exactly n bytes. */
static uint8_t zeros[65536];
static MDB_val sfix(struct script *s, size_t n)
{
    MDB_val v = {n, zeros};
    if (n > sizeof zeros)
        v.mv_size = sizeof zeros;           /* engine rejects it (BAD_VALSIZE) */
    if (s->n - s->i >= v.mv_size) {
        v.mv_data = (void *)(s->p + s->i);
        s->i += v.mv_size;
    } else {
        s->i = s->n;
    }
    return v;
}

/* The size an existing DUPFIXED DB's items already have (8 if it is empty). */
static size_t fixed_size(MDB_txn *txn, MDB_dbi dbi)
{
    MDB_cursor *c;
    MDB_val k, v;
    size_t n = 8;
    if (mdb_cursor_open(txn, dbi, &c) == MDB_SUCCESS) {
        if (mdb_cursor_get(c, &k, &v, MDB_FIRST) == MDB_SUCCESS)
            n = v.mv_size;
        mdb_cursor_close(c);
    }
    return n;
}

#define KEY(maxlen) ((dfl[d] & MDB_INTEGERKEY) ? sint(&s) : sval(&s, (maxlen)))
#define VAL(maxlen) ((dfl[d] & MDB_INTEGERDUP) ? sint(&s) :              \
                     (dfl[d] & MDB_DUPFIXED) ? sfix(&s, fsz[d]) : sval(&s, (maxlen)))

static const unsigned int dbflag_choices[] = {
    0, MDB_DUPSORT, MDB_DUPSORT | MDB_DUPFIXED, MDB_INTEGERKEY,
    MDB_DUPSORT | MDB_INTEGERDUP | MDB_DUPFIXED, MDB_REVERSEKEY,
    MDB_DUPSORT | MDB_REVERSEDUP, 0,
};

static void run_script(MDB_env *env, const uint8_t *p, size_t n)
{
    struct script s = {p, n, 0};
    MDB_txn *txn;
    MDB_dbi dbi[4];
    int have[4] = {0};
    unsigned int dfl[4] = {0};
    size_t fsz[4] = {8, 8, 8, 8};
    int ops = 0;

    if (mdb_txn_begin(env, NULL, 0, &txn) != MDB_SUCCESS)
        return;
    if (mdb_dbi_open(txn, NULL, 0, &dbi[0]) != MDB_SUCCESS) {
        mdb_txn_abort(txn);
        return;
    }
    have[0] = 1;
    mdb_dbi_flags(txn, dbi[0], &dfl[0]);
    if (dfl[0] & MDB_DUPFIXED)
        fsz[0] = fixed_size(txn, dbi[0]);

    while (s.i < s.n && ops++ < 256) {
        uint8_t op = sbyte(&s);
        int d = (op >> 4) & 3;
        if (!have[d]) {
            char name[8];
            snprintf(name, sizeof name, "db%d", d);
            unsigned int fl = dbflag_choices[(op >> 6) | ((d & 1) << 2)];
            if (mdb_dbi_open(txn, name, MDB_CREATE | fl, &dbi[d]) != MDB_SUCCESS &&
                mdb_dbi_open(txn, name, 0, &dbi[d]) != MDB_SUCCESS)
                d = 0;
            else
                have[d] = 1;
            if (have[d]) {
                mdb_dbi_flags(txn, dbi[d], &dfl[d]);
                if (dfl[d] & MDB_DUPFIXED)
                    fsz[d] = fixed_size(txn, dbi[d]);
            }
        }
        switch (op & 15) {
        case 0: case 1: case 2: {         /* put */
            MDB_val k = KEY(64), v = VAL(200);
            static const unsigned int pf[] = {0, MDB_NOOVERWRITE, MDB_NODUPDATA};
            mdb_put(txn, dbi[d], &k, &v, pf[(op & 15) % 3]);
            break;
        }
        case 3: {                         /* reserve put */
            /* lmdb.h, MDB_RESERVE: "This flag must not be specified if the
             * database was opened with MDB_DUPSORT" -- a plain put there. */
            if (dfl[d] & MDB_DUPSORT) {
                MDB_val k = KEY(64), v = VAL(200);
                mdb_put(txn, dbi[d], &k, &v, 0);
                break;
            }
            MDB_val k = KEY(64), v;
            v.mv_size = sbyte(&s) * 17u;
            v.mv_data = NULL;
            if (mdb_put(txn, dbi[d], &k, &v, MDB_RESERVE) == MDB_SUCCESS && v.mv_data)
                memset(v.mv_data, 'r', v.mv_size);
            break;
        }
        case 4: case 5: {                 /* delete key / key+data */
            MDB_val k = KEY(64), v = VAL(200);
            mdb_del(txn, dbi[d], &k, (op & 1) ? &v : NULL);
            break;
        }
        case 6: case 7: {                 /* cursor put/del at a position */
            MDB_cursor *c;
            if (mdb_cursor_open(txn, dbi[d], &c) != MDB_SUCCESS)
                break;
            MDB_val k = KEY(64), v;
            static const MDB_cursor_op pos[] = {MDB_SET_RANGE, MDB_FIRST, MDB_LAST, MDB_SET};
            if (mdb_cursor_get(c, &k, &v, pos[sbyte(&s) & 3]) == MDB_SUCCESS) {
                if (op & 1) {
                    mdb_cursor_del(c, (sbyte(&s) & 1) ? MDB_NODUPDATA : 0);
                } else {
                    MDB_val nv = VAL(200);
                    /* lmdb.h, MDB_CURRENT: with MDB_DUPSORT "the data item
                     * must still sort into the same place", which fresh
                     * script data need not -- so dupsort DBs get a plain
                     * cursor put (a new dup or a no-op on an existing one). */
                    unsigned int cf = (sbyte(&s) & 1) ? MDB_CURRENT : 0;
                    if (dfl[d] & MDB_DUPSORT)
                        cf = 0;
                    mdb_cursor_put(c, &k, &nv, cf);
                }
            }
            mdb_cursor_close(c);
            break;
        }
        case 8: {                         /* append run (page splits) */
            MDB_val k = sval(&s, 32);
            unsigned int cnt = sbyte(&s);
            uint8_t kb[40];
            for (unsigned int j = 0; j < cnt; j++) {
                size_t kl = k.mv_size < 32 ? k.mv_size : 32;
                memcpy(kb, k.mv_data ? k.mv_data : "", kl);
                kb[kl] = (uint8_t)(j >> 8);
                kb[kl + 1] = (uint8_t)j;
                MDB_val kk = {kl + 2, kb}, vv = {j % 97 + 1, zeros};
                unsigned int ik = j, iv = j * 7u;
                if (dfl[d] & MDB_INTEGERKEY)
                    kk = (MDB_val){sizeof ik, &ik};
                if (dfl[d] & MDB_INTEGERDUP)
                    vv = (MDB_val){sizeof iv, &iv};
                else if (dfl[d] & MDB_DUPFIXED)
                    vv = (MDB_val){fsz[d] < sizeof zeros ? fsz[d] : sizeof zeros, zeros};
                mdb_put(txn, dbi[d], &kk, &vv, 0);
            }
            break;
        }
        case 9:                           /* empty or delete a sub-DB */
            if (d != 0) {
                mdb_drop(txn, dbi[d], sbyte(&s) & 1);
                have[d] = 0;
            }
            break;
        case 10: case 11: {               /* commit, start a new txn */
            int rc = mdb_txn_commit(txn);
            memset(have, 0, sizeof have);
            if (rc != MDB_SUCCESS || mdb_txn_begin(env, NULL, 0, &txn) != MDB_SUCCESS)
                return;
            if (mdb_dbi_open(txn, NULL, 0, &dbi[0]) != MDB_SUCCESS) {
                mdb_txn_abort(txn);
                return;
            }
            have[0] = 1;
            mdb_dbi_flags(txn, dbi[0], &dfl[0]);
            if (dfl[0] & MDB_DUPFIXED)
                fsz[0] = fixed_size(txn, dbi[0]);
            break;
        }
        case 12: {                        /* nested txn, aborted or committed */
            MDB_txn *child;
            if (mdb_txn_begin(env, txn, 0, &child) == MDB_SUCCESS) {
                MDB_val k = KEY(64), v = VAL(200);
                mdb_put(child, dbi[d], &k, &v, 0);
                if (sbyte(&s) & 1)
                    mdb_txn_commit(child);
                else
                    mdb_txn_abort(child);
            }
            break;
        }
        default: {                        /* lookup */
            MDB_val k = KEY(64), v;
            if (mdb_get(txn, dbi[d], &k, &v) == MDB_SUCCESS)
                touch(&v);
            break;
        }
        }
    }
    mdb_txn_commit(txn);
}
#endif

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    char path[4096];
    MDB_env *env;
    const uint8_t *script = NULL;
    size_t nscript = 0;

#ifdef MDB_FUZZ_WRITE
    if (size < 1)
        return 0;
    nscript = data[size - 1];
    size--;
    if (nscript > size)
        nscript = size;
    script = data + size - nscript;
    size -= nscript;
#endif
    (void)script;
    (void)nscript;

    if (write_input(path, sizeof path, data, size) != 0)
        return 0;
    if (mdb_env_create(&env) == MDB_SUCCESS) {
        mdb_env_set_maxdbs(env, MAX_DBS);
        mdb_env_set_mapsize(env, MAP_SIZE);
#ifdef MDB_FUZZ_WRITE
        if (mdb_env_open(env, path, MDB_NOSUBDIR | MDB_NOLOCK | MDB_NOSYNC, 0600) == MDB_SUCCESS) {
            run_script(env, script, nscript);
            read_walk(env, MDB_RDONLY);
        }
#else
        if (mdb_env_open(env, path, MDB_NOSUBDIR | MDB_NOLOCK | MDB_RDONLY, 0600) == MDB_SUCCESS)
            read_walk(env, MDB_RDONLY);
#endif
        mdb_env_close(env);
    }
    unlink(path);
    return 0;
}
