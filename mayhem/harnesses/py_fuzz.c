/*
 * libFuzzer harness for the py-lmdb Python binding (lmdb/cpython.c over both
 * bundled engines), driven through its public Python API.
 *
 * The sanitized lmdb.cpython extension is linked statically into this binary
 * and registered as a built-in module (PyImport_AppendInittab), so ASan/UBSan
 * and coverage see cpython.c and both engines; the rest of the package
 * (lmdb/__init__.py, verify.py, tool.py, _envid.py) is imported from the
 * source tree.  Each target is one function in mayhem/harnesses/pyfuzz.py,
 * selected at compile time with -DPY_TARGET="<function>".
 *
 * The Python function returns normally for any input (it catches the
 * exceptions the API documents for bad input / bad files).  Any other Python
 * exception is a bug in py-lmdb and aborts with the traceback.
 *
 * Python coverage feedback: lmdb/verify.py, lmdb/tool.py and lmdb/__init__.py
 * are pure Python, which SanitizerCoverage cannot see.  A C trace function
 * (PyEval_SetTrace) turns every line-to-line transition inside the source
 * tree's lmdb/ package into an AFL-style edge in libFuzzer's extra-counters
 * section -- the same mechanism atheris uses for instrumented imports -- so
 * the verifier's and the cdbmake reader's branches guide the fuzzer.  Code
 * outside lmdb/ (the harness, the stdlib) is not traced.
 *
 * Kept across inputs on purpose: the interpreter and imported modules.  Each
 * input opens its own Environment on its own temp file and closes it, so no
 * database state survives an input.
 */
#include <Python.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef PY_TARGET
#error "define PY_TARGET"
#endif
#ifndef PY_SRC
#define PY_SRC "/mayhem"
#endif

PyMODINIT_FUNC PyInit_cpython(void);

static PyObject *target_fn;

/* --- Python line-edge coverage -> libFuzzer extra counters --------------- */
#define PYCOV_SIZE (1u << 16)
__attribute__((used, section("__libfuzzer_extra_counters")))
static uint8_t pycov[PYCOV_SIZE];

/* code object -> stable id (0 = not ours), open addressing.  The traced code
 * objects belong to imported modules, which live for the whole process, so
 * their addresses are stable keys; the id is derived from file name + first
 * line only, so it is the same in every process. */
#define CODE_SLOTS 8192
static struct { PyCodeObject *code; uint32_t id; } code_tab[CODE_SLOTS];
static uint32_t pycov_prev;

static uint32_t code_id(PyCodeObject *co)
{
    size_t h = ((uintptr_t)co >> 4) & (CODE_SLOTS - 1);
    for (size_t n = 0; n < CODE_SLOTS; n++, h = (h + 1) & (CODE_SLOTS - 1)) {
        if (code_tab[h].code == co)
            return code_tab[h].id;
        if (code_tab[h].code == NULL) {
            uint32_t id = 0;
            const char *fn = PyUnicode_AsUTF8(co->co_filename);
            static const char pfx[] = PY_SRC "/lmdb/";
            if (fn && strncmp(fn, pfx, sizeof pfx - 1) == 0) {
                id = 2166136261u;           /* FNV-1a(file) ^ first line */
                for (const char *c = fn; *c; c++)
                    id = (id ^ (uint8_t)*c) * 16777619u;
                id ^= (uint32_t)co->co_firstlineno * 0x9E3779B1u;
                id |= 1;
            } else {
                PyErr_Clear();
            }
            Py_INCREF(co);              /* keep the key alive */
            code_tab[h].code = co;
            code_tab[h].id = id;
            return id;
        }
    }
    return 0;                           /* table full: stop adding */
}

static int pycov_trace(PyObject *obj, PyFrameObject *frame, int what, PyObject *arg)
{
    (void)obj;
    (void)arg;
    if (what != PyTrace_LINE && what != PyTrace_CALL && what != PyTrace_RETURN)
        return 0;
    PyCodeObject *co = PyFrame_GetCode(frame);
    uint32_t id = code_id(co);
    Py_DECREF(co);
    if (!id)
        return 0;
    uint32_t cur = (id ^ ((uint32_t)PyFrame_GetLineNumber(frame) * 0x85EBCA6Bu)
                    ^ ((uint32_t)what << 29)) & (PYCOV_SIZE - 1);
    uint8_t *c = &pycov[cur ^ pycov_prev];
    if (*c != 255)
        (*c)++;
    pycov_prev = cur >> 1;
    return 0;
}

static void die_with_traceback(const char *what)
{
    fprintf(stderr, "py_fuzz: %s\n", what);
    if (PyErr_Occurred())
        PyErr_Print();
    fflush(stderr);
    abort();
}

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    (void)argc;
    (void)argv;
    PyStatus st;
    PyPreConfig pre;
    PyConfig cfg;

    if (PyImport_AppendInittab("lmdb.cpython", PyInit_cpython) != 0)
        die_with_traceback("AppendInittab failed");

    /* Plain malloc, so ASan sees every Python object allocation. */
    PyPreConfig_InitIsolatedConfig(&pre);
    pre.allocator = PYMEM_ALLOCATOR_MALLOC;
    st = Py_PreInitialize(&pre);
    if (PyStatus_Exception(st))
        Py_ExitStatusException(st);

    PyConfig_InitIsolatedConfig(&cfg);
    cfg.write_bytecode = 0;
    cfg.install_signal_handlers = 0;
    cfg.site_import = 0;
    st = Py_InitializeFromConfig(&cfg);
    PyConfig_Clear(&cfg);
    if (PyStatus_Exception(st))
        Py_ExitStatusException(st);

    if (PyRun_SimpleString("import sys\n"
                           "sys.path[:0] = ['" PY_SRC "/mayhem/harnesses', '" PY_SRC "']\n") != 0)
        die_with_traceback("sys.path setup failed");
    PyObject *mod = PyImport_ImportModule("pyfuzz");
    if (!mod)
        die_with_traceback("import pyfuzz failed");
    target_fn = PyObject_GetAttrString(mod, PY_TARGET);
    Py_DECREF(mod);
    if (!target_fn)
        die_with_traceback("pyfuzz." PY_TARGET " missing");
    PyEval_SetTrace(pycov_trace, NULL);
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    pycov_prev = 0;
    PyObject *buf = PyBytes_FromStringAndSize((const char *)data, (Py_ssize_t)size);
    if (!buf)
        die_with_traceback("PyBytes_FromStringAndSize failed");
    PyObject *res = PyObject_CallOneArg(target_fn, buf);
    Py_DECREF(buf);
    if (!res)
        die_with_traceback("unexpected Python exception from pyfuzz." PY_TARGET);
    Py_DECREF(res);
    return 0;
}
