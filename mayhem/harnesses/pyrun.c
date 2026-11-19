/*
 * pyrun — the interpreter mayhem/test.sh runs py-lmdb's test suite with: a
 * plain `python3` main() linked against the image's libpython, built by
 * mayhem/build.sh next to the freshly built lmdb.cpython extension.
 */
#include <Python.h>

int main(int argc, char **argv)
{
    return Py_BytesMain(argc, argv);
}
