#!/usr/bin/env bash
#
# mayhem/build.sh — build py-lmdb's fuzz targets and its test suite.
#
# Runs in the commit image as `mayhem` in /mayhem (air-gapped and re-runnable:
# everything comes from the tree and apt packages baked into the image).
#
# setup.py's engine preparation is replayed here without setuptools: each
# bundled LMDB tree (lib/ = 0.9, lib1/ = 1.0) is copied, patched with its
# py-lmdb series in setup.py's order (read from setup.py's ENGINES table), and
# for the CPython extension also given its symbol-rename header + engine.c
# glue, exactly as prepare_engine_tree() does.
#
# Outputs
#   /mayhem/mdb09_read  /mayhem/mdb09_write  /mayhem/mdb10_read  /mayhem/mdb10_write
#       C harness over each patched engine (mayhem/harnesses/mdb_fuzz.c)
#   /mayhem/py_file /mayhem/py_ops /mayhem/py_verify /mayhem/py_restore
#       embedded-CPython harness (mayhem/harnesses/py_fuzz.c + pyfuzz.py) with
#       the sanitized lmdb.cpython extension linked in
#   /mayhem/<target>-standalone       run-once reproducers
#   build/mayhem-test/                normal-flags extension + pyrun for test.sh
set -euo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${MAYHEM_JOBS:=$(nproc)}"
: "${COVERAGE_FLAGS=}"
: "${SRC:=/mayhem}"
: "${STANDALONE_FUZZ_MAIN:=/opt/mayhem/StandaloneFuzzTargetMain.c}"
export SANITIZER_FLAGS DEBUG_FLAGS CC CXX LIB_FUZZING_ENGINE MAYHEM_JOBS COVERAGE_FLAGS

cd "$SRC"
OUT="$SRC"
B="$SRC/build/mayhem"           # gitignored by upstream's `build` entry
H="$SRC/mayhem/harnesses"
mkdir -p "$B"

PYVER="$(python3 -c 'import sys; print("%d.%d" % sys.version_info[:2])')"
PYINC="$(python3 -c 'import sysconfig; print(sysconfig.get_paths()["include"])')"
PYEXT="$(python3 -c 'import sysconfig; print(sysconfig.get_config_var("EXT_SUFFIX"))')"
PYLIBS="-lpython${PYVER} -lm -ldl -lpthread"
[ -f "$PYINC/Python.h" ] || { echo "build.sh: Python.h missing (python3-dev)" >&2; exit 1; }

# The engine flags upstream compiles with (setup.py): -UNDEBUG keeps LMDB's
# own asserts live, -w silences its warnings.
ENGINE_FLAGS="-UNDEBUG -w"
# LMDB reads its on-page structures (MDB_node, sub-page MDB_page, 2-byte key
# sizes) at odd addresses by design -- nodes and dupsort sub-pages are only
# byte/2-byte aligned inside a page -- so UBSan's alignment check fires on
# healthy databases within seconds (py_ops/py_restore build valid ones). It is
# relaxed for the engine sources (mdb.c, midl.c) only; the rest of UBSan and
# all of ASan stay on and halting, and cpython.c/the harnesses keep it.
ENGINE_SAN="-fno-sanitize=alignment"

# ---------------------------------------------------------------------------
# 1) Patched engine trees, as setup.py's prepare_engine_tree() makes them.
#    $B/<tag>-plain : patched tree (no renaming) — C harnesses
#    $B/<tag>       : + rename header + engine.c — CPython extension
# ---------------------------------------------------------------------------
ENGINE_TAGS=()
declare -A ENGINE_TREE
while read -r tree patches; do
  case "$tree" in lib) tag=v09 ;; lib1) tag=v10 ;; *) continue ;; esac
  [ -d "$SRC/$tree" ] || continue
  plain="$B/$tag-plain" ; dest="$B/$tag"
  rm -rf "$plain" "$dest"
  cp -r "$SRC/$tree" "$plain"
  for p in $patches; do
    patch -s -N -p3 -d "$plain" < "$SRC/$tree/py-lmdb/$p.patch"
  done
  cp -r "$plain" "$dest"
  cp "$SRC/$tree/py-lmdb/rename.h" "$dest/lmdb_rename.h"
  cp "$SRC/lmdb/engine.c" "$dest/engine.c"
  for f in mdb.c midl.c engine.c; do
    { echo '#include "lmdb_rename.h"'; cat "$dest/$f"; } > "$dest/$f.tmp"
    mv "$dest/$f.tmp" "$dest/$f"
  done
  ENGINE_TAGS+=("$tag"); ENGINE_TREE[$tag]="$tree"
done < <(python3 "$H/engine_patches.py" "$SRC/setup.py")
[ "${#ENGINE_TAGS[@]}" -gt 0 ] || { echo "build.sh: no engine trees found" >&2; exit 1; }

# The extension's compile line (setup.py): every engine's -D flag, the newest
# engine's include dir, lib/py-lmdb and lmdb/.
EXT_DEFS="-DHAVE_PATCHED_LMDB=1"
for tag in "${ENGINE_TAGS[@]}"; do
  case "$tag" in v09) EXT_DEFS+=" -DLMDB_ENGINE_V09=1" ;; v10) EXT_DEFS+=" -DLMDB_ENGINE_V10=1" ;; esac
done
LAST_TAG="${ENGINE_TAGS[-1]}"
EXT_INC="-I$SRC/lib/py-lmdb -I$SRC/lmdb -I$B/$LAST_TAG -I$PYINC"

# compile_set <outdir> <flags...>: objects for the extension + both engines
compile_ext() {
  local od="$1"; shift
  mkdir -p "$od"
  local jobs=()
  # -fno-sanitize=function on cpython.c only: CPython's method tables call
  # every method through a cast PyCFunction/getter pointer (the C API's
  # documented pattern), which UBSan's -fsanitize=function flags on the first
  # method call of every input.  The rest of UBSan and all of ASan stay on.
  "$CC" "$@" -fno-sanitize=function $ENGINE_FLAGS $EXT_DEFS $EXT_INC -c "$SRC/lmdb/cpython.c" -o "$od/cpython.o" & jobs+=($!)
  for tag in "${ENGINE_TAGS[@]}"; do
    for f in mdb midl engine; do
      local def; case "$tag" in v09) def=-DLMDB_ENGINE_V09=1 ;; v10) def=-DLMDB_ENGINE_V10=1 ;; esac
      local es=""; [ "$f" = engine ] || es="$ENGINE_SAN"
      "$CC" "$@" $es $ENGINE_FLAGS $EXT_DEFS $def -I"$B/$tag" -I"$SRC/lmdb" -I"$SRC/lib/py-lmdb" \
        -c "$B/$tag/$f.c" -o "$od/$tag-$f.o" & jobs+=($!)
    done
  done
  local rc=0; for j in "${jobs[@]}"; do wait "$j" || rc=1; done
  return $rc
}

# ---------------------------------------------------------------------------
# 2) Fuzz builds: project code with $SANITIZER_FLAGS (+ coverage for the
#    libFuzzer binaries), harnesses linked twice (libFuzzer / standalone).
# ---------------------------------------------------------------------------
FZ="$SANITIZER_FLAGS $DEBUG_FLAGS -O1 -fsanitize=fuzzer-no-link"
SA="$SANITIZER_FLAGS $DEBUG_FLAGS -O1"

"$CXX" $SANITIZER_FLAGS $DEBUG_FLAGS -c "$SRC/mayhem/lsan_off.cc" -o "$B/lsan_off.o"
"$CC" $SANITIZER_FLAGS $DEBUG_FLAGS -c "$STANDALONE_FUZZ_MAIN" -o "$B/standalone_main.o"

# C engine harnesses: one binary per engine x {read, write}
for tag in "${ENGINE_TAGS[@]}"; do
  plain="$B/$tag-plain"
  for v in fz sa; do
    od="$B/obj-$tag-$v"; mkdir -p "$od"
    if [ "$v" = fz ]; then fl="$FZ"; else fl="$SA"; fi
    "$CC" $fl $ENGINE_SAN $ENGINE_FLAGS -I"$plain" -c "$plain/mdb.c" -o "$od/mdb.o" & p1=$!
    "$CC" $fl $ENGINE_SAN $ENGINE_FLAGS -I"$plain" -c "$plain/midl.c" -o "$od/midl.o" & p2=$!
    wait "$p1"; wait "$p2"
  done
  name="mdb${tag#v}"
  for mode in read write; do
    mdef=""; [ "$mode" = write ] && mdef="-DMDB_FUZZ_WRITE"
    "$CC" $FZ $mdef -I"$plain" -c "$H/mdb_fuzz.c" -o "$B/obj-$tag-fz/h_$mode.o"
    "$CXX" $SANITIZER_FLAGS $DEBUG_FLAGS $LIB_FUZZING_ENGINE "$B/obj-$tag-fz/h_$mode.o" \
      "$B/obj-$tag-fz/mdb.o" "$B/obj-$tag-fz/midl.o" "$B/lsan_off.o" -lpthread \
      -o "$OUT/${name}_$mode"
    "$CC" $SA $mdef -I"$plain" -c "$H/mdb_fuzz.c" -o "$B/obj-$tag-sa/h_$mode.o"
    "$CXX" $SANITIZER_FLAGS $DEBUG_FLAGS "$B/standalone_main.o" "$B/obj-$tag-sa/h_$mode.o" \
      "$B/obj-$tag-sa/mdb.o" "$B/obj-$tag-sa/midl.o" "$B/lsan_off.o" -lpthread \
      -o "$OUT/${name}_$mode-standalone"
  done
done

# Python-level harnesses: sanitized extension objects linked into py_fuzz.c
compile_ext "$B/ext-fz" $FZ
compile_ext "$B/ext-sa" $SA
for t in file ops verify restore; do
  for v in fz sa; do
    if [ "$v" = fz ]; then fl="$FZ"; else fl="$SA"; fi
    "$CC" $fl -DPY_TARGET="\"${t}_target\"" -DPY_SRC="\"$SRC\"" -I"$PYINC" \
      -c "$H/py_fuzz.c" -o "$B/ext-$v/py_$t.o"
  done
  "$CXX" $SANITIZER_FLAGS $DEBUG_FLAGS $LIB_FUZZING_ENGINE "$B/ext-fz/py_$t.o" "$B"/ext-fz/v*.o \
    "$B/ext-fz/cpython.o" "$B/lsan_off.o" $PYLIBS -o "$OUT/py_$t"
  "$CXX" $SANITIZER_FLAGS $DEBUG_FLAGS "$B/standalone_main.o" "$B/ext-sa/py_$t.o" "$B"/ext-sa/v*.o \
    "$B/ext-sa/cpython.o" "$B/lsan_off.o" $PYLIBS -o "$OUT/py_$t-standalone"
done

# ---------------------------------------------------------------------------
# 3) Test build, NORMAL flags (as `setup.py build_ext` compiles it): the
#    lmdb.cpython extension in a package copy, plus `pyrun`, a tiny launcher
#    embedding the same libpython (the suite's interpreter; see test.sh).
# ---------------------------------------------------------------------------
T="$SRC/build/mayhem-test"
rm -rf "$T/pkg"; mkdir -p "$T/pkg/lmdb"
TF="-O2 -fPIC $COVERAGE_FLAGS"
compile_ext "$T/obj" $TF
"$CC" -shared $COVERAGE_FLAGS "$T/obj"/v*.o "$T/obj/cpython.o" -lpthread -o "$T/pkg/lmdb/cpython$PYEXT"
cp "$SRC"/lmdb/*.py "$SRC"/lmdb/*.pyi "$SRC"/lmdb/py.typed "$T/pkg/lmdb/" 2>/dev/null || cp "$SRC"/lmdb/*.py "$T/pkg/lmdb/"
"$CC" -O2 $COVERAGE_FLAGS -I"$PYINC" "$H/pyrun.c" $PYLIBS -o "$T/pyrun"

echo "build.sh: built ${ENGINE_TAGS[*]} engine targets, py targets and test runner"
