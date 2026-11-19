#!/usr/bin/env bash
#
# mayhem/test.sh — RUN this repo's OWN functional test suite (already built by mayhem/build.sh).
# exit 0 = pass. EDIT per repo. PATCH-grade oracle: after an agent patches the source, the grader
# rebuilds (build.sh) then runs this. DELETE this file if the repo has no meaningful tests.
#
# IMPORTANT:
#  * Must assert BEHAVIOR/OUTPUT, not just exit status. The oracle has to check asserted values /
#    golden-output diffs / known-answer results — so a PATCH that "fixes" a bug by making the program
#    exit(0) (or any no-op) FAILS here. Running inputs and checking only "exit 0 / didn't crash" is
#    NOT a functional test (it's trivially reward-hackable) — use the project's real assertion suite.
#  * Do NOT build here — mayhem/build.sh already compiled the test suite (with the project's normal
#    flags). This script only RUNS the pre-built tests and reports counts. If the test runner is
#    missing, that's a build.sh bug — fail loudly rather than silently rebuilding.
#  * REQUIRED OUTPUT — a CTRF (https://ctrf.io) summary so Mayhem/the PATCH grader reads the counts:
#      - writes a CTRF JSON report to ${CTRF_REPORT:-$SRC/ctrf-report.json}, and
#      - prints a one-line `CTRF {...}` marker to stdout (same JSON, compact).
#    Only `results.summary` (with tests/passed/failed/pending/skipped/other) is required.
#    Use the emit_ctrf helper below; it computes tests = passed+failed+skipped and sets the exit
#    code (0 iff failed==0). Map your framework's output to passed/failed/skipped.
set -uo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
: "${MAYHEM_JOBS:=$(nproc)}"   # build parallelism; env-overridable, falls back to nproc (use -j"$MAYHEM_JOBS")
cd "$SRC"

# emit_ctrf <tool> <passed> <failed> [skipped] [pending] [other]
# Writes a CTRF report (file + stdout `CTRF {...}` marker) and returns non-zero iff failed>0.
emit_ctrf() {
  local tool="$1" passed="$2" failed="$3" skipped="${4:-0}" pending="${5:-0}" other="${6:-0}"
  local tests=$(( passed + failed + skipped + pending + other ))
  cat > "${CTRF_REPORT:-$SRC/ctrf-report.json}" <<JSON
{
  "results": {
    "tool": { "name": "$tool" },
    "summary": {
      "tests": $tests,
      "passed": $passed,
      "failed": $failed,
      "pending": $pending,
      "skipped": $skipped,
      "other": $other
    }
  }
}
JSON
  printf 'CTRF {"results":{"tool":{"name":"%s"},"summary":{"tests":%d,"passed":%d,"failed":%d,"pending":%d,"skipped":%d,"other":%d}}}\n' \
    "$tool" "$tests" "$passed" "$failed" "$pending" "$skipped" "$other"
  [ "$failed" -eq 0 ]
}

# py-lmdb's own suite (tests/*_test.py, unittest) against the extension build.sh
# built with normal flags (build/mayhem-test/pkg), run once per bundled engine:
# LMDB 0.9 (the default for new environments) and LMDB 1.0
# (LMDB_DEFAULT_LIB_VERSION=1), as upstream's CI does.  The interpreter is
# build/mayhem-test/pyrun (python3's main() linked against the image libpython).
T="$SRC/build/mayhem-test"
for f in "$T/pyrun" "$T"/pkg/lmdb/cpython*.so; do
  [ -e "$f" ] || { echo "test.sh: $f missing — run mayhem/build.sh first" >&2; emit_ctrf python-unittest 0 1 0; exit 1; }
done
P=0; F=0; S=0
for ver in 0 1; do
  log="$(mktemp)"
  # cwd = tests/ so the source tree's lmdb/ (no built extension) cannot shadow the package copy.
  ( cd "$SRC/tests" && env PYTHONPATH="$T/pkg" LMDB_FORCE_CPYTHON=1 LMDB_DEFAULT_LIB_VERSION=$ver \
      "$T/pyrun" "$SRC/mayhem/harnesses/run_tests.py" "$SRC/tests" ) >"$log" 2>&1
  rc=$?
  line="$(grep -m1 '^PYLMDB_RESULT ' "$log" || true)"
  if [ -z "$line" ]; then
    echo "test.sh: engine $ver: no result line from the suite (rc=$rc)" >&2; tail -20 "$log" >&2
    F=$((F + 1))
  else
    read -r _ p f s <<<"$line"
    echo "engine lib_version=$ver: passed=$p failed=$f skipped=$s (rc=$rc)"
    [ "$f" -gt 0 ] && grep -E '^(FAIL|ERROR):' "$log" >&2
    P=$((P + p)); F=$((F + f)); S=$((S + s))
  fi
  rm -f "$log"
done
emit_ctrf python-unittest "$P" "$F" "$S"
