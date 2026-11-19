#!/usr/bin/env bash
#
# mayhem/build.sh — build this repo's fuzz harness(es). EDIT per repo.
#
# Runs inside the commit image (mayhem/Dockerfile) as `mayhem` in /mayhem. The base image
# (ghcr.io/savantenvs/base) already exports the build contract — use these, don't redefine:
#   CC, CXX             stock clang / clang++
#   LIB_FUZZING_ENGINE  -fsanitize=fuzzer   (link into each harness that has a LLVMFuzzer entry)
#   SANITIZER_FLAGS     -fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer
#                       (ASan + UBSan, both set to HALT — so Mayhem catches memory AND UB defects)
#   DEBUG_FLAGS         -g -gdwarf-3   (DWARF debug info — always on for fuzz/standalone builds,
#                       independent of the sanitizer off-switch; DWARF version must be < 4)
#   RUST_DEBUG_FLAGS    -C debuginfo=2 -C force-frame-pointers=yes -C llvm-args=-gdwarf-3
#                       (thread through RUSTFLAGS on every cargo-fuzz build)
#   GO_DEBUG_FLAGS      -gcflags=all=-N -l
#                       (thread through go build / go-fuzz-build so the linked ELF keeps symbols)
#   SRC                 /mayhem (the repo source)
#
# Contract: build EVERYTHING here — one runnable binary per fuzz harness, AND the project's test
# suite (so mayhem/test.sh only has to RUN it, never compile). Keep it ADDITIVE (build upstream as
# upstream documents; don't edit upstream files). IMPORTANT: build the PROJECT ITSELF with
# $SANITIZER_FLAGS and $DEBUG_FLAGS (not just the harness) so the fuzzed code is instrumented
# AND carries DWARF < 4 symbols — otherwise ASan/UBSan only see the harness, not the library
# you're trying to find bugs in, and backtraces won't resolve project source lines. Build the TEST
# suite with the project's NORMAL flags (a clean, independent build) so test.sh stays an honest
# functional oracle and won't false-fail on benign UB. Leave the test binary/runner where test.sh
# expects it.
set -euo pipefail

# clang rejects SOURCE_DATE_EPOCH='' (empty) — it must be unset or a valid integer.
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

# Build knobs come from the ENVIRONMENT (overridable), with sane defaults — no if-statements,
# just parameter-expansion fallbacks. Default sanitizers are the base's ASan+UBSan (halting); override
# per build via the Dockerfile's `--build-arg SANITIZER_FLAGS="..."`.
# NB: SANITIZER_FLAGS uses `=` (no colon) on purpose — `=` only fills when the var is UNSET, so an
# explicit EMPTY value (`--build-arg SANITIZER_FLAGS=`) is honored and builds with NO sanitizers
# (useful when you want the program's natural crash / full backtrace, not an ASan report). The other
# knobs use `:=` (default on empty too). MAYHEM_JOBS sets build parallelism (falls back to nproc).
: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
# DEBUG_FLAGS carries DWARF debug info INDEPENDENTLY of the sanitizer off-switch (so an empty
# SANITIZER_FLAGS still yields DWARF symbols). DWARF MUST be < 4 (Mayhem triage can't read >=4); clang-19's
# plain `-g` emits DWARF-5, so `-gdwarf-3` is explicit. Apply $DEBUG_FLAGS to the fuzz/harness/standalone
# builds (NOT the test/oracle build). Rust/Go carry the same intent via their language flags below.
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${RUST_DEBUG_FLAGS:=-C debuginfo=2 -C force-frame-pointers=yes -C llvm-args=-gdwarf-3}"
: "${GO_DEBUG_FLAGS:=-gcflags=all=-N -l}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${MAYHEM_JOBS:=$(nproc)}"
# COVERAGE_FLAGS: empty by default → no effect on the normal oracle build. Set it via the Dockerfile's
# `--build-arg COVERAGE_FLAGS="-fprofile-instr-generate -fcoverage-mapping"` to instrument the TEST
# build for source-coverage measurement (how much of the project the test suite actually exercises —
# a quality signal for the oracle; complements the anti-reward-hack sabotage check). APPEND it to the
# test build's compile+link flags in step 3 (NOT the fuzz build); after `test.sh` runs, merge with
# `llvm-profdata` and report with `llvm-cov`. Empty value is honored (`=`, not `:=`).
: "${COVERAGE_FLAGS=}"
export SANITIZER_FLAGS DEBUG_FLAGS RUST_DEBUG_FLAGS GO_DEBUG_FLAGS CC CXX LIB_FUZZING_ENGINE MAYHEM_JOBS COVERAGE_FLAGS

cd "$SRC"

OUT="$SRC/mayhem/out"            # gitignored (mayhem/.gitignore)
OBJ="$OUT/obj"
mkdir -p "$OBJ"
GITVER="$(git -C "$SRC" describe --tags 2>/dev/null || echo unknown)"
# -fno-sanitize=shift-base: masscan assembles big-endian integers as `px[i]<<24 | ...` (~50 sites in
# 14 files, e.g. the pcap magic check in rawsock-pcapfile.c), which is signed-int shift overflow for
# any byte >= 0x80 and halts on nearly every input though the result is correct. Only that one UBSan
# check is relaxed; ASan and the rest of UBSan stay on and halting.
FUZZ_CFLAGS="$SANITIZER_FLAGS -fno-sanitize=shift-base $DEBUG_FLAGS -O1 -fsanitize=fuzzer-no-link -I$SRC/src"

# 1) The PROJECT, sanitized + SanCov-instrumented: every src/*.c (upstream's Makefile compiles the
#    same flat list). main.c is compiled twice: renamed (-Dmain=masscan_main) for the library the
#    harnesses link — it holds globals other units use — and as-is for the CLI binary.
# templ-payloads.c: payloads_udp_create() — called by main() on EVERY run — checksums its built-in
# odd-length payloads with partial_checksum(), which reads one byte past each (an upstream bug), so
# with global redzones ASan aborts every input before parsing starts. For that one file only, global
# variables get no redzones (-asan-globals=0); its heap/stack checks and all of UBSan stay on.
compile() {
  local src="$1" o="$OBJ/$(basename "${1%.c}").o" extra=""
  case "$src" in */templ-payloads.c) [ -n "$SANITIZER_FLAGS" ] && extra="-mllvm -asan-globals=0" ;; esac
  $CC $FUZZ_CFLAGS $extra -DGIT="\"$GITVER\"" -c "$src" -o "$o"
}
export -f compile; export OBJ FUZZ_CFLAGS GITVER
ls "$SRC"/src/*.c | grep -v '/main\.c$' | xargs -P "$MAYHEM_JOBS" -I{} bash -c 'compile "$1"' _ {}
$CC $FUZZ_CFLAGS -DGIT="\"$GITVER\"" -Dmain=masscan_main -c "$SRC/src/main.c" -o "$OBJ/main_lib.o"
$CC $FUZZ_CFLAGS -DGIT="\"$GITVER\"" -c "$SRC/src/main.c" -o "$OUT/main_cli.o"
rm -f "$OUT/libmasscan.a"
ar rcs "$OUT/libmasscan.a" "$OBJ"/*.o
LIBS="-lm -lrt -ldl -lpthread"
$CXX $SANITIZER_FLAGS $DEBUG_FLAGS -c "$SRC/mayhem/lsan_off.cc" -o "$OUT/lsan_off.o"
$CC $SANITIZER_FLAGS $DEBUG_FLAGS -c "$STANDALONE_FUZZ_MAIN" -o "$OUT/standalone_main.o"

# 2) libFuzzer harnesses (+ -standalone reproducers).
#    name:source:extra-defines
HARNESSES="
fuzz_banner:fuzz_banner.c:
fuzz_banner_smb:fuzz_banner.c:-DFIXED_PROTO=PROTO_SMB -DFIXED_PORT=445
fuzz_banner_ssl:fuzz_banner.c:-DFIXED_PROTO=PROTO_SSL3 -DFIXED_PORT=443
fuzz_frame:fuzz_frame.c:
fuzz_ranges:fuzz_ranges.c:
fuzz_service_probes:fuzz_service_probes.c:
fuzz_pcap_payloads:fuzz_pcap_payloads.c:
"
echo "$HARNESSES" | while IFS=: read -r name src defs; do
  [ -n "$name" ] || continue
  $CC $FUZZ_CFLAGS $defs -c "$SRC/mayhem/harnesses/$src" -o "$OUT/$name.o"
  $CXX $SANITIZER_FLAGS $DEBUG_FLAGS $LIB_FUZZING_ENGINE "$OUT/$name.o" "$OUT/lsan_off.o" \
      "$OUT/libmasscan.a" $LIBS -o "$OUT/$name"
  $CXX $SANITIZER_FLAGS $DEBUG_FLAGS "$OUT/standalone_main.o" "$OUT/$name.o" "$OUT/lsan_off.o" \
      "$OUT/libmasscan.a" $LIBS -o "$OUT/$name-standalone"
done

# 2b) The CLI itself, sanitized + SanCov, for the file-input targets (--readscan, -c): those
#     loaders exit() on malformed input, so they are fuzzed as the program, not in-process. So is
#     --nmap-payloads: its reader underflows a line buffer on any blank line (upstream trim() bug),
#     which stops an in-process fuzzer at once, while a file-input run carries on past it.
$CXX $SANITIZER_FLAGS $DEBUG_FLAGS -fsanitize=fuzzer-no-link "$OUT/main_cli.o" "$OUT/lsan_off.o" \
    "$OUT/libmasscan.a" $LIBS -o "$OUT/masscan"

# 3) Upstream's own build with its NORMAL flags (Makefile CFLAGS) -> bin/masscan, the binary
#    mayhem/test.sh runs (--selftest + known-answer CLI checks).
env -u CFLAGS -u LDFLAGS -u CPPFLAGS make -C "$SRC" -j"$MAYHEM_JOBS" CC="$CC" \
    ${COVERAGE_FLAGS:+CFLAGS="-g -O2 -Wall $COVERAGE_FLAGS"} ${COVERAGE_FLAGS:+LIBS="-lm -lrt -ldl -lpthread $COVERAGE_FLAGS"}
echo "build.sh: done"
