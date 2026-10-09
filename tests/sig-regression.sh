#!/usr/bin/env bash
# sig-regression.sh — pairwise diff check over 5 seeds.
#
# Builds donut five times with DONUT_SEED in {"", rot1, rot2, rot3, rot4}.
# Asserts (a) all five sha256(donut) differ pairwise ignoring the stock
# collision, (b) all five sha256(loader_exe_x64.h) differ pairwise, (c) the
# KAT passes under each seed. Runs as the LAST step of the Docker donut-build
# stage. Fails the Docker build on any assertion.

set -euo pipefail

SEEDS=("" "rot-a-$$" "rot-b-$$" "rot-c-$$" "rot-d-$$")
declare -a BIN_SHAS
declare -a HDR_SHAS

for s in "${SEEDS[@]}"; do
  echo "sig-regression: building with DONUT_SEED='${s}'"
  make -s clean >/dev/null 2>&1 || true
  DONUT_SEED="$s" make -s donut >/dev/null
  DONUT_SEED="$s" make -s kat >/dev/null
  ./kat >/dev/null || { echo "sig-regression: KAT failed under seed='${s}'"; exit 1; }
  BIN_SHAS+=("$(sha256sum donut | awk '{print $1}')")
  HDR_SHAS+=("$(sha256sum loader_exe_x64.h | awk '{print $1}')")
done

# Pairwise diffs for non-stock seeds (indexes 1..4 must all differ).
for i in 1 2 3 4; do
  for j in 1 2 3 4; do
    if [ "$i" -lt "$j" ]; then
      if [ "${BIN_SHAS[$i]}" = "${BIN_SHAS[$j]}" ]; then
        echo "sig-regression: FAIL — donut binary sha256 collides across seeds $i,$j"
        exit 1
      fi
      if [ "${HDR_SHAS[$i]}" = "${HDR_SHAS[$j]}" ]; then
        echo "sig-regression: FAIL — loader_exe_x64.h sha256 collides across seeds $i,$j"
        exit 1
      fi
    fi
  done
done

echo "sig-regression: ok — 5 seeds built, 4 non-stock seeds pairwise distinct on both artifacts"
