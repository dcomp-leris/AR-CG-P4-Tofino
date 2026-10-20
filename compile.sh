#!/bin/bash
# Compile ICEFE.p4 for Tofino 2 (takes ~10-15 min). Output: ./ICEFE/ (bfrt.json, pipe/tofino2.bin ...)
#   bash compile.sh
# Expected result: "0 errors, 28 warnings" (warnings are unused legacy registers/tables).
SDE=${SDE:-/opt/bf-sde-9.13.4}       # SDE location (override: SDE=/my/sde bash compile.sh)
HERE="$(cd "$(dirname "$0")" && pwd)"
cd "$HERE" || exit 1
"$SDE/install/bin/bf-p4c" --target tofino2 --arch t2na -g --verbose 2 -o ICEFE ICEFE.p4 2>&1 | tee ICEFE.compile.log
bash make_switchd_conf.sh                        # (re)write the bf_switchd configuration
