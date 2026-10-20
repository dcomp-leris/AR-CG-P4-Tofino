#!/bin/bash
# Compile ICEFE.p4 for Tofino 2 (takes ~10-15 min). Output: ./ICEFE/ (bfrt.json, pipe/tofino2.bin ...)
#   bash compile.sh                                      # ECN-Preserving Admission (default)
#   ICEFE_ADMISSION_MODE=operator-ect1 bash compile.sh  # Operator-Controlled ECT(1) Admission
# Expected result: 0 errors. Warnings concern unused legacy registers/tables.
set -euo pipefail
SDE=${SDE:-/opt/bf-sde-9.13.4}       # SDE location (override: SDE=/my/sde bash compile.sh)
HERE="$(cd "$(dirname "$0")" && pwd)"
cd "$HERE" || exit 1

ADMISSION_MODE=${ICEFE_ADMISSION_MODE:-ecn-preserving}
case "$ADMISSION_MODE" in
    ecn-preserving) ECT1_REWRITE=0 ;;
    operator-ect1)  ECT1_REWRITE=1 ;;
    *)
        echo "ICEFE_ADMISSION_MODE must be 'ecn-preserving' or 'operator-ect1'" >&2
        exit 2
        ;;
esac

echo "ICEFE admission mode: $ADMISSION_MODE"
"$SDE/install/bin/bf-p4c" --target tofino2 --arch t2na \
    -DICEFE_OPERATOR_CONTROLLED_ECT1="$ECT1_REWRITE" \
    -g --verbose 2 -o ICEFE ICEFE.p4 2>&1 | tee ICEFE.compile.log
bash make_switchd_conf.sh                        # (re)write the bf_switchd configuration
