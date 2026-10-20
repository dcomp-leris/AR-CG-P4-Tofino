#!/bin/bash
# Switch side of one training/test replay (run on the Tofino as a normal user while bf_switchd
# runs, and with no interactive bfrt_python open).
#   bash scripts/train_step.sh prep|collect DL|UL TAG        e.g.  bash scripts/train_step.sh prep DL train_DL
#   prep    : load ICEFE, unshaped port 137, clone budget DL (52/13) or UL (32/8), clear per-flow state
#   collect : after the replay, dump the per-flow feature registers to raw/training/features_TAG.json
HERE="$(cd "$(dirname "$0")" && pwd)"                       # .../scripts
SDE=${SDE:-/opt/bf-sde-9.13.4}
mkdir -p /tmp/c7
# Small launcher read by bfshell: it sets the three parameters and runs train_switch.py.
printf "C7_MODE = '%s'\nC7_BUDGET = '%s'\nC7_TAG = '%s'\nC7_ROOT = '%s'\nexec(open('%s/train_switch.py').read())\n" \
       "$1" "$2" "$3" "$(cd "$HERE/.." && pwd)" "$HERE" > /tmp/c7/train_$1_$3.py
# bfshell -b needs a terminal: 'script' provides one. Only the useful lines are shown.
cd /tmp/c7 && script -qfc "$SDE/install/bin/bfshell -b /tmp/c7/train_$1_$3.py" /dev/null | grep -E "c7 |ICEFE|entries|Error|error|Traceback"
