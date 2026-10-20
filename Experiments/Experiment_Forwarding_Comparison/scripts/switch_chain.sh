#!/bin/bash
# Run ONCE on the Tofino with sudo after stopping the current switchd:
#   sudo env SDE=/path/to/bf-sde-9.13.4 bash scripts/switch_chain.sh
# For each run in raw/runs/sequence.txt it cold-starts bf_switchd with that run's
# program, waits until the run writes switch_done.json (or abort.json), stops it.
# The BFRT side is driven separately (bfshell -b) by the operator's driver.
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SDE=${SDE:-/opt/bf-sde-9.13.4}
if pgrep -x bf_switchd >/dev/null; then echo "Stop the running bf_switchd first."; exit 1; fi
fuser -k 9090/tcp 2>/dev/null
$SDE/install/libexec/bf_kdrv_mod_load || true   # same as run.sh; harmless if already loaded
while read -r run prog; do
  [ -z "$run" ] && continue
  dir=$ROOT/raw/runs/$run
  [ -e "$dir/switch_done.json" ] && { echo "skip $run (done)"; continue; }
  echo "=== $run ($prog) $(date -Is)"
  env SDE=$SDE SDE_INSTALL=$SDE/install LD_LIBRARY_PATH=$SDE/install/lib:$SDE/install/lib64 \
    $SDE/install/bin/bf_switchd --install-dir $SDE/install --background \
    --conf-file $ROOT/programs/$prog.switchd.conf --init-mode=cold --status-port 7777 \
    > "$dir/switchd.log" 2>&1 &
  pid=$!
  echo "{\"pid\": $pid, \"started\": \"$(date -Is)\"}" > "$dir/switchd_started.json"
  while kill -0 $pid 2>/dev/null && [ ! -e "$dir/switch_done.json" ] && [ ! -e "$dir/abort.json" ]; do sleep 2; done
  sleep 3
  kill -INT $pid 2>/dev/null; sleep 5; kill -9 $pid 2>/dev/null; wait $pid 2>/dev/null
  echo "=== $run stopped $(date -Is)"
  [ -e "$dir/abort.json" ] && { echo "abort requested"; exit 2; }
  sleep 5
done < $ROOT/config/sequence.txt
echo "Chain finished. Restore your normal program with your usual run_switchd.sh."
