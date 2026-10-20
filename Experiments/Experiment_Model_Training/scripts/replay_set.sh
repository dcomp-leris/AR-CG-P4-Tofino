#!/bin/bash
# sudo bash replay_set.sh DIR "name1 name2 ..."   (superpeach)
# Replays DIR/<name>.pcap for all names concurrently at original timing, preloaded (-K).
# Refuses to start unless DIR/GO exists: it is created only after the files are
# verified and the switch prep step has run, and it is removed when the replay starts.
DIR=$1; NAMES=$2; IF=enp2s0np1
cd "$DIR" || exit 1
if [ ! -e GO ]; then
  echo "NOT READY: wait until the switch prep is done (no $DIR/GO yet). Nothing was sent."
  exit 1
fi
cat GO; rm -f GO
for n in $NAMES; do [ -s $n.pcap ] || { echo "missing $n.pcap"; exit 1; }; done
for n in $NAMES; do cat $n.pcap > /dev/null; done      # warm the page cache
echo "start $(date +%s.%N) $NAMES" | tee replay_events.log
for n in $NAMES; do
  tcpreplay -K -i $IF --stats=30 $n.pcap > replay_$n.log 2>&1 &
done
wait
echo "end $(date +%s.%N)" | tee -a replay_events.log
grep -H -E "Actual|Successful|Failed|Retried" replay_*.log
