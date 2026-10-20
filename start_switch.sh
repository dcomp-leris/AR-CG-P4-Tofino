#!/bin/bash
# Start bf_switchd with the compiled ICEFE program (terminal 1, needs sudo). Leave it running.
#   sudo bash start_switch.sh
# The bfshell prompt appears when the driver is up; then use load_controller.sh in terminal 2.
SDE=${SDE:-/opt/bf-sde-9.13.4}
HERE="$(cd "$(dirname "$0")" && pwd)"
[ -f "$HERE/ICEFE.switchd.conf" ] || bash "$HERE/make_switchd_conf.sh"   # create the conf once
export SDE SDE_INSTALL="$SDE/install"
cd "$SDE" || exit 1
./run_switchd.sh --arch tf2 -c "$HERE/ICEFE.switchd.conf"
