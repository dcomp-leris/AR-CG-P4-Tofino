#!/bin/bash
# Configure the running switch with ICEFE.py (terminal 2, as a normal user, after start_switch.sh).
#   bash load_controller.sh
# It runs ICEFE.py and icefe_tools.py in a non-interactive bfshell (~2-4 min: 4 x 8192 LPF entries).
# For interactive work use instead:  bfshell  ->  bfrt_python  ->  %run -i <this folder>/ICEFE.py
SDE=${SDE:-/opt/bf-sde-9.13.4}
HERE="$(cd "$(dirname "$0")" && pwd)"
mkdir -p /tmp/icefe
printf "ICEFE_DIR = %s\nexec(open(ICEFE_DIR + '/load_icefe.py').read())\n" "'$HERE'" > /tmp/icefe/load.py
cd /tmp/icefe && script -qfc "$SDE/install/bin/bfshell -b /tmp/icefe/load.py" /dev/null
