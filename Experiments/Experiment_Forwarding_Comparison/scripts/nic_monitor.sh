#!/bin/bash
# Logs luigi nfp1 RX counters every 5 s (epoch, dev_rx_pkts, dev_rx_discards, rx_errors).
LUIGI_SSH=${ICEFE_LUIGI_SSH:-user@luigi-host}
LUIGI_IFACE=${ICEFE_LUIGI_IFACE:-nfp1}
ssh -o BatchMode=yes "$LUIGI_SSH" "while true; do printf '%s ' \$(date +%s.%N); ethtool -S '$LUIGI_IFACE' | awk -F': ' '/ dev_rx_pkts:| dev_rx_discards:| dev_rx_errors:/{printf \"%s=%s \", \$1, \$2}'; echo; sleep 5; done"
