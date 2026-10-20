#!/bin/bash
# Run on peach as leris. Extracts one copy of every original session and rewrites
# addresses to peach (172.16.0.4, enp2s0np1) -> luigi (172.16.0.5, nfp1).
# Packet timestamps are not modified.
set -euo pipefail
OUT=~/r2c1/sessions
mkdir -p "$OUT"
cd ~/pcaps
PEACH_MAC=00:15:4d:13:5c:a6   # enp2s0np1 on superpeach
LUIGI_MAC=00:15:4d:13:5c:b8   # nfp1 on superluigi
# name  source-pcap  original-dst-ip  dst-port
while read -r name src ip port; do
  [ -z "$name" ] && continue
  tmp="$OUT/$name.orig.pcap"
  tshark -r "$src" -Y "ip.dst==$ip && udp.dstport==$port" -w "$tmp" -F pcap
  tcprewrite --infile="$tmp" --outfile="$OUT/$name.pcap" \
    --srcipmap=0.0.0.0/0:172.16.0.4/32 --dstipmap=0.0.0.0/0:172.16.0.5/32 \
    --enet-smac=$PEACH_MAC --enet-dmac=$LUIGI_MAC --fixcsum
  rm -f "$tmp"
  tshark -r "$OUT/$name.pcap" -T fields -E separator=, -e frame.time_epoch -e frame.len \
    -e ip.src -e ip.dst -e udp.srcport -e udp.dstport > "$OUT/$name.timeline.csv"
  echo "$name done"
done <<'LIST'
AR_5000   dl/myar_p00.pcap    20.20.20.1     5000
AR_5001   dl/myar_p00.pcap    20.20.20.2     5001
AR_5002   dl/myar_p00.pcap    20.20.20.3     5002
AR_5003   dl/myar_p00.pcap    20.20.20.4     5003
CGDL_4000 dl/mycgdl_p00.pcap  100.100.100.1  4000
CGDL_4001 dl/mycgdl_p00.pcap  100.100.100.2  4001
CGDL_4002 dl/mycgdl_p00.pcap  100.100.100.3  4002
CGDL_4003 dl/mycgdl_p00.pcap  100.100.100.4  4003
CGDL_4004 dl/mycgdl_p00.pcap  100.100.100.5  4004
CGDL_4005 dl/mycgdl_p00.pcap  150.150.150.1  4005
CGUL_3000 ul/mycgull_p00.pcap 200.200.200.1  3000
CGUL_3005 ul/mycgull_p00.pcap 200.200.200.1  3005
LIST
cd "$OUT" && sha256sum *.pcap > SHA256SUMS && echo ALL_DONE
