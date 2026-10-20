#!/bin/bash
# Build the c7 training (first 70 %) and test (last 30 %) replay sets on superluigi.
set -e
cd ~/c7
rm -rf dataset && mkdir -p dataset/train dataset/test dataset/src
editcap -F pcap ~/cg_traffic/VoD.pcapng dataset/src/VoD.pcap
# name  class  path  options
cat > dataset/manifest.txt <<M
ar AR $HOME/cg_traffic/ar.pcap --keep-major 0.005
DLF CG $HOME/cg_traffic/DLF.pcap --keep-major 0.005
DL_K CG $HOME/cg_traffic/DL_K.pcap --keep-major 0.005
UL_F CG $HOME/cg_traffic/UL_F.pcap --keep-major 0.005
UL_k CG $HOME/cg_traffic/UL_k.pcap --keep-major 0.005
aim_chat Other $HOME/pcap_pool/other/aim_chat_3a.pcap --max-flows 600
email Other $HOME/pcap_pool/other/email1a.pcap --ipv6 --max-flows 600
rdp_navigation Other $HOME/pcap_pool/other/rdp_navigation.pcap --max-flows 600
rdp_youtube Other $HOME/pcap_pool/other/rdp_youtube.pcap --max-flows 600
skype Other $HOME/cg_traffic/Skype.pcap --max-flows 600
streaming Other $HOME/cg_traffic/streaming.pcap --ipv6 --max-flows 600
telegram Other $HOME/cg_traffic/Telegram.pcap --max-flows 600
vod Other $HOME/c7/dataset/src/VoD.pcap --ipv6 --max-flows 600
M
while read name cls path opts; do
  python3 segment_pcap.py "$path" dataset/train/$name.pcap dataset/train/map.csv --cls $cls --capture $name \
      --window 0 0.7 --segment-s 5 --used dataset/train/used.json $opts
  python3 segment_pcap.py "$path" dataset/test/$name.pcap dataset/test/map.csv --cls $cls --capture $name \
      --window 0.7 1.0 --segment-s 5 --used dataset/test/used.json $opts
done < dataset/manifest.txt
du -sh dataset/train dataset/test
echo DATASET_DONE
