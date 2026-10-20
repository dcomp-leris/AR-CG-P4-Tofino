#!/usr/bin/env python3
"""Per-flow reference features from a replay PCAP (first N packets per dst port):
mean IP total length (PS), median and mean inter-packet gap (us). Standard library only.
python3 pcap_flow_truth.py OUT.csv N in1.pcap [in2.pcap ...]"""
import csv, statistics, struct, sys

out, n_first, paths = sys.argv[1], int(sys.argv[2]), sys.argv[3:]
flows = {}
for path in paths:
    with open(path, 'rb') as f:
        f.read(24)
        while True:
            rec = f.read(16)
            if len(rec) < 16:
                break
            sec, usec, incl, orig = struct.unpack('<IIII', rec)
            data = f.read(incl)
            if len(data) < 38 or data[12:14] != b'\x08\x00':
                continue
            ihl = (data[14] & 15) * 4
            proto = data[23]
            dport = struct.unpack('!H', data[14 + ihl + 2:14 + ihl + 4])[0]
            key = (path.split('/')[-1], dport, proto)
            fl = flows.setdefault(key, {'t': [], 'len': []})
            if len(fl['t']) < n_first:
                fl['t'].append(sec + usec / 1e6)
                fl['len'].append(struct.unpack('!H', data[16:18])[0])
with open(out, 'w', newline='') as fh:
    w = csv.writer(fh)
    w.writerow(['pcap', 'port', 'proto', 'n', 'ps_mean', 'ipg_median_us', 'ipg_mean_us'])
    for (p, port, proto), fl in sorted(flows.items()):
        gaps = [(b - a) * 1e6 for a, b in zip(fl['t'], fl['t'][1:])]
        w.writerow([p, port, proto, len(fl['t']), round(statistics.mean(fl['len']), 1),
                    round(statistics.median(gaps), 1) if gaps else '', round(statistics.mean(gaps), 1) if gaps else ''])
print(len(flows), 'flows')
