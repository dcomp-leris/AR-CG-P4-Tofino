#!/usr/bin/env python3
"""Original send times of UDP packets in replay PCAPs (relative to each PCAP's start):
python3 pcap_send_ref.py OUT.csv.gz a.pcap [b.pcap ...]  -> pcap,port,ip_id,ip_len,t_rel"""
import gzip, struct, sys
out = gzip.open(sys.argv[1], 'wt')
out.write('pcap,port,ip_id,ip_len,t_rel\n')
for path in sys.argv[2:]:
    name = path.rsplit('/', 1)[-1].rsplit('.', 1)[0]
    with open(path, 'rb') as f:
        f.read(24)
        while True:
            rec = f.read(16)
            if len(rec) < 16:
                break
            sec, usec, incl, orig = struct.unpack('<IIII', rec)
            d = f.read(incl)
            if len(d) < 38 or d[12:14] != b'\x08\x00' or d[23] != 17:
                continue
            ihl = (d[14] & 15) * 4
            out.write('%s,%d,%d,%d,%.6f\n' % (name, struct.unpack('!H', d[14 + ihl + 2:14 + ihl + 4])[0],
                                              struct.unpack('!H', d[18:20])[0], struct.unpack('!H', d[16:18])[0], sec + usec / 1e6))
out.close()
