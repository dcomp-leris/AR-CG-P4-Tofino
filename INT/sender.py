#!/usr/bin/env python3
"""INT probe sender (run on superpeach, 172.16.0.4, interface enp2s0np1, needs sudo).

    sudo python3 sender.py            (runs until Ctrl-C)

Every 0.1 s it sends one INT probe alternately with ToS 0 and ToS 1 (so probes are
measured on both queues). A probe is Ethernet / IPv4 (protocol 253) / nodeCount(id, count=0).
The Tofino (ICEFE.p4) sends it once around its internal loop (recirculation, first INT record,
swid = 1: statistics of port 137) and then back to superpeach (second INT record, swid = 2:
statistics of port 136). receiver.py, also on superpeach, captures the returned probes.

Output: data/sender_queue0.csv and data/sender_queue1.csv  (columns ID, Timestamp [ns]).
"""

import csv                                   # CSV log of every sent probe
from pathlib import Path                     # output folder next to this file

from time import sleep, time, perf_counter_ns    # pacing and send timestamps
from scapy.all import Packet, bind_layers, BitField, ShortField, IntField, XByteField, PacketListField, FieldLenField, Raw, Ether, IP, UDP, sendp, get_if_hwaddr, sniff


class InBandNetworkTelemetry(Packet):
    # One INT record (37 bytes). The field widths MUST match header InBandNetworkTelemetry_h
    # in ICEFE.p4 and the same class in receiver.py.
    fields_desc = [ BitField("swid", 0, 6),                        # 1 = first pass (port 137 stats), 2 = return pass (port 136 stats)
                    BitField("ingress_port",0, 9),                 # ingress port of the packet at the switch
                    BitField("egress_port",0, 9),                  # (not filled by ICEFE.p4)
                    BitField("egress_spec", 0, 9),                 # (not filled by ICEFE.p4)
                    BitField("qid", 0, 7),                         # queue used: 0 Classic, 1 L4S
                    BitField("ingress_global_timestamp", 0, 32),   # (not filled by ICEFE.p4)
                    BitField("egress_global_timestamp", 0, 32),    # switch egress time, ns (32 low bits)
                    BitField("enq_timestamp",0, 32),               # (not filled by ICEFE.p4)
                    BitField("enq_qdepth",0, 32),                  # queue depth metadata (if filled)
                    BitField("deq_timedelta", 0, 32),              # (not filled by ICEFE.p4)
                    BitField("deq_qdepth", 0, 32),                 # (not filled by ICEFE.p4)
                    BitField("processing_time", 0, 32),            # SUM of queue delays (ns) since the last probe
                    BitField("number_of_packets_for_average", 0, 32)   # number of packets in that sum
                  ]
    def extract_padding(self, p):
                return "", p                                       # nothing after a record belongs to it

class nodeCount(Packet):
  # Header right after IPv4: probe id, number of INT records, then the records themselves.
  name = "nodeCount"
  fields_desc = [ ShortField("id", 0),                             # probe sequence number (wraps at 65536)
                  ShortField("count", 0),                          # number of INT records present
                  PacketListField("INT", [], InBandNetworkTelemetry, count_from=lambda pkt:(pkt.count*1))]

def main():

    dstIP0 = '172.16.0.4'            # destination of ToS-0 probes (superpeach itself: probes come back)
    dstIP1 = '172.16.0.4'            # destination of ToS-1 probes
    #dstIP2 = '10.10.10.3'
    dstMAC = "00:15:4d:13:5c:a6"     # superpeach NIC MAC (frames are delivered back to it)
    iface = 'enp2s0np1' #'wlp6s0'    # superpeach fiber interface (Tofino port 136)

    bind_layers(IP, nodeCount, proto = 253)    # IP protocol 253 -> nodeCount header

    id = 0                                     # probe counter
    path = Path(__file__).resolve().parent / 'data'
    path.mkdir(parents=True, exist_ok=True)
    with open(path / 'sender_queue0.csv', 'w', newline='') as file0, \
         open(path / 'sender_queue1.csv', 'w', newline='') as file1:
         #open(f'{path}/sender_queue2.csv', 'w', newline='') as file2:

        writer0 = csv.writer(file0)            # log of ToS-0 probes
        writer1 = csv.writer(file1)            # log of ToS-1 probes
        #writer2 = csv.writer(file2)

        writer0.writerow(['ID', 'Timestamp'])
        writer1.writerow(['ID', 'Timestamp'])
        #writer2.writerow(['ID', 'Timestamp'])

        while True:
            # Probe with ToS 0, no INT records yet (count = 0).
            pkt0 = Ether(src=get_if_hwaddr(iface), dst=dstMAC) / IP(
            src='172.16.0.4', dst=dstIP0, proto=253, tos=0) / nodeCount(id=id, count=0, INT=[])
            timestamp = perf_counter_ns()      # host send time (ns, monotonic clock)
            sendp(pkt0, iface=iface)           # send at layer 2
            writer0.writerow([id, timestamp])
            pkt0.show2()                       # print the packet (debug output)
            #sleep(0.33)
            sleep(0.1)                         # 100 ms between probes

            # Same probe with ToS 1.
            pkt1 = Ether(src=get_if_hwaddr(iface), dst=dstMAC) / IP(
            src='172.16.0.4', dst=dstIP1, proto=253, tos=1) / nodeCount(id=id, count=0, INT=[])
            timestamp = perf_counter_ns()
            sendp(pkt1, iface=iface)
            writer1.writerow([id, timestamp])
            pkt1.show2()
            sleep(0.1)
            #sleep(1)
            # pkt2 = Ether(src=get_if_hwaddr(iface), dst=dstMAC) / IP(
            # dst=dstIP2, proto=253) / nodeCount(id=id, count=0, INT=[])
            # timestamp = perf_counter_ns()
            # sendp(pkt2, iface=iface)
            # writer2.writerow([id, timestamp])
            # pkt2.show2()
            # sleep(0.33)

            id = (id + 1) % 65536              # 16-bit id field


if __name__ == '__main__':
    main()
