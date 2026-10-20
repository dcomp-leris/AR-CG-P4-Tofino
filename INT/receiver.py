#!/usr/bin/env python3
"""INT probe receiver (run on superpeach, interface enp2s0np1, needs sudo).

    sudo python3 receiver.py <experiment_id> <duration_s>
    e.g.  sudo python3 receiver.py 1 120         -> results in ./data/
          sudo python3 receiver.py run_A 120     -> results in ./run_A/

It captures the probes sent by sender.py after their trip through the Tofino and, for every
valid probe, stores the queue delay sums of port 137 (record swid 1) and port 136 (record
swid 2) in one table per queue id. At the end it prints capture statistics and writes
receiver_queue0.csv / receiver_queue1.csv.
Average queue delay over the interval = queue_delay_port_X / number_of_packets_for_average_port_X.
"""

from scapy.all import Packet, bind_layers, BitField, ShortField, IntField, Ether, IP, UDP, sendp, get_if_hwaddr, sniff, PacketListField
import pandas as pd                          # tables of received records
import sys                                   # command-line arguments
from pathlib import Path                     # output folder
from time import time, perf_counter_ns       # receive timestamps


class InBandNetworkTelemetry(Packet):
    # Older (P4 v1model) layout, kept for reference:
    # fields_desc = [
    #     BitField("switchID_t", 0, 31),
    #     BitField("ingress_port", 0, 9),
    #     BitField("egress_port", 0, 9),
    #     BitField("egress_spec", 0, 9),
    #     BitField("priority", 0, 3),
    #     BitField("qid", 0, 5),
    #     BitField("ingress_global_timestamp", 0, 48),
    #     BitField("egress_global_timestamp", 0, 48),
    #     BitField("enq_timestamp", 0, 32),
    #     BitField("enq_qdepth", 0, 19),
    #     BitField("deq_timedelta", 0, 32),
    #     BitField("deq_qdepth", 0, 19),
    #     BitField("processing_time", 0, 32)
    # ]
    # Current 37-byte layout: identical to sender.py and to InBandNetworkTelemetry_h in ICEFE.p4.
    fields_desc = [ BitField("swid", 0, 6),                    # 1 = port 137 statistics, 2 = port 136
                    BitField("ingress_port", 0, 9),
                    BitField("egress_port",0,9),
                    BitField("egress_spec",0,9),
                    BitField("qid",0,7),                       # queue of the probe: 0 Classic, 1 L4S
                    BitField("ingress_global_timestamp",0,32),
                    BitField("egress_global_timestamp",0,32),
                    BitField("enq_timestamp",0,32),
                    BitField("enq_qdepth",0,32),
                    BitField("deq_timedelta",0,32),
                    BitField("deq_qdepth",0,32),
                    BitField("processing_time",0,32),          # sum of queue delays (ns) since previous probe
                    BitField("number_of_packets_for_average",0,32)   # packets in that sum
                  ]
    """any thing after this packet is extracted is padding"""

    def extract_padding(self, p):
        return "", p


class NodeCount(Packet):
    # Probe id, number of INT records, records.
    name = "nodeCount"
    fields_desc = [ShortField("id", 0),
                   ShortField("count", 0),
                   PacketListField("INT", [], InBandNetworkTelemetry, count_from=lambda pkt: (pkt.count * 1))]


class INTTOFINO:
    # Values extracted from one probe (one row of the output tables).
    def __init__(self):
        self.id = 0
        # self.downlink_enq_qdepth = 0
        # self.downlink_deq_qdepth = 0
        # self.downlink_deq_timedelta = 0
        # self.downlink_processing_time = 0
        # self.uplink_enq_qdepth = 0
        # self.uplink_deq_qdepth = 0
        # self.uplink_deq_timedelta = 0
        # self.uplink_processing_time = 0
        self.queue_delay_port_137 = 0
        self.number_of_packets_for_average_port_137 = 0
        self.queue_delay_port_136 = 0
        self.number_of_packets_for_average_port_136 = 0


def telemetry_layer(int_pkt):
    """Return the INT record object (scapy may wrap it), or None."""
    if isinstance(int_pkt, InBandNetworkTelemetry):
        return int_pkt
    if InBandNetworkTelemetry in int_pkt:
        return int_pkt[InBandNetworkTelemetry]
    return None


def handle_pkt(pkt, queues, stats):
    """Called by sniff() for every captured frame: count it, keep only complete INT probes."""
    stats["total"] += 1
    if IP not in pkt:                       # not IPv4
        return

    stats["ip"] += 1
    if pkt[IP].proto != 253:                # not an INT probe
        return

    stats["proto253"] += 1
    if NodeCount not in pkt:
        stats["missing_nodecount"] += 1
        return

    node_count = pkt[NodeCount]
    stats["nodecount"] += 1
    if node_count.count == 0:               # our own outgoing probe (seen before the switch)
        stats["count0"] += 1
        return

    int_layers = []                         # parsed INT records of this probe
    for int_pkt in node_count.INT:
        telemetry = telemetry_layer(int_pkt)
        if telemetry is not None:
            int_layers.append(telemetry)

    if len(int_layers) < node_count.count:  # truncated probe: skip
        stats["malformed_int"] += 1
        print(f"Skipping malformed INT packet: id={node_count.id}, count={node_count.count}, parsed={len(int_layers)}")
        return

    stats["valid"] += 1
    dataINT = INTTOFINO()
    int_id = node_count.id
    timestamp = perf_counter_ns()           # receive time (ns, monotonic clock of superpeach)
    qid = int_layers[-1].qid                # queue of the probe (oldest record is last after push_front)
    while qid >= len(queues):               # create a table for an unexpected queue id
        queues.append(pd.DataFrame(columns=INT_COLUMNS))

    for telemetry in int_layers:
        if telemetry.swid == 1: # PORT 137 (first pass through the switch)
            dataINT.queue_delay_port_137 = telemetry.processing_time
            dataINT.number_of_packets_for_average_port_137 = telemetry.number_of_packets_for_average
        else: # PORT 136 (return pass to superpeach)
            dataINT.queue_delay_port_136 = telemetry.processing_time
            dataINT.number_of_packets_for_average_port_136 = telemetry.number_of_packets_for_average

    print("QID: ", qid)
    print("INT ID: ", int_id)
    print("Timestamp: ", timestamp)
    print("queue_delay_port_137: ", dataINT.queue_delay_port_137)
    print("number_of_packets_for_average_port_137: ", dataINT.number_of_packets_for_average_port_137)
    print("queue_delay_port_136: ", dataINT.queue_delay_port_136)
    print("number_of_packets_for_average_port_136: ", dataINT.number_of_packets_for_average_port_136)
    print()

    # One row for this probe, appended to the table of its queue.
    int_df = pd.DataFrame([{'id': int_id,
                    'timestamp': timestamp,
                    'queue_delay_port_137': dataINT.queue_delay_port_137,
                    'number_of_packets_for_average_port_137': dataINT.number_of_packets_for_average_port_137,
                    'queue_delay_port_136': dataINT.queue_delay_port_136,
                    'number_of_packets_for_average_port_136': dataINT.number_of_packets_for_average_port_136,
                 }])

    queues[qid] = pd.concat([queues[qid], int_df], ignore_index=True)




# Columns of receiver_queue<qid>.csv
INT_COLUMNS = [ 'id',
                'timestamp',
                'queue_delay_port_137',
                'number_of_packets_for_average_port_137',
                'queue_delay_port_136',
                'number_of_packets_for_average_port_136',
              ]


def output_path(experiment):
    """Output folder: a path is used as given; a number -> ./data; a name -> ./<name>."""
    path = Path(experiment)
    if path.is_absolute() or len(path.parts) > 1:
        return path
    if experiment.isdigit():
        return Path(__file__).resolve().parent / 'data'
    return Path(__file__).resolve().parent / path


def main():
    if len(sys.argv) == 3:
        queues = []                          # one pandas table per queue id
        numq = 2 # number of queues, change when add more queues
        while numq > 0:
            queues.append(pd.DataFrame(columns=INT_COLUMNS))
            numq = numq - 1

        iface = 'enp2s0np1' #'wlp6s0'        # superpeach fiber interface
        bind_layers(IP, NodeCount, proto=253)    # decode protocol 253 as nodeCount + INT
        bind_layers(Ether, IP)
        timeEx = int(sys.argv[2])            # capture duration in seconds

        stats = {"total": 0, "ip": 0, "proto253": 0, "nodecount": 0, "count0": 0, "missing_nodecount": 0, "malformed_int": 0, "valid": 0}

        print(f"Waiting packets on {iface}...")
        sniff(iface=iface, prn=lambda x: handle_pkt(x, queues, stats), timeout=timeEx)

        # What was seen during the capture (useful to debug a missing return path).
        print("Capture summary:")
        print(f"  total packets seen: {stats['total']}")
        print(f"  IP packets seen: {stats['ip']}")
        print(f"  IP proto 253 packets seen: {stats['proto253']}")
        print(f"  parsed NodeCount packets seen: {stats['nodecount']}")
        print(f"  NodeCount packets with count=0: {stats['count0']}")
        print(f"  proto 253 packets missing NodeCount: {stats['missing_nodecount']}")
        print(f"  malformed/short INT packets skipped: {stats['malformed_int']}")
        print(f"  valid INT packets saved: {stats['valid']}")

        print("Saving collect INT data...")
        experiment = sys.argv[1]
        path = output_path(experiment)
        path.mkdir(parents=True, exist_ok=True)
        nq_saved = 0
        for qid, queue in enumerate(queues):     # one CSV per non-empty queue table
            if len(queue.index) > 0:
                filename = f'receiver_queue{qid}.csv'
                queue.to_csv(path / filename)
                nq_saved = nq_saved + 1
        print(f"Successfully saved {nq_saved} queues in {path}")
    else:
        print("2 arguments are expected: ID and duration (in seconds) of the experiment...")


if __name__ == '__main__':
    main()
