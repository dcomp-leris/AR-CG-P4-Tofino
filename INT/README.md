# INT queue probes

## Goal

`sender.py` sends protocol-253 probes. `receiver.py` reads the two INT records returned by ICEFE and writes queue-delay sums and packet counts to CSV files.

## Requirements

- ICEFE running on the Tofino
- A Linux probe host connected to switch port 136
- Python 3, Scapy, pandas, and root access

Set the host interface, addresses, and MAC addresses at the top of both scripts.

The P4 program must parse `nodeCount`, recirculate the probe, and emit the 37-byte `InBandNetworkTelemetry_h` record. It must also provide the per-queue `switchLatency` and `totalPkts` registers used for `processing_time` and `number_of_packets_for_average`. The header layout must match the Scapy definitions in both scripts.

## Run

On the probe host, use two terminals:

```bash
sudo python3 receiver.py 1 120
sudo python3 sender.py
```

The first command captures for 120 seconds. Queue 0 and Queue 1 are written separately. Average queue delay is the reported delay sum divided by its packet count.
