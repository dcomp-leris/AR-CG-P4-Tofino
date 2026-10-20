# Controlled ns-3 simulation

## Goal and topology

Three clients connect through 100-Mb/s, 1-ms access links to one router. The router and server share a 10-Mb/s, 10-ms bottleneck using `FqPieQueueDisc` with L4S enabled, a 1-ms CE threshold, and a 15-ms queue-delay reference.

Traffic is C1: 6-Mb/s Classic UDP background, C2: 10-Mb/s TCP traffic, and C3: video-like UDP. The five C3 settings are:

| Scenario | ECN | Rate | Sender |
|---|---:|---:|---|
| S1 | Not-ECT | 6 Mb/s | non-responsive |
| S2 | ECT(1) | 6 Mb/s | non-responsive |
| S3 | ECT(1) | 6 Mb/s | custom responsive UDP |
| S4 | ECT(1) | 12 Mb/s | non-responsive |
| S5 | ECT(1) | 3.5 Mb/s | paced/capped |

S3 uses the `ResponsiveUdpClient` defined in the source; it is not SCReAM. The source labels C2 as Prague but does not set a TCP congestion-control TypeId, so select Prague in the ns-3 TCP configuration if it is not your build's default.

## Run

Requirements: ns-3.40 with the traffic-control, applications, and flow-monitor modules. Plotting requires Python 3, Matplotlib, NumPy, and pandas.

```bash
cp l4s-multi-scenario-experiment.cc /path/to/ns-3.40/scratch/
cd /path/to/ns-3.40
for s in 1 2 3 4 5; do
  ./ns3 run "scratch/l4s-multi-scenario-experiment --scenario=$s"
done
```

The program prints transmitted/received packets, loss, throughput, mean delay, CE marks, and drops.

The plotting scripts contain the reported numerical values and generate:

- `figure_A1a_queueing_delay.png`: mean delay of C2 and C3.
- `figure_A1b_throughput.png`: throughput of C2 and C3.
- `figure_A1c_packet_loss.png`: C3 packet loss.
- `figure_A1d_tradeoff_matrix.png`: C3 loss versus C2 delay.

```bash
python3 plot_queue_delay.py
python3 plot_throughput.py
python3 plot_packet_loss.py
python3 plot_tradeoff.py
```
