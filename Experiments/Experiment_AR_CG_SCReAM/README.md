# Experiment_AR_CG_SCReAM

## Goal and topology

Run E1.3--E1.5: four TCP Cubic Not-ECT flows share the 1-Gb/s bottleneck with either four Prague flows plus replayed AR/CG traffic, native ECT(1) SCReAM, or Not-ECT SCReAM. The base RTT is 10 ms and each cell has five 60-s repetitions with coupled AQM and step-only marking.

| Role | Data IP | Switch port |
|---|---|---:|
| Prague, SCReAM, and replay sender | 172.16.0.4 | 136 |
| Cubic sender | 172.16.0.6 | 138 |
| Receiver | 172.16.0.5 | 137 |

Requirements: running ICEFE, `iperf3`, `tcpreplay`, a Prague-capable kernel, Ericsson SCReAM V2 `scream_bw_test_tx/rx`, root access, and passwordless SSH. The merged AR/CG PCAP is excluded. Set `ICEFE_*_SSH`, `ICEFE_*_E1_DIR`, `ICEFE_ARCG_PCAP`, `SCREAM_TX`, and `SCREAM_RX` before generating the run plan.

## Run

Start `scripts/e1_host_job.py` on the two sender hosts as described in `Experiment_TCP_Coexistence`. Then run on the Tofino host:

```bash
python3 scripts/e1_plan.py --e1x
python3 scripts/e1_drive.py
python3 scripts/e1_analyze.py
python3 scripts/e1x_extra.py
```

The published seeded order and held-out flow map are in `config/`; compact output tables are in `results/`.
