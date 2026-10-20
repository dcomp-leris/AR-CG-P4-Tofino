# Experiment_TCP_Coexistence

## Goal and topology

Compare TCP Prague and TCP Cubic with coupled AQM and step-only marking. The bottleneck is Tofino port 137 at 1 Gb/s. The base RTT is 10 ms and each run lasts 60 s.

| Role | Data IP | Switch port |
|---|---|---:|
| Prague/ECT(0) sender | 172.16.0.4 | 136 |
| Cubic Not-ECT sender | 172.16.0.6 | 138 |
| Receiver | 172.16.0.5 | 137 |

Requirements: running ICEFE, `iperf3`, a Prague-capable Linux kernel, `tc/netem`, root access on senders, and passwordless SSH from the Tofino host. Set `ICEFE_PEACH_SSH`, `ICEFE_MARIO_SSH`, `ICEFE_LUIGI_SSH`, and the corresponding `ICEFE_*_E1_DIR` variables for your hosts.

## Run

Copy `scripts/e1_host_job.py` to both sender hosts, then run it as root using the role and a writable shared run directory:

```bash
sudo python3 e1_host_job.py peach /path/to/e1-runs
sudo python3 e1_host_job.py mario /path/to/e1-runs
```

On the Tofino host:

```bash
python3 scripts/e1_plan.py
python3 scripts/e1_drive.py
python3 scripts/e1_analyze.py
```

`config/sequence_80.json` records the published seeded order with neutral host placeholders. Raw run files are created under `raw/e1/` and are ignored by Git. The compact published tables are in `results/`.
