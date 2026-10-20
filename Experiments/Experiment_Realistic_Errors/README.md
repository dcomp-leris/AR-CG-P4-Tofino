# Experiment_Realistic_Errors

## Goal and topology

Replay the held-out AR, CG, and Other mixture and apply ICEFE's actual decisions under about 9.8 Gb/s of P4TG background traffic. The replay sender is on port 136, the receiver is on port 137, and P4TG enters port 152. Five downlink and five uplink runs are used.

Requirements: running ICEFE, a second Tofino/P4TG source, `tcpreplay`, `tcpdump`, Python 3, root access on the hosts, and passwordless SSH. Build `merged_DL.pcap` and `merged_UL.pcap` from the held-out captures and place them on the replay host; PCAPs are not included. Set `ICEFE_PEACH_SSH`, `ICEFE_LUIGI_SSH`, their `ICEFE_*_FP_DIR` values, and `ICEFE_DATASET_DIR`.

## Run

Copy `scripts/fp_host_job.py` to the replay and receiver hosts and start it with the appropriate role. Start the P4TG load, then run on the Tofino host:

```bash
python3 scripts/fp_drive.py
python3 scripts/fp_analyze.py
```

`data/` contains the test split maps and packet-time reference. New raw files go to ignored `raw/fp/`; published summary tables are in `results/`.
