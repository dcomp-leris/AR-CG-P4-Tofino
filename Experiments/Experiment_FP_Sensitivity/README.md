# Experiment_FP_Sensitivity

## Goal and topology

Repeat the congested downlink mixture after marking seeded sets of Other flows so that they represent approximately 10% or 18% of Other packets. The topology and five repetitions per level match `Experiment_Realistic_Errors`.

Requirements and runtime scripts are shared with `Experiment_Realistic_Errors`. This folder keeps only the sensitivity-specific marker, selections, and published table. The original merged downlink PCAP is excluded.

## Run

On the replay host, create the two marked inputs:

```bash
python3 mark_fp.py merged_DL.pcap merged_DL_fp10.pcap /path/to/Experiment_Realistic_Errors/data/map_test_DL.csv 0.10 7 fp10_selected.json
python3 mark_fp.py merged_DL.pcap merged_DL_fp18.pcap /path/to/Experiment_Realistic_Errors/data/map_test_DL.csv 0.18 7 fp18_selected.json
```

Copy the marked PCAPs to the replay host. The realistic-mixture folder links to this folder's two published selection JSON files. Start the same host jobs and P4TG load, then run from `Experiment_Realistic_Errors`:

```bash
python3 scripts/fp_drive.py --sens
python3 scripts/fp_analyze.py
```

The exact published selections are in `data/fp10_selected.json` and `data/fp18_selected.json`. The compact set-level table is in `results/`.
