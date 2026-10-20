# Experiment_Model_Training

## Goal and inputs

Build the 70/30 capture split, collect ICEFE's switch-computed features, and fit the five fixed-topology range trees. PCAPs are excluded. `data/` contains the published split maps and measured training/test samples; `model/` contains the selected weights, vote map, and report.

Requirements: running ICEFE, Python 3, NumPy, Wireshark tools, `tcpreplay`, and the source captures listed in `scripts/build_dataset.sh`.

## Refit the model from the included samples

```bash
python3 scripts/fit_trees.py data/samples_train.csv data/samples_test.csv model_rebuilt --seed 3 --candidates 16 --passes 4
```

## Rebuild features from PCAPs

On the dataset host, edit the capture paths in `scripts/build_dataset.sh`, then run it with `segment_pcap.py` in the same working directory. Copy the generated train/test PCAPs to the replay host.

For each direction, prepare ICEFE, replay the corresponding set, and collect its registers on the Tofino host:

```bash
bash scripts/train_step.sh prep DL train_DL
# replay the DL training PCAPs on the sender
bash scripts/train_step.sh collect DL train_DL
python3 scripts/make_samples.py data/map_train_DL.csv raw/training/features_train_DL.json samples_train_DL.csv --budget DL
```

Repeat with `UL`. `train_switch.py` reads the public repository's root ICEFE program.
