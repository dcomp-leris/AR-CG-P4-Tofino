# Experiment_Forwarding_Comparison

## Goal and topology

Measure ICEFE and a forwarding-only program on the same 10-Gb/s path: sender `172.16.0.4` on port 136, Tofino 2, and receiver `172.16.0.5` on port 137. The exact earlier ICEFE build used by this experiment is kept in `programs/`; it is separate from the final root program.

Requirements: SDE 9.13.4, `tcpreplay`, `tcpdump`, `tshark`, `editcap`, root access for switch restarts and host capture, and passwordless SSH. Session PCAPs are excluded; their hashes are in `config/SHA256SUMS`.

## Prepare and run

Compile both measured programs on the Tofino host:

```bash
export SDE=/path/to/bf-sde-9.13.4
$SDE/install/bin/bf-p4c --target tofino2 --arch t2na -g -o programs/ICEFE_r2c1 programs/ICEFE_r2c1.p4
$SDE/install/bin/bf-p4c --target tofino2 --arch t2na -g -o programs/FWD_r2c1 programs/FWD_r2c1.p4
bash scripts/make_switchd_configs.sh
```

If the switch uses another PCIe path, set `PCIE_SYSFS_PREFIX` before generating the configurations. Set `ICEFE_PEACH_SSH`, `ICEFE_LUIGI_SSH`, their `ICEFE_*_R2C1_DIR` values, and `ICEFE_R2C1_SESSIONS` for the host setup.

Create the local run area:

```bash
mkdir -p raw/runs
cp config/plan_DL.json config/plan_UL.json raw/
cp config/SUPERSEDED.json raw/runs/
```

Prepare the session PCAPs with `scripts/prepare_sessions.sh`, start `scripts/host_job.py` on sender and receiver, and then run these on the Tofino host in separate terminals:

```bash
sudo env SDE="$SDE" bash scripts/switch_chain.sh
python3 scripts/drive.py
```

After all runs:

```bash
python3 scripts/analyze.py
python3 scripts/window_latency.py
```

The compact published outputs are in `results/`; raw captures and logs remain under ignored `raw/`.
