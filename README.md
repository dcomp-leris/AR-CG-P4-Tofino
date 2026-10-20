# ICEFE

## Goal

ICEFE classifies AR and cloud-gaming traffic in an Intel Tofino 2 switch, stores the decision, and applies operator-controlled queue and ECN treatment. This repository contains the switch program, controller, trained model, telemetry tools, simulations, and experiment scripts.

## Requirements

- Intel Tofino 2 switch
- Intel/Barefoot SDE 9.13.4 with `bf-p4c`, `bf_switchd`, `bfshell`, and Python BFRT
- Linux hosts connected to the ports defined in `ICEFE.py`

The supplied laboratory mapping is ports 136, 137, and 138 at 10 Gb/s. Port 152 is enabled only by experiments that use the P4 traffic generator. Change `SERVER_INVENTORY` and `SERVER_PORT_MAP` in `ICEFE.py` for another topology.

## Run ICEFE

Run these commands on the Tofino host from the repository root:

```bash
export SDE=/path/to/bf-sde-9.13.4
bash compile.sh
sudo env SDE="$SDE" bash start_switch.sh
```

The default build uses **ECN-Preserving Admission**. To build the optional
**Operator-Controlled ECT(1) Admission** profile instead, use:

```bash
ICEFE_ADMISSION_MODE=operator-ect1 bash compile.sh
```

Both profiles preserve incoming ECT(0), ECT(1), and CE. The optional profile
changes only operator-authorized Not-ECT AR/CG packets to ECT(1). Authorized
AR/CG traffic uses Q1 in either profile. Other and Not-Classified traffic keep
their incoming ECN and DSCP and follow the default ECN-based queue selection.

Keep the switch process open. In a second terminal:

```bash
export SDE=/path/to/bf-sde-9.13.4
bash load_controller.sh
```

For an interactive controller session:

```text
$SDE/install/bin/bfshell
bfrt_python
%run -i /absolute/path/to/ICEFE.py
%run -i /absolute/path/to/icefe_tools.py
run_coupling_aqm(duration_s=60)
```

`Model.json` contains the five tree thresholds and `majority.txt` contains their vote map. `coupling_aqm.py` implements the host-side coupled-AQM update loop. The controller assigns DWRR weights 1 and 16 to Q0 and Q1, respectively. Compilation creates `ICEFE/`, `ICEFE.compile.log`, and `ICEFE.switchd.conf`; these generated files are not stored in Git.

## Repository layout

- `INT/`: probe sender and receiver for switch queue telemetry.
- `NS3_Simulation/`: the five controlled ns-3 scenarios and plotting scripts.
- `Forward_only/`: the forwarding-only P4 baseline.
- `Experiments/`: runnable experiment scripts, compact configurations, and summary tables.

Each subfolder has its own short run guide. PCAPs and raw run logs are intentionally excluded.
