# Forward-only baseline

## Goal

This program forwards the same laboratory traffic without ICEFE classification. `t2na_SF.p4` is the data plane and `t2na_SF.py` enables ports 136, 137, and 138 at 10 Gb/s and port 152 at 100 Gb/s.

## Requirements and run

Use a Tofino 2 switch with SDE 9.13.4. Run on the Tofino host:

```bash
export SDE=/path/to/bf-sde-9.13.4
$SDE/install/bin/bf-p4c --target tofino2 --arch t2na -g -o t2na_SF t2na_SF.p4
```

Start `bf_switchd` with a platform configuration that points to `t2na_SF/bfrt.json`, `t2na_SF/pipe/context.json`, and `t2na_SF/pipe/tofino2.bin`. Then load the port controller:

```text
$SDE/install/bin/bfshell
bfrt_python
%run -i /absolute/path/to/t2na_SF.py
```

Change the port list in `t2na_SF.py` and the forwarding map in `t2na_SF.p4` for another cabling layout.
