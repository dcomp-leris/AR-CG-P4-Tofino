#!/bin/bash
set -e
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PCIE_SYSFS_PREFIX=${PCIE_SYSFS_PREFIX:-/sys/devices/pci0000:00/0000:00:03.0/0000:05:00.0}

for PROGRAM in ICEFE_r2c1 FWD_r2c1; do
  OUT="$ROOT/programs/$PROGRAM"
  cat > "$ROOT/programs/$PROGRAM.switchd.conf" <<CONF
{
  "chip_list": [{
    "chip_family": "tofino2",
    "instance": 0,
    "pcie_sysfs_prefix": "$PCIE_SYSFS_PREFIX",
    "sds_fw_path": "share/tofino_sds_fw/avago/firmware"
  }],
  "p4_devices": [{
    "device-id": 0,
    "p4_programs": [{
      "program-name": "$PROGRAM",
      "bfrt-config": "$OUT/bfrt.json",
      "p4_pipelines": [{
        "p4_pipeline_name": "pipe",
        "context": "$OUT/pipe/context.json",
        "config": "$OUT/pipe/tofino2.bin",
        "pipe_scope": [0, 1, 2, 3],
        "path": "$OUT"
      }]
    }],
    "agent0": "lib/libpltfm_mgr.so"
  }],
  "switch_options": [{"device-id": 0}]
}
CONF
done

echo "Generated switchd configurations in $ROOT/programs"
