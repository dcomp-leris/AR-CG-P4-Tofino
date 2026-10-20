#!/bin/bash
# Writes ICEFE.switchd.conf for the compiled program in ./ICEFE (absolute paths are required
# by bf_switchd, so the file is generated for wherever this folder is located).
#   bash make_switchd_conf.sh
HERE="$(cd "$(dirname "$0")" && pwd)"           # absolute path of this folder
OUT="$HERE/ICEFE"                               # bf-p4c output folder (see compile.sh)
cat > "$HERE/ICEFE.switchd.conf" <<CONF
{
  "chip_list": [
    {
      "chip_family": "tofino2",
      "instance": 0,
      "pcie_sysfs_prefix": "/sys/devices/pci0000:00/0000:00:03.0/0000:05:00.0",
      "sds_fw_path": "share/tofino_sds_fw/avago/firmware"
    }
  ],
  "p4_devices": [
    {
      "device-id": 0,
      "p4_programs": [
        {
          "program-name": "ICEFE",
          "bfrt-config": "$OUT/bfrt.json",
          "p4_pipelines": [
            {
              "p4_pipeline_name": "pipe",
              "context": "$OUT/pipe/context.json",
              "config": "$OUT/pipe/tofino2.bin",
              "pipe_scope": [0, 1, 2, 3],
              "path": "$OUT"
            }
          ]
        }
      ],
      "agent0": "lib/libpltfm_mgr.so"
    }
  ],
  "switch_options": [ { "device-id": 0 } ]
}
CONF
echo "written $HERE/ICEFE.switchd.conf"
