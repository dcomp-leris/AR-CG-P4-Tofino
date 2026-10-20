'''
# Controller/Tofino2
# Version 2.0.0
# Authors: Mateus, Alireza
# Lab: LERIS
# Date: 2025-04-14
'''
# coupling_configuration: match the name registered by switchd.
# Change only if ICEFE.p4 was built/loaded under a different program name.
COUPLING_PROGRAM_NAME = "ICEFE_r2c1"

# coupling_aqm_defaults: RFC 9332 Appendix A reference DualPI2 parameters.
# https://www.rfc-editor.org/rfc/rfc9332.html#appendix-A
# These configure run_coupling_aqm(), not a fixed CE percentage.
# Start the loop explicitly after loading this controller.
# Convert queue-delay samples from nanoseconds to seconds before applying gains.
COUPLING_AQM_ALGORITHM = "DualPI2"
COUPLING_FACTOR = 2  # Matches the P4 right shift; changing this needs P4 changes.
COUPLING_TARGET_DELAY_MS = 15
COUPLING_UPDATE_INTERVAL_MS = 16
COUPLING_MAX_RTT_MS = 100
COUPLING_ALPHA_HZ = 0.16
COUPLING_BETA_HZ = 3.2
COUPLING_INITIAL_BASE_PROBABILITY = 0.0
COUPLING_STALE_SAMPLE_MS = 64
COUPLING_MAX_POLL_INTERVAL_MS = 32  # Abort if BFRT cannot sustain the schedule.

# coupling_feedback_import: helper beside this controller, also usable in tests.
import sys
import time
from pathlib import Path
from ipaddress import IPv4Address
coupling_helper_dir = Path(globals().get("__file__", "ICEFE_r2c1.py")).resolve().parent
if str(coupling_helper_dir) not in sys.path:
    sys.path.insert(0, str(coupling_helper_dir))
from coupling_aqm import CouplingAQM, bfrt_field

# CoDel is a different AQM, not a source of the DualPI2 base probability.
# Its drop scheduling must not be substituted for these PI gains.

# coupling_variables: decimal thresholds indexed by EGRESS PORT, not queue.
# 0 disables probabilistic marking; 3277 ~= 10%; 16384 = 50%; 32768 = 100%.
# L4S keeps TM congestion marking; Classic uses the squared probability.
# topology_inventory: addresses do not establish the physical port mapping.
FIBER_PORTS = (136, 137, 138)
SERVER_INVENTORY = {
    "Server1": {"management_ip": "0.0.0.0", "fiber_ip": "172.16.0.5"},
    "Server2": {"management_ip": "0.0.0.0", "fiber_ip": "172.16.0.3"},
    "Server3": {"management_ip": "0.0.0.0", "fiber_ip": "172.16.0.4"},
}
# topology_port_map: fill only from observed/verified cabling, never IP order.
# Verified by user-provided discover_server_ports() output on 2026-10-10.
SERVER_PORT_MAP = {"Server1": 137, "Server2": 138, "Server3": 136}
COUPLING_BASE_BY_PORT = {
    port: round(COUPLING_INITIAL_BASE_PROBABILITY * 65536) for port in FIBER_PORTS
}


# Resolve and check the coupled program before changing ports or TM settings.
coupling_program = getattr(bfrt, COUPLING_PROGRAM_NAME)
coupling_register = None  # r2c1: no hardware users in the measurement build
# coupling_classic_register: derived threshold, not independently configured.
coupling_classic_register = None  # r2c1: no hardware users in the measurement build
# coupling_sampling_register: index 2 * egress port + logical queue.
coupling_delay_register = coupling_program.pipe.Egress.coupling_queue_delay
coupling_stamp_register = coupling_program.pipe.Egress.coupling_queue_stamp

# coupling_action: reusable setter for manual experiments and the AQM loop.
# p_base = base_value / 65536; p_CL = min(1, 2 * p_base).
# This writes thresholds; run_coupling_aqm() calculates them from queue feedback.
def set_coupling_base(dev_port, base_value, verbose=True, pipe=None):
    if type(dev_port) is not int or not 0 <= dev_port < 512:
        raise ValueError("Coupling egress port must be an integer from 0 to 511")
    if type(base_value) is not int or not 0 <= base_value <= 65535:
        raise ValueError("Coupling base threshold must be an integer from 0 to 65535")
    # coupling_classic_action: p_C = p_base squared, quantized to 16 bits.
    # Integer arithmetic rounds to nearest; endpoint 65535 means certainty.
    classic_value = (base_value * base_value + 32768) // 65536
    if base_value == 65535:
        classic_value = 65535
    # Two BFRT writes are not atomic; a brief mismatch is possible on updates.
    target = {} if pipe is None else {"pipe": pipe}
    coupling_classic_register.mod(REGISTER_INDEX=dev_port, f1=classic_value, **target)
    coupling_register.mod(REGISTER_INDEX=dev_port, f1=base_value, **target)
    # Uses the current BFRT target; the default target addresses all pipes.
    bfrt.complete_operations()
    coupled_percent = 100 * min(1, 2 * base_value / 65536)
    classic_percent = 100 if classic_value == 65535 else 100 * classic_value / 65536
    if verbose:
        print("Coupling port {}: base={}, Classic CE/drop={:.5f}%, "
          "L4S coupled CE={:.3f}% when TM trigger is inactive".
          format(dev_port, base_value, classic_percent, coupled_percent))


# coupling_sampling_action: explicit pipe avoids confusing per-pipe arrays.
def read_coupling_sample(dev_port, queue):
    target = dict(REGISTER_INDEX=2 * dev_port + queue, pipe=dev_port >> 7,
                  from_hw=True, print_ents=False, return_ents=True)
    # Separate registers are approximate, not an atomic snapshot. Read the
    # delay first and then its freshness stamp. High-rate traffic continues to
    # update both; rejecting every changed stamp would starve the controller.
    delay = bfrt_field(coupling_delay_register.get(**target), "f1")
    stamp = bfrt_field(coupling_stamp_register.get(**target), "f1")
    return delay, stamp


# coupling_feedback_loop: run in bfrt_python after configuration, not a thread.
# Default 10-second trial. Pass duration_s=None to run until Ctrl-C.
def run_coupling_aqm(duration_s=10):
    if duration_s is not None and duration_s <= 0:
        raise ValueError("duration_s must be positive or None")
    if COUPLING_FACTOR != 2 or COUPLING_AQM_ALGORITHM != "DualPI2":
        raise ValueError("This P4/controller combination requires DualPI2 with k=2")
    interval = COUPLING_UPDATE_INTERVAL_MS / 1000
    max_interval = COUPLING_MAX_POLL_INTERVAL_MS / 1000
    controllers = {}
    for port in COUPLING_BASE_BY_PORT:
        entry = coupling_register.get(REGISTER_INDEX=port, pipe=port >> 7,
            from_hw=True, print_ents=False, return_ents=True)
        base = bfrt_field(entry, "f1")
        controllers[port] = CouplingAQM(
            target_ms=COUPLING_TARGET_DELAY_MS,
            interval_ms=COUPLING_UPDATE_INTERVAL_MS,
            alpha_hz=COUPLING_ALPHA_HZ, beta_hz=COUPLING_BETA_HZ,
            initial_probability=1.0 if base == 65535 else base / 65536,
            stale_ms=COUPLING_STALE_SAMPLE_MS)
    started = time.monotonic()
    deadline = started
    last_cycle = None
    last_report = started - 1
    cycles = 0
    writes = 0
    statuses = {}
    max_observed_interval = 0.0
    print("DualPI2 feedback starting; Ctrl-C stops it and preserves the last probabilities.")
    try:
        while duration_s is None or time.monotonic() - started < duration_s:
            now = time.monotonic()
            if now < deadline:
                time.sleep(deadline - now)
            cycle_started = time.monotonic()
            if duration_s is not None and cycle_started - started >= duration_s:
                break
            if last_cycle is not None:
                gap = cycle_started - last_cycle
                max_observed_interval = max(max_observed_interval, gap)
                if gap > max_interval:
                    raise RuntimeError("BFRT polling exceeded {} ms; feedback stopped".
                                       format(COUPLING_MAX_POLL_INTERVAL_MS))
            last_cycle = cycle_started
            # Read all samples before calculating or writing this cycle.
            samples = {port: (read_coupling_sample(port, 0),
                              read_coupling_sample(port, 1)) for port in controllers}
            sampled_at = time.monotonic()
            if sampled_at - cycle_started > max_interval:
                raise RuntimeError("BFRT sample reads exceeded the polling budget")
            for port, controller in controllers.items():
                threshold, status = controller.update(*samples[port], sampled_at)
                statuses[port] = status
                if threshold is not None:
                    set_coupling_base(port, threshold, verbose=False, pipe=port >> 7)
                    writes += 1
            if time.monotonic() - cycle_started > max_interval:
                raise RuntimeError("BFRT read/write cycle exceeded the polling budget")
            cycles += 1
            if sampled_at - last_report >= 1:
                print("DualPI2 cycle {}: {}".format(cycles, {
                    port: {"state": statuses[port], "p_base": round(c.probability, 6),
                           "queues": c.queue_status(sampled_at)}
                    for port, c in controllers.items()}))
                last_report = sampled_at
            # No catch-up bursts after a slow cycle.
            deadline = max(deadline + interval, time.monotonic())
    except KeyboardInterrupt:
        print("DualPI2 feedback stopped by user.")
    finally:
        print("DualPI2 stopped: cycles={}, updates={}, max interval={:.3f} ms; "
              "last register values remain active".
              format(cycles, writes, max_observed_interval * 1000))
    return {"cycles": cycles, "updates": writes,
            "max_interval_ms": max_observed_interval * 1000, "states": statuses}


# topology_discovery: read observed ingress ports for IPv4/ARP source addresses.
def discover_server_ports():
    observations = {}
    for name, server in SERVER_INVENTORY.items():
        host_slot = int(IPv4Address(server["fiber_ip"])) & 7
        entry = coupling_program.pipe.Ingress.topology_source_port.get(
            REGISTER_INDEX=host_slot, pipe=1, from_hw=True,
            print_ents=False, return_ents=True)
        observed = bfrt_field(entry, "f1")
        observations[name] = observed if observed in FIBER_PORTS else None
    print("Observed server ingress ports:", observations)
    return observations


# topology_forwarding_setup: three destination rules cover IPv4 and ARP targets.
def install_server_topology(port_map):
    if set(port_map) != set(SERVER_INVENTORY):
        raise ValueError("Provide a port for each of Server1, Server2 and Server3")
    if any(type(port) is not int for port in port_map.values()) or set(port_map.values()) != set(FIBER_PORTS):
        raise ValueError("Server mapping must use ports 136, 137, 138 exactly once")
    forwarding = coupling_program.pipe.Ingress.topology_forward
    # Only this dedicated three-entry table is replaced; classifier is untouched.
    forwarding.clear()
    for name, server in SERVER_INVENTORY.items():
        forwarding.add_with_topology_set_port(
            topology_destination=int(IPv4Address(server["fiber_ip"])),
            port=port_map[name])
    bfrt.complete_operations()
    SERVER_PORT_MAP.update(port_map)
    print("Installed IPv4/ARP server forwarding:", SERVER_PORT_MAP)


def install_discovered_topology():
    # Requires each server to emit IPv4 or ARP first. Re-read to detect movement.
    first = discover_server_ports()
    time.sleep(0.1)
    second = discover_server_ports()
    if first != second:
        raise ValueError("Observed topology changed; verify the fiber cables")
    install_server_topology(second)


# topology_tm_setup: get real physical queue mapping rather than assuming 0/16/32.
def configure_server_queues():
    for port in FIBER_PORTS:
        entry = bfrt.tf2.tm.port.cfg.get(dev_port=port, print_ents=False, return_ents=True)
        if isinstance(entry, (list, tuple)):
            if len(entry) != 1:
                raise ValueError("Expected one TM port configuration")
            entry = entry[0]
        data = {(key.decode() if isinstance(key, bytes) else key): value
                for key, value in entry.data.items()}
        queues = data["egress_qid_queues"]
        if int(data["port_queues_count"]) < 2 or len(queues) < 2 or queues[0] == queues[1]:
            raise ValueError("Port {} needs distinct Q0/Q1 queue carving".format(port))
        for logical, weight in ((0, 1), (1, 32)):
            bfrt.tf2.tm.queue.sched_cfg.mod(
                pipe=port >> 7, pg_id=data["pg_id"], pg_queue=queues[logical],
                dwrr_weight=weight)
        print("Port {}: Q0={}, Q1={}, PG={}".format(port, queues[0], queues[1], data["pg_id"]))


############################################################################################################################
# Port configuration *******************************************************************************************************
## Fiber ports (136,137,138) & existing loopback (144)
## Enable Exress/Ingress Mirroring 
## Port Rate/ Burst Size Configuration
## Server-to-port assignment comes from SERVER_PORT_MAP / observed packets.
############################################################################################################################
# topology_interface_setup: active fiber ports are enabled without changing
# the speed/FEC of an already configured interface. New ports default to 10G.
for fiber_port in FIBER_PORTS:
    current = bfrt.port.port.get(DEV_PORT=fiber_port, print_ents=False, return_ents=True)
    if current is None or current == -1 or current == []:
        bfrt.port.port.add(DEV_PORT=fiber_port, SPEED="BF_SPEED_10G",
            FEC="BF_FEC_TYP_NONE", PORT_ENABLE=True, AUTO_NEGOTIATION="PM_AN_FORCE_DISABLE")
    else:
        bfrt.port.port.mod(DEV_PORT=fiber_port, PORT_ENABLE=True)

# Existing traffic-generator ports are optional and are not enabled by this setup.

## Add loopback Port (Used for INT loop!)
# r2c1: INT loopback port 144 not configured (no INT traffic in this experiment).





## Egress Mirroring (Enable mirror session 1 in TM) (Mirroring bydefault for Tofino2 is 128/6)
bfrt.mirror.cfg.entry_with_normal(sid=1, direction='EGRESS', session_enable=True, ucast_egress_port=128, ucast_egress_port_valid=True, max_pkt_len=48).push()
'''
Extra Ingress Mirroring example: 
bfrt.mirror.cfg.entry_with_normal(sid=1, direction='INGRESS', session_enable=True, ucast_egress_port=128, ucast_egress_port_valid=True, max_pkt_len=48).push()
'''

## Existing fiber-port rate-enable configuration in Traffic Manager (TM)
# r2c1: TM settings applied identically to both programs by r2c1_common.apply_tm().

# Traffic-generator shaping configuration is not applied to inactive ports.

'''
Description (Port Configuration in TM):
# Rate and max burst size units are:
    max_burst_size = BYTES
    max_rate = KILOBITS/SEC

# BPS (Bit Per Second) + (Byte or Bits)?
    bfrt.tf2.tm.port.sched_shaping.mod(dev_port=136, unit='BPS', max_rate=100000, max_burst_size=4500)
    bfrt.tf2.tm.port.sched_shaping.mod(dev_port=137, unit='BPS', max_rate=100000, max_burst_size=4500)

# PPS (Packet Per Second) + Packets
    bfrt.tf2.tm.port.sched_shaping.mod(dev_port=136, unit='PPS', max_rate=15000, max_burst_size=100)
    bfrt.tf2.tm.port.sched_shaping.mod(dev_port=137, unit='PPS', max_rate=15000, max_burst_size=100)
'''






# topology_queue_setup: retain Q0/Q1 weights, use actual TM queue mapping.
# Existing buffering and shaping settings are retained.
# r2c1: configure_server_queues() not applied; all evaluated packets use Q0.

############################################################################################################################
# EWMA/LPF Configuration ***************************************************************************************************
### EWMA Computing Using Low Pass Filter (LPF) Configuration
#### Features are IPG, PS, IFG, FS
#### Alpha = 0.95
############################################################################################################################
for r2c1_index in range(256):  # r2c1: one LPF state per flow entry
    coupling_program.pipe.Ingress.lpf_packet_size.add(r2c1_index,'SAMPLE', 100000000, 100000000,0)
for r2c1_index in range(256):  # r2c1: one LPF state per flow entry
    coupling_program.pipe.Ingress.lpf_frame_size.add(r2c1_index,'SAMPLE', 100000000, 100000000,0)
for r2c1_index in range(256):  # r2c1: one LPF state per flow entry
    coupling_program.pipe.Ingress.lpf_ipg.add(r2c1_index,'SAMPLE', 100000000, 100000000,0)
for r2c1_index in range(256):  # r2c1: one LPF state per flow entry
    coupling_program.pipe.Ingress.lpf_ifg.add(r2c1_index,'SAMPLE', 100000000, 100000000,0)




############################################################################################################################
# Machine Learning (ML) Model Deployment ***********************************************************************************
## ML: Random Forest (RF)
############################################################################################################################
'''
Function: AR/CG Classification
Features: IPG, PS, IFG, and FS
Algorithm: Random Forest (RF)
    Classes: AR or CG or Other (Non-(AR or CG)
    Number of Trees: 5
    Features: IPG, PS, IFG, FS (EWMA Alpha = 0.95)
    Aggregation: Majoraity
'''

### constant variabls
max_value_16_bit = 65535    # (2^16 - 1)
max_value_20_bit = 1048575  # (2^20 - 1)

'''
Tree1 
------------------------------------------- 
FS Check:
    If 0 ≤ FS ≤ 42 → Class: Other
    If 43 ≤ FS ≤ 1667 → Class: CG
    If FS ≥ 1668 → Go to IPI Check

IPI Check (when FS ≥ 1668):
    If 0 ≤ IPI ≤ 1403 → Class: AR
    If IPI ≥ 1404 → Class: CG
'''
import json
from pathlib import Path

with (Path(__file__).resolve().parent / "weights.json").open() as f:
    data = json.load(f)

#with open("./weights.json", "r") as f:
    #data = json.load(f)

#print(data['Tree1']['IPG']['r1']['min'], data['Tree1']['IPG']['r1']['max'],data['Tree1']['IPG']['r1']['class'])

#FS (Three rules)
coupling_program.pipe.Ingress.table_T1_FS.add_with_classify_T1(metadata_frame_size_start=data['Tree1']['FS']['r1']['min'], 
                                                      metadata_frame_size_end=data['Tree1']['FS']['r1']['max'], 
                                                      classify_result=data['Tree1']['FS']['r1']['class'])

coupling_program.pipe.Ingress.table_T1_FS.add_with_classify_T1(metadata_frame_size_start=data['Tree1']['FS']['r2']['min'], 
                                                      metadata_frame_size_end=data['Tree1']['FS']['r2']['max'], 
                                                      classify_result=data['Tree1']['FS']['r2']['class'])


coupling_program.pipe.Ingress.table_T1_FS.add_with_classify_T1(metadata_frame_size_start=data['Tree1']['FS']['r3']['min'], 
                                                      metadata_frame_size_end=data['Tree1']['FS']['r3']['max'], 
                                                      classify_result=data['Tree1']['FS']['r3']['class'])

coupling_program.pipe.Ingress.table_T1_FS.add_with_classify_T1(metadata_frame_size_start=data['Tree1']['FS']['r4']['min'], 
                                                      metadata_frame_size_end=data['Tree1']['FS']['r4']['max'], 
                                                      classify_result=data['Tree1']['FS']['r4']['class'])


## PS (Manually)
coupling_program.pipe.Ingress.table_T1_PS.add_with_classify_T1(metadata_frame_size_start=data['Tree1']['PS']['r1']['min'], 
                                                      metadata_frame_size_end=data['Tree1']['PS']['r1']['max'], 
                                                      classify_result=data['Tree1']['PS']['r1']['class'])
coupling_program.pipe.Ingress.table_T1_PS.add_with_classify_T1(metadata_frame_size_start=data['Tree1']['PS']['r2']['min'], 
                                                      metadata_frame_size_end=data['Tree1']['PS']['r2']['max'], 
                                                      classify_result=data['Tree1']['PS']['r2']['class'])
coupling_program.pipe.Ingress.table_T1_PS.add_with_classify_T1(metadata_frame_size_start=data['Tree1']['PS']['r3']['min'], 
                                                      metadata_frame_size_end=data['Tree1']['PS']['r3']['max'], 
                                                      classify_result=data['Tree1']['PS']['r3']['class'])
coupling_program.pipe.Ingress.table_T1_PS.add_with_classify_T1(metadata_frame_size_start=data['Tree1']['PS']['r4']['min'], 
                                                      metadata_frame_size_end=data['Tree1']['PS']['r4']['max'], 
                                                      classify_result=data['Tree1']['PS']['r4']['class'])

'''
        "r1": { "min": 100, "max": 550, "class": 2 },
        "r2": { "min": 550, "max": 1100, "class": 1 },
        "r3": { "min": 0, "max": 99, "class": 3 },
        "r4": { "min": 1101, "max": 65535, "class": 3 }
'''
'''
coupling_program.pipe.Ingress.table_T1_FS.add_with_classify_T1(metadata_frame_size_start=43, metadata_frame_size_end=1667, classify_result=2)
coupling_program.pipe.Ingress.table_T1_FS.add_with_classify_T1(metadata_frame_size_start=1668, metadata_frame_size_end=max_value_16_bit, classify_result=0)
'''
#IPG (Two Rules)
coupling_program.pipe.Ingress.table_T1_IPG.add_with_classify_T1(metadata_ipg_20lsb_start=data['Tree1']['IPG']['r1']['min'], 
                                                      metadata_ipg_20lsb_end=data['Tree1']['IPG']['r1']['max'], 
                                                      classify_result=data['Tree1']['IPG']['r1']['class'])

coupling_program.pipe.Ingress.table_T1_IPG.add_with_classify_T1(metadata_ipg_20lsb_start=data['Tree1']['IPG']['r2']['min'], 
                                                      metadata_ipg_20lsb_end=data['Tree1']['IPG']['r2']['max'], 
                                                      classify_result=data['Tree1']['IPG']['r2']['class'])
'''
coupling_program.pipe.Ingress.table_T1_IPG.add_with_classify_T1(metadata_ipg_20lsb_start=0, metadata_ipg_20lsb_end=1403, classify_result=1)
coupling_program.pipe.Ingress.table_T1_IPG.add_with_classify_T1(metadata_ipg_20lsb_start=1404, metadata_ipg_20lsb_end=max_value_20_bit, classify_result=2)
'''

'''
Tree2 
------------------------------------------- 
IFI Check:
    If IFI ≤ 31502 → Class: Other
    (No need to check PS as this range always predicts Other.)

If IFI ≥ 31503:
    IPI Check:
        If IPI ≤ 1403 → Class: AR
        If IPI > 1403 → Class: CG       
'''
#IFG (Two Rules)
coupling_program.pipe.Ingress.table_T2_IFG.add_with_classify_T2(metadata_ifg_20lsb_start=data['Tree2']['IFG']['r1']['min'], 
                                                       metadata_ifg_20lsb_end=data['Tree2']['IFG']['r1']['max'], 
                                                       classify_result=data['Tree2']['IFG']['r1']['class'])
coupling_program.pipe.Ingress.table_T2_IFG.add_with_classify_T2(metadata_ifg_20lsb_start=data['Tree2']['IFG']['r2']['min'], 
                                                       metadata_ifg_20lsb_end=data['Tree2']['IFG']['r2']['max'], 
                                                       classify_result=data['Tree2']['IFG']['r2']['class'])
coupling_program.pipe.Ingress.table_T2_IFG.add_with_classify_T2(metadata_ifg_20lsb_start=data['Tree2']['IFG']['r3']['min'], 
                                                       metadata_ifg_20lsb_end=data['Tree2']['IFG']['r3']['max'], 
                                                       classify_result=data['Tree2']['IFG']['r3']['class'])

'''
## PS (Manually)
coupling_program.pipe.Ingress.table_T2_PS.add_with_classify_T1(metadata_frame_size_start=data['Tree1']['PS']['r1']['min'], 
                                                      metadata_frame_size_end=data['Tree1']['PS']['r1']['max'], 
                                                      classify_result=data['Tree1']['PS']['r1']['class'])
coupling_program.pipe.Ingress.table_T2_PS.add_with_classify_T1(metadata_frame_size_start=data['Tree1']['PS']['r2']['min'], 
                                                      metadata_frame_size_end=data['Tree1']['PS']['r2']['max'], 
                                                      classify_result=data['Tree1']['PS']['r2']['class'])
coupling_program.pipe.Ingress.table_T2_PS.add_with_classify_T1(metadata_frame_size_start=data['Tree1']['PS']['r3']['min'], 
                                                      metadata_frame_size_end=data['Tree1']['PS']['r3']['max'], 
                                                      classify_result=data['Tree1']['PS']['r3']['class'])
coupling_program.pipe.Ingress.table_T2_PS.add_with_classify_T1(metadata_frame_size_start=data['Tree1']['PS']['r4']['min'], 
                                                      metadata_frame_size_end=data['Tree1']['PS']['r4']['max'], 
                                                      classify_result=data['Tree1']['PS']['r4']['class'])
'''


'''
coupling_program.pipe.Ingress.table_T2_IFG.add_with_classify_T2(metadata_ifg_20lsb_start=0, metadata_ifg_20lsb_end=31502, classify_result=3)
coupling_program.pipe.Ingress.table_T2_IFG.add_with_classify_T2(metadata_ifg_20lsb_start=31503, metadata_ifg_20lsb_end=max_value_20_bit, classify_result=0)
'''

#IPG (Two Rules)
coupling_program.pipe.Ingress.table_T2_IPG.add_with_classify_T2(metadata_ipg_20lsb_start=data['Tree2']['IPG']['r1']['min'], 
                                                       metadata_ipg_20lsb_end=data['Tree2']['IPG']['r1']['max'], 
                                                       classify_result=data['Tree2']['IPG']['r1']['class'])
coupling_program.pipe.Ingress.table_T2_IPG.add_with_classify_T2(metadata_ipg_20lsb_start=data['Tree2']['IPG']['r2']['min'], 
                                                       metadata_ipg_20lsb_end=data['Tree2']['IPG']['r2']['max'], 
                                                       classify_result=data['Tree2']['IPG']['r2']['class'])

'''
coupling_program.pipe.Ingress.table_T2_IPG.add_with_classify_T2(metadata_ipg_20lsb_start=0, metadata_ipg_20lsb_end=1403, classify_result=1)
coupling_program.pipe.Ingress.table_T2_IPG.add_with_classify_T2(metadata_ipg_20lsb_start=1404, metadata_ipg_20lsb_end=max_value_20_bit, classify_result=2)
'''


'''
Tree3 
------------------------------------------- 
Step 1: Check FS
    If FS ≤ 42 → Class: Other
    (This covers cases where FS is very low, regardless of IFI or IPI.)
    If FS > 42 → Go to Step 2

Step 2: Check IFI
    If IFI ≤ 57938 → Class: CG
    (When FS is high and IFI is not too high, the decision is CG.)

    If IFI > 57938 → Go to Step 3

Step 3: Check IPI
    If IPI ≤ 1403 → Class: AR
    If IPI > 1403 → Class: CG
'''
#FS (Two Rules)
coupling_program.pipe.Ingress.table_T3_FS.add_with_classify_T3(metadata_frame_size_start=data['Tree3']['FS']['r1']['min'], 
                                                      metadata_frame_size_end=data['Tree3']['FS']['r1']['max'], 
                                                      classify_result=data['Tree3']['FS']['r1']['class'])
coupling_program.pipe.Ingress.table_T3_FS.add_with_classify_T3(metadata_frame_size_start=data['Tree3']['FS']['r2']['min'], 
                                                      metadata_frame_size_end=data['Tree3']['FS']['r2']['max'], 
                                                      classify_result=data['Tree3']['FS']['r2']['class'])

'''
coupling_program.pipe.Ingress.table_T3_FS.add_with_classify_T3(metadata_frame_size_start=0, metadata_frame_size_end=42, classify_result=3)
coupling_program.pipe.Ingress.table_T3_FS.add_with_classify_T3(metadata_frame_size_start=43, metadata_frame_size_end=max_value_16_bit, classify_result=0)
'''
#IFG (Two Rules)
coupling_program.pipe.Ingress.table_T3_IFG.add_with_classify_T3(metadata_ifg_20lsb_start=data['Tree3']['IFG']['r1']['min'], 
                                                       metadata_ifg_20lsb_end=data['Tree3']['IFG']['r1']['max'], 
                                                       classify_result=data['Tree3']['IFG']['r1']['class'])
coupling_program.pipe.Ingress.table_T3_IFG.add_with_classify_T3(metadata_ifg_20lsb_start=data['Tree3']['IFG']['r2']['min'], 
                                                       metadata_ifg_20lsb_end=data['Tree3']['IFG']['r2']['max'], 
                                                       classify_result=data['Tree3']['IFG']['r2']['class'])

'''
coupling_program.pipe.Ingress.table_T3_IFG.add_with_classify_T3(metadata_ifg_20lsb_start=0, metadata_ifg_20lsb_end=57938, classify_result=2)
coupling_program.pipe.Ingress.table_T3_IFG.add_with_classify_T3(metadata_ifg_20lsb_start=57939, metadata_ifg_20lsb_end=max_value_20_bit, classify_result=0)
'''



#IPG (Two Rules)
coupling_program.pipe.Ingress.table_T3_IPG.add_with_classify_T3(metadata_ipg_20lsb_start=data['Tree3']['IPG']['r1']['min'], 
                                                       metadata_ipg_20lsb_end=data['Tree3']['IPG']['r1']['max'], 
                                                       classify_result=data['Tree3']['IPG']['r1']['class'])
coupling_program.pipe.Ingress.table_T3_IPG.add_with_classify_T3(metadata_ipg_20lsb_start=data['Tree3']['IPG']['r2']['min'], 
                                                       metadata_ipg_20lsb_end=data['Tree3']['IPG']['r2']['max'], 
                                                       classify_result=data['Tree3']['IPG']['r2']['class'])
'''
coupling_program.pipe.Ingress.table_T3_IPG.add_with_classify_T3(metadata_ipg_20lsb_start=0, metadata_ipg_20lsb_end=1403, classify_result=1)
coupling_program.pipe.Ingress.table_T3_IPG.add_with_classify_T3(metadata_ipg_20lsb_start=1404, metadata_ipg_20lsb_end=max_value_20_bit, classify_result=2)
'''


'''
 Tree4 
-------------------------------------------
Step 1: Check IFI
    If IFI ≤ 57831 → Go to Step 2a (FS=6)

    If IFI ≥ 57832 → Go to Step 2b  (IPI=5)

Step 2a: (Low IFI Range)

    Check FS:
        If FS ≤ 44 → Class: Other
        (This follows the rule: (0≤ IFI ≤57831) & (0≤ FS ≤44))

        If FS ≥ 45 → Class: CG
        (This follows the rule: (45 ≤ FS ≤ 65535))

Step 2b: (High IFI Range)

    Check IPI:
        If IPI ≤ 1403 → Class: AR
        (This corresponds to: (57832≤ IFI ≤1048575) & (0 ≤ IPI ≤1403))

        If IPI ≥ 218209 → Class: Other
        (This corresponds to: (57832≤ IFI ≤1048575) & (218209≤ IPI ≤1048575))

        If IPI is between 1404 and 218208 → Class: CG
        (This covers the remaining cases where IFI is high and IPI isn’t extremely low or high)
'''
#IFG (Two Rule)
coupling_program.pipe.Ingress.table_T4_IFG.add_with_classify_T4(metadata_ifg_20lsb_start=data['Tree4']['IFG']['r1']['min'], 
                                                       metadata_ifg_20lsb_end=data['Tree4']['IFG']['r1']['max'], 
                                                       classify_result=data['Tree4']['IFG']['r1']['class'])
coupling_program.pipe.Ingress.table_T4_IFG.add_with_classify_T4(metadata_ifg_20lsb_start=data['Tree4']['IFG']['r2']['min'], 
                                                       metadata_ifg_20lsb_end=data['Tree4']['IFG']['r2']['max'], 
                                                       classify_result=data['Tree4']['IFG']['r2']['class'])

'''
coupling_program.pipe.Ingress.table_T4_IFG.add_with_classify_T4(metadata_ifg_20lsb_start=0, metadata_ifg_20lsb_end=57831, classify_result=6)
coupling_program.pipe.Ingress.table_T4_IFG.add_with_classify_T4(metadata_ifg_20lsb_start=57832, metadata_ifg_20lsb_end=max_value_20_bit, classify_result=5)

'''


#FS (Two Rules)
coupling_program.pipe.Ingress.table_T4_FS.add_with_classify_T4(metadata_frame_size_start=data['Tree4']['FS']['r1']['min'], 
                                                      metadata_frame_size_end=data['Tree4']['FS']['r1']['max'], 
                                                      classify_result=data['Tree4']['FS']['r1']['class'])
coupling_program.pipe.Ingress.table_T4_FS.add_with_classify_T4(metadata_frame_size_start=data['Tree4']['FS']['r2']['min'], 
                                                      metadata_frame_size_end=data['Tree4']['FS']['r2']['max'], 
                                                      classify_result=data['Tree4']['FS']['r2']['class'])
coupling_program.pipe.Ingress.table_T4_FS.add_with_classify_T4(metadata_frame_size_start=data['Tree4']['FS']['r3']['min'], 
                                                      metadata_frame_size_end=data['Tree4']['FS']['r3']['max'], 
                                                      classify_result=data['Tree4']['FS']['r3']['class'])
'''
coupling_program.pipe.Ingress.table_T4_FS.add_with_classify_T4(metadata_frame_size_start=0, metadata_frame_size_end=44, classify_result=3)
coupling_program.pipe.Ingress.table_T4_FS.add_with_classify_T4(metadata_frame_size_start=45, metadata_frame_size_end=max_value_16_bit, classify_result=2)
'''

#IPG (Three Rules)
coupling_program.pipe.Ingress.table_T4_IPG.add_with_classify_T4(metadata_ipg_20lsb_start=data['Tree4']['IPG']['r1']['min'], 
                                                       metadata_ipg_20lsb_end=data['Tree4']['IPG']['r1']['max'], 
                                                       classify_result=data['Tree4']['IPG']['r1']['class'])
coupling_program.pipe.Ingress.table_T4_IPG.add_with_classify_T4(metadata_ipg_20lsb_start=data['Tree4']['IPG']['r2']['min'], 
                                                       metadata_ipg_20lsb_end=data['Tree4']['IPG']['r2']['max'], 
                                                       classify_result=data['Tree4']['IPG']['r2']['class'])
coupling_program.pipe.Ingress.table_T4_IPG.add_with_classify_T4(metadata_ipg_20lsb_start=data['Tree4']['IPG']['r3']['min'], 
                                                       metadata_ipg_20lsb_end=data['Tree4']['IPG']['r3']['max'], 
                                                       classify_result=data['Tree4']['IPG']['r3']['class'])

'''
coupling_program.pipe.Ingress.table_T4_IPG.add_with_classify_T4(metadata_ipg_20lsb_start=0, metadata_ipg_20lsb_end=1403, classify_result=1)
coupling_program.pipe.Ingress.table_T4_IPG.add_with_classify_T4(metadata_ipg_20lsb_start=1404, metadata_ipg_20lsb_end=218208, classify_result=2)
coupling_program.pipe.Ingress.table_T4_IPG.add_with_classify_T4(metadata_ipg_20lsb_start=218208, metadata_ipg_20lsb_end=max_value_20_bit, classify_result=3)
'''



# tree4 *************************************************
'''
Tree5 
-------------------------------------------
FS Check:

    If FS ≤ 42 → Class: Other
    If FS > 42 → Go to IPI check

IPI Check (when FS > 42):
    If IPI ≤ 1382 → Class: AR
    If IPI > 1382 → Class: CG
'''
#FS (Two Rules)
coupling_program.pipe.Ingress.table_T5_FS.add_with_classify_T5(metadata_frame_size_start=data['Tree5']['FS']['r1']['min'], 
                                                      metadata_frame_size_end=data['Tree5']['FS']['r1']['max'], 
                                                      classify_result=data['Tree5']['FS']['r1']['class'])
coupling_program.pipe.Ingress.table_T5_FS.add_with_classify_T5(metadata_frame_size_start=data['Tree5']['FS']['r2']['min'], 
                                                      metadata_frame_size_end=data['Tree5']['FS']['r2']['max'], 
                                                      classify_result=data['Tree5']['FS']['r2']['class'])

'''
coupling_program.pipe.Ingress.table_T5_FS.add_with_classify_T5(metadata_frame_size_start=0, metadata_frame_size_end=42, classify_result=3)
coupling_program.pipe.Ingress.table_T5_FS.add_with_classify_T5(metadata_frame_size_start=43, metadata_frame_size_end=max_value_16_bit, classify_result=0)
'''
#IPG (Two Rules)
coupling_program.pipe.Ingress.table_T5_IPG.add_with_classify_T5(metadata_ipg_20lsb_start=data['Tree5']['IPG']['r1']['min'], 
                                                       metadata_ipg_20lsb_end=data['Tree5']['IPG']['r1']['max'], 
                                                       classify_result=data['Tree5']['IPG']['r1']['class'])
coupling_program.pipe.Ingress.table_T5_IPG.add_with_classify_T5(metadata_ipg_20lsb_start=data['Tree5']['IPG']['r2']['min'], 
                                                       metadata_ipg_20lsb_end=data['Tree5']['IPG']['r2']['max'], 
                                                       classify_result=data['Tree5']['IPG']['r2']['class'])

coupling_program.pipe.Ingress.table_T5_IPG.add_with_classify_T5(metadata_ipg_20lsb_start=data['Tree5']['IPG']['r3']['min'], 
                                                       metadata_ipg_20lsb_end=data['Tree5']['IPG']['r3']['max'], 
                                                       classify_result=data['Tree5']['IPG']['r3']['class'])

'''
coupling_program.pipe.Ingress.table_T5_IPG.add_with_classify_T5(metadata_ipg_20lsb_start=0, metadata_ipg_20lsb_end=1382, classify_result=1)
coupling_program.pipe.Ingress.table_T5_IPG.add_with_classify_T5(metadata_ipg_20lsb_start=1383, metadata_ipg_20lsb_end=max_value_20_bit, classify_result=2)
'''

print(data['Tree5']['IPG']['r1']['min'], data['Tree5']['IPG']['r1']['max'],data['Tree5']['IPG']['r1']['class'])
print(data['Tree5']['IPG']['r2']['min'], data['Tree5']['IPG']['r2']['max'],data['Tree5']['IPG']['r2']['class'])
#print(data['Tree5']['FS']['r3']['min'], data['Tree5']['FS']['r3']['max'],data['Tree5']['FS']['r3']['class'])






##Threshold of Mirroring 
##coupling_program.pipe.Egress.table_threshold.add_with_decisionMirror(packet_counter_value_start=0, packet_counter_value_end=0,frame_counter_value_start=0,frame_counter_value_end=0)
# r2c1: per-entry observation budget (replaces table_pkt_check/table_frame_check).
# A packet is cloned while its 1-based packet index <= P AND fewer than F frames
# (RTP markers) of its entry have completed before it.
R2C1_BUDGETS = {'DL': {'packets': 52, 'frames': 13}, 'UL': {'packets': 32, 'frames': 8}}


def set_budget(direction):
    budget = R2C1_BUDGETS[direction]
    table = coupling_program.pipe.Egress.r2c1_budget
    table.clear()
    table.add_with_decisionMirror(r2c1_pkt_idx_start=1, r2c1_pkt_idx_end=budget['packets'],
                                  r2c1_frm_idx_start=0, r2c1_frm_idx_end=budget['frames'] - 1)
    bfrt.complete_operations()
    print('r2c1 budget', direction, budget)
    return budget


# Aggregation & Final Decision 
# Historical alternative majority-table loader (unused).

script_dir = Path(__file__).resolve().parent
with (script_dir / "majority.txt").open() as f:
#with open("majority.txt", "r") as f:
    for line in f:
        line = line.strip()
        if not line:
            continue  # Skip empty lines

        # Expected format: t1=1,t2=2,t3=2,t4=2,t5=2,m=2
        parts = line.split(',')
        votes = {}
        for part in parts:
            key, value = part.split('=')
            votes[key.strip()] = int(value.strip())

        # Use the BFRT API to add the entry
        coupling_program.pipe.Ingress.table_majority.add_with_trees_aggregation(
            metadata_classT1 = votes['t1'],
            metadata_classT2 = votes['t2'],
            metadata_classT3 = votes['t3'],
            metadata_classT4 = votes['t4'],
            metadata_classT5 = votes['t5'],
            majority        = votes['m']
        )




# coupling_setup: run after the existing classifier and TM configuration.
# r2c1: coupled AQM disabled; set_coupling_base() is not called.

# Manual commands in bfrt_python after loading this controller:
# set_coupling_base(137, 0)      # Disable Classic CE/drop and L4S coupled CE.
#                               # L4S native TM marking remains active.
# set_coupling_base(137, 3277)   # Classic ~= 0.25%; L4S coupled ~= 10%.
# coupling_register.get(REGISTER_INDEX=137, from_hw=True)

# coupling_classic_register.get(REGISTER_INDEX=137, from_hw=True)

# coupling_feedback_start: explicit, bounded first trial after loading this file.
# run_coupling_aqm(duration_s=10)
# run_coupling_aqm(duration_s=None)  # Continuous; Ctrl-C stops the loop.

# topology_setup: unverified cabling is not assigned a guessed port.
if all(port is not None for port in SERVER_PORT_MAP.values()):
    install_server_topology(SERVER_PORT_MAP)
else:
    print("Fiber mapping is unset. Generate IPv4/ARP traffic from all three servers,")
    print("then run discover_server_ports() and install_discovered_topology().")
