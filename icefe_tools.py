"""ICEFE measurement helpers for bfrt_python (counters, sampled ring, per-flow state).

Load AFTER the controller, inside bfrt_python:
    %run -i /path/to/ICEFE/ICEFE.py          (configures the switch)
    %run -i /path/to/ICEFE/icefe_tools.py    (adds the functions below)

Functions (the names keep the "c7_" prefix used by all experiment scripts):
  c7_reset()              clear the c7 counters, the sample ring and its sequence/slot registers
  c7_set_mask(k)          store 1 packet out of 2^k (leaving port 137) in the sample ring
  c7_set_step(us)         L4S step marking threshold in microseconds (default 1000 = 1 ms)
  c7_counters()           print/return the non-zero decision, class and AQM-event counters
  c7_ring()               read the filled ring slots (residence time, queue delay, flow, DSCP, ECN, event)
  c7_save(path)           counters + ring + current AQM probability of port 137 -> JSON file
  c7_diag()               show the classification path of every flow (clones, tree votes, decision)
  c7_clear_flows()        forget all per-flow decisions so the next flows are classified again
  c7_flow_state(path)     per-flow packet / clone / decision counters (used by the smoke test)
  c7_clear_features()     clear the per-flow feature registers (LPF state needs a switchd restart)
  c7_collect_features(p)  dump all non-zero per-flow feature registers to JSON (training)
All reads use pipe 1 (dev ports 128-255, i.e. the server ports 136/137/138).
"""
import json          # result files
import time          # timestamps / timing of slow reads

C7_PIPE = 1          # registers are read from pipe 1 (dev ports 128-255 = 136/137/138)
C7_ALL_PIPES = 65535 # counters are summed over all pipes
C7_RING = 65536      # number of slots of the sample ring (P4: c7_residence_ring etc.)
# Program handle: PROGRAM_NAME is defined by ICEFE.py (default "ICEFE").
C7_PROG = getattr(bfrt, globals().get('PROGRAM_NAME', 'ICEFE'))
C7_IG = C7_PROG.pipe.Ingress   # ingress tables/registers
C7_EG = C7_PROG.pipe.Egress    # egress tables/registers
# Decoding of the codes stored by the P4 program.
C7_CLASS = {0: 'none', 1: 'AR', 2: 'CG', 3: 'Other'}
C7_EVENT = {0: 'none', 1: 'ce_tm', 2: 'ce_coupled', 3: 'ce_classic', 4: 'drop_classic', 5: 'ce_step'}
C7_ECN = {0: 'NotECT', 1: 'ECT1', 2: 'ECT0', 3: 'CE'}


def _c7_name(key):
    """BFRT field name without prefix, e.g. b'Egress.c7_seq_reg.f1' -> 'f1'."""
    return (key.decode() if isinstance(key, bytes) else str(key)).split('.')[-1].lstrip('$')


def _c7_scalar(value):
    """Single value from a BFRT field (lists of one element, bytes -> int)."""
    if isinstance(value, (list, tuple)):
        value = value[0] if len(value) == 1 else value
    if isinstance(value, (bytes, bytearray)):
        return int.from_bytes(value, 'big')
    return value


def _c7_fields(entry):
    """All data fields of one BFRT entry as a {name: value} dict."""
    if isinstance(entry, (list, tuple)):
        entry = entry[0]
    return {_c7_name(k): _c7_scalar(v) for k, v in entry.data.items()}


def _c7_index(entry):
    """Index (REGISTER_INDEX or COUNTER_INDEX) of a BFRT entry."""
    for k, v in entry.key.items():
        if _c7_name(k) in ('REGISTER_INDEX', 'COUNTER_INDEX'):
            return _c7_scalar(v)
    raise RuntimeError('No index in BFRT key')


def _c7_ctr(table, index):
    """(packets, bytes) of one counter index, read from hardware, summed over pipes."""
    f = _c7_fields(table.get(COUNTER_INDEX=index, pipe=C7_ALL_PIPES, from_hw=True,
                             print_ents=False, return_ents=True))
    return f.get('COUNTER_SPEC_PKTS', 0), f.get('COUNTER_SPEC_BYTES', 0)


def _c7_reg(table, index=0):
    """Value of one register cell (pipe 1), read from hardware."""
    return _c7_fields(table.get(REGISTER_INDEX=index, pipe=C7_PIPE, from_hw=True,
                                print_ents=False, return_ents=True))['f1']


def c7_reset():
    """Clear the c7 counters and the sample ring (start of a run)."""
    for table in (C7_IG.c7_ingress_decision, C7_IG.c7_ingress_class, C7_EG.c7_egress_event,
                  C7_EG.c7_seq_reg, C7_EG.c7_slot_reg, C7_EG.c7_residence_ring,
                  C7_EG.c7_queue_ring, C7_EG.c7_tag_ring):
        table.clear()
    bfrt.complete_operations()
    print('c7 counters and ring cleared')


def c7_set_mask(k):
    """Ring sampling: 1 packet in 2^k (mask = 2^k - 1 is compared with the sequence number)."""
    C7_EG.c7_sampling.set_default_with_c7_set_mask(mask=(1 << k) - 1)
    bfrt.complete_operations()
    print('c7 ring samples 1 in', 1 << k)


def c7_set_step(step_us=1000):
    """L4S step threshold. P4 adds (2^32 - step) to the queue delay, so we pass the negative step."""
    step_ns = int(step_us * 1000)
    C7_EG.c7_l4s_step.set_default_with_c7_set_step(neg_step_ns=(1 << 32) - step_ns)
    bfrt.complete_operations()
    print('c7 L4S step threshold', step_us, 'us')


def c7_counters(show=True):
    """Decode the three counter arrays (index layouts are documented in ICEFE.p4)."""
    out = {'ingress_decision': [], 'ingress_class': [], 'egress_event': []}
    for i in range(16):
        p, b = _c7_ctr(C7_IG.c7_ingress_decision, i)
        if p:
            out['ingress_decision'].append({'decision': C7_CLASS[i >> 2],
                                            'arrival_ecn': C7_ECN[i & 3], 'packets': p, 'bytes': b})
    for i in range(8):
        p, b = _c7_ctr(C7_IG.c7_ingress_class, i)
        if p:
            out['ingress_class'].append({'queue': i >> 2, 'class': C7_CLASS[i & 3],
                                         'packets': p, 'bytes': b})
    for i in range(64):
        p, b = _c7_ctr(C7_EG.c7_egress_event, i)
        if p:
            out['egress_event'].append({'queue': i >> 5, 'class': C7_CLASS[(i >> 3) & 3],
                                        'event': C7_EVENT.get(i & 7, i & 7),
                                        'packets': p, 'bytes': b})
    if show:
        for key, rows in out.items():
            print(key)
            for row in rows:
                print('   ', row)
    return out


def c7_ring():
    """Read the filled part of the ring and decode the tag (flow ID, DSCP, ECN, queue, event)."""
    filled = min(_c7_reg(C7_EG.c7_slot_reg), C7_RING)
    columns = {}
    for name, table in (('residence', C7_EG.c7_residence_ring), ('queue', C7_EG.c7_queue_ring),
                        ('tag', C7_EG.c7_tag_ring)):
        entries = table.get(regex=True, pipe=C7_PIPE, from_hw=True,
                            print_ents=False, return_ents=True)
        columns[name] = {_c7_index(e): _c7_fields(e)['f1'] for e in entries}
    rows = []
    for slot in range(filled):
        tag = columns['tag'].get(slot, 0)
        rows.append({'residence_ns': columns['residence'].get(slot), 'queue_raw': columns['queue'].get(slot),
                     'flow_id': tag >> 16, 'dscp': (tag >> 10) & 63, 'ecn_out': (tag >> 8) & 3,
                     'queue': (tag >> 7) & 1, 'event': (tag >> 4) & 7})
    print('c7 ring:', len(rows), 'samples; sequence =', _c7_reg(C7_EG.c7_seq_reg))
    return rows


def c7_save(path, ring=True):
    """Write counters (+ ring) and the AQM probabilities of port 137 to a JSON file."""
    out = {'saved_unix': time.time(), 'counters': c7_counters(show=False),
           'sequence': _c7_reg(C7_EG.c7_seq_reg),
           'p_base_137': _c7_reg(C7_EG.coupling_base_probability, 137),
           'p_classic_137': _c7_reg(C7_EG.coupling_classic_probability, 137)}
    if ring:
        out['ring'] = c7_ring()
    with open(path, 'w') as f:
        json.dump(out, f)
    print('c7 saved', path)
    return path


def _c7_nonzero(table):
    """{index: value} of all non-zero cells of a register (slow: reads all 65536 cells)."""
    entries = table.get(regex=True, pipe=C7_PIPE, from_hw=True, print_ents=False, return_ents=True)
    return {_c7_index(e): _c7_fields(e)['f1'] for e in entries if _c7_fields(e)['f1']}


def c7_diag():
    """Classification path per flow index: egress count -> clone arrival -> trees -> decision."""
    steps = [('egress_pkt_cnt', C7_EG.c7_pkt_cnt), ('egress_frm_cnt', C7_EG.c7_frm_cnt),
             ('clone_arrivals', C7_IG.drop_cloned_pkt), ('T1', C7_IG.metadata_classT1),
             ('T2', C7_IG.metadata_classT2), ('T3', C7_IG.metadata_classT3),
             ('T4', C7_IG.metadata_classT4), ('T5', C7_IG.metadata_classT5),
             ('decision', C7_IG.shared_register)]
    out = {}
    for name, table in steps:
        t0 = time.time()
        out[name] = _c7_nonzero(table)
        print('%-15s %4d non-zero entries (%.0f s)  %s' % (
            name, len(out[name]), time.time() - t0, dict(list(sorted(out[name].items()))[:8])))
    print('budget entries:')
    C7_EG.c7_budget.dump()
    print('mirror session 1:')
    bfrt.mirror.cfg.get(sid=1)
    return out


def c7_clear_flows():
    """Clear per-flow classification state so replayed flows are cloned and classified again."""
    for table in (C7_EG.c7_pkt_cnt, C7_EG.c7_frm_cnt, C7_IG.drop_cloned_pkt, C7_IG.shared_register,
                  C7_IG.c7_ingress_flow, C7_EG.c7_clone_tx, C7_EG.c7_eg_flow,
                  C7_EG.timestamp_ipg_reg, C7_EG.timestamp_ifg_reg,
                  C7_IG.metadata_classT1, C7_IG.metadata_classT2, C7_IG.metadata_classT3,
                  C7_IG.metadata_classT4, C7_IG.metadata_classT5):
        table.clear()
    bfrt.complete_operations()
    print('c7 per-flow classification state cleared')


def _c7_nonzero_counter(table):
    """{index: packets} of all non-zero entries of a counter."""
    entries = table.get(regex=True, pipe=C7_ALL_PIPES, from_hw=True, print_ents=False, return_ents=True)
    out = {}
    for e in entries:
        f = _c7_fields(e)
        if f.get('COUNTER_SPEC_PKTS'):
            out[_c7_index(e)] = f['COUNTER_SPEC_PKTS']
    return out


def c7_flow_state(path=None):
    """Per-flow-index state for the smoke test (dict of index -> value per stage)."""
    state = {'ingress_pkts': _c7_nonzero(C7_IG.c7_ingress_flow),
             'egress_pkt_cnt': _c7_nonzero(C7_EG.c7_pkt_cnt),
             'clone_tx': _c7_nonzero(C7_EG.c7_clone_tx),
             'clone_rx': _c7_nonzero(C7_IG.drop_cloned_pkt),
             'decision': _c7_nonzero(C7_IG.shared_register),
             'egress_pkts': _c7_nonzero(C7_EG.c7_eg_flow)}
    for k, v in state.items():
        print('%-15s %s' % (k, dict(sorted(v.items())[:10])))
    if path:
        with open(path, 'w') as f:
            json.dump(state, f)
    return state


C7_FEATURE_REGS = ('packet_size_reg', 'frame_size_reg', 'ipg_cloned_packets_reg', 'ifg_reg',
                   'drop_cloned_pkt', 'shared_register', 'metadata_classT1', 'metadata_classT2',
                   'metadata_classT3', 'metadata_classT4', 'metadata_classT5', 'c7_ingress_flow')


def c7_clear_features():
    """Clear the per-flow classifier state read by c7_collect_features (LPF state is not
    reset here: a cold switchd start is required before a training/test replay)."""
    for name in C7_FEATURE_REGS + ('rtp_marker_reg',):
        getattr(C7_IG, name).clear()
    for table in (C7_EG.c7_pkt_cnt, C7_EG.c7_frm_cnt, C7_EG.c7_clone_tx, C7_EG.c7_eg_flow):
        table.clear()
    bfrt.complete_operations()
    print('c7 per-flow feature state cleared')


def c7_collect_features(path):
    """Dump every non-zero per-flow classifier register (index -> value) to JSON."""
    out = {}
    for name in C7_FEATURE_REGS:
        t0 = time.time()
        out[name] = _c7_nonzero(getattr(C7_IG, name))
        print('%-24s %6d entries (%.0f s)' % (name, len(out[name]), time.time() - t0))
    out['egress_pkts'] = _c7_nonzero(C7_EG.c7_eg_flow)
    out['clone_tx'] = _c7_nonzero(C7_EG.c7_clone_tx)
    with open(path, 'w') as f:
        json.dump(out, f)
    print('c7 features saved', path)
    return out
