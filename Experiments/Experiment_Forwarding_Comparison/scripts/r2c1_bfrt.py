"""R2-C1 BFRT helpers and session runner. Load in bfrt_python with %run -i
AFTER the program's own setup (ICEFE_r2c1.py or fwd_setup.py).

Identical for both programs: port setup, TM settings, reset, sampling mask,
sum polling, common snapshot. ICEFE_r2c1 additionally snapshots per-entry
decision timing and clone/RF activity.
"""
import json
import time
from pathlib import Path

R2C1_ROOT = Path(__file__).resolve().parent.parent
R2C1_PIPE = 1                # dev ports 128-255 (136, 137, 138 and mirror 128)
R2C1_ALL_PIPES = 65535       # counter reads (indirect counters need all pipes)
R2C1_WRAP = 1 << 32
R2C1_RING = 65536
R2C1_PORTS = (136, 137, 138)
# Configuration registers that a state reset must not touch.
R2C1_KEEP = {'coupling_base_probability', 'coupling_classic_probability'}


def _name(key):
    return (key.decode() if isinstance(key, bytes) else str(key)).split('.')[-1].lstrip('$')


def _scalar(value):
    if isinstance(value, (list, tuple)):
        if len(value) != 1:
            raise ValueError('Expected one pipe value, got %r' % (value,))
        value = value[0]
    if isinstance(value, (bytes, bytearray)):
        return int.from_bytes(value, 'big')
    if isinstance(value, bool) or not isinstance(value, (int, str)):
        return value
    try:
        return int(value)
    except ValueError:
        return value  # enum/string fields such as SPEED


def _fields(entry):
    if isinstance(entry, (list, tuple)):
        if len(entry) != 1:
            raise ValueError('Expected one BFRT entry')
        entry = entry[0]
    if entry is None or not hasattr(entry, 'data'):
        raise RuntimeError('BFRT read failed: %r' % (entry,))
    return {_name(k): _scalar(v) for k, v in entry.data.items()
            if not isinstance(v, (list, tuple)) or len(v) == 1}


def _key_index(entry):
    for k, v in entry.key.items():
        if _name(k) in ('REGISTER_INDEX', 'COUNTER_INDEX'):
            return _scalar(v)
    raise RuntimeError('No index in BFRT key')


class R2C1:
    def __init__(self, program_name):
        self.name = program_name
        self.program = getattr(bfrt, program_name)
        self.icefe = program_name.startswith('ICEFE')
        self.ingress = self.program.pipe.Ingress if self.icefe else self.program.pipe.SwitchIngress
        self.egress = self.program.pipe.Egress
        build = R2C1_ROOT / 'programs' / program_name / 'bfrt.json'
        self.schema = json.loads(build.read_text())
        self.last = {}
        self.total = {}
        self.max_delta = {}
        self.polls = 0

    # ---------------------------------------------------------------- setup
    def setup_ports(self):
        """Same call sequence as ICEFE.py topology_interface_setup."""
        for port in R2C1_PORTS:
            current = bfrt.port.port.get(DEV_PORT=port, print_ents=False, return_ents=True)
            if current is None or current == -1 or current == []:
                bfrt.port.port.add(DEV_PORT=port, SPEED='BF_SPEED_10G', FEC='BF_FEC_TYP_NONE',
                                   PORT_ENABLE=True, AUTO_NEGOTIATION='PM_AN_FORCE_DISABLE')
            else:
                bfrt.port.port.mod(DEV_PORT=port, PORT_ENABLE=True)

    def apply_tm(self):
        """Identical TM in both programs: no port shaping; defaults otherwise."""
        for port in R2C1_PORTS:
            bfrt.tf2.tm.port.sched_cfg.mod(dev_port=port, max_rate_enable=False)
        bfrt.complete_operations()
        return self.tm_state()

    def tm_state(self):
        state = {}
        for port in R2C1_PORTS:
            item = {}
            for table in ('cfg', 'sched_cfg', 'sched_shaping', 'buffer'):
                obj = getattr(bfrt.tf2.tm.port, table, None)
                if obj is None:
                    continue
                try:
                    entry = obj.get(dev_port=port, from_hw=True, print_ents=False, return_ents=True)
                    item[table] = {k: str(v) for k, v in _fields(entry).items()}
                except Exception as error:  # record, do not hide
                    item[table] = 'unreadable: %s' % error
            state[str(port)] = item
        return state

    def port_state(self):
        out = {}
        for port in R2C1_PORTS:
            entry = bfrt.port.port.get(DEV_PORT=port, print_ents=False, return_ents=True)
            out[str(port)] = {k: str(v) for k, v in _fields(entry).items()
                              if k in ('SPEED', 'FEC', 'PORT_ENABLE', 'PORT_UP', 'AUTO_NEGOTIATION')}
        return out

    # ---------------------------------------------------------------- state
    def _tables(self, kinds):
        prefix = 'pipe.'
        for table in self.schema['tables']:
            name = table['name']
            if not name.startswith(prefix) or table['table_type'] not in kinds:
                continue
            control, leaf = name.split('.')[1], name.split('.')[-1]
            if leaf in R2C1_KEEP:
                continue
            try:
                yield leaf, getattr(getattr(self.program.pipe, control), leaf)
            except AttributeError:
                continue  # in bfrt.json but without hardware allocation

    def reset(self):
        """Zero every register and counter of this program (configuration
        registers in R2C1_KEEP excepted). LPF filter state cannot be cleared
        from BFRT; each session therefore uses its own LPF index (CRC8 entry)
        and switchd is restarted before every run."""
        cleared = []
        for kind in (('Register',), ('Counter',)):
            for leaf, table in self._tables(kind):
                table.clear()
                cleared.append(leaf)
        bfrt.complete_operations()
        self.last, self.total, self.max_delta, self.polls = {}, {}, {}, 0
        for key in ('residence', 'queue'):
            self.last[key] = 0
            self.total[key] = 0
            self.max_delta[key] = 0
        return cleared

    def set_mask(self, mask):
        assert mask >= 0 and (mask & (mask + 1)) == 0, 'mask must be 2^k - 1'
        self.egress.r2c1_sampling.set_default_with_r2c1_set_mask(mask=mask)
        bfrt.complete_operations()

    # ---------------------------------------------------------------- reads
    def reg(self, table, index=0):
        return _fields(table.get(REGISTER_INDEX=index, pipe=R2C1_PIPE, from_hw=True,
                                 print_ents=False, return_ents=True))

    def ctr(self, table, index=0):
        values = _fields(table.get(COUNTER_INDEX=index, pipe=R2C1_ALL_PIPES, from_hw=True,
                                   print_ents=False, return_ents=True))
        return {'packets': values.get('COUNTER_SPEC_PKTS'), 'bytes': values.get('COUNTER_SPEC_BYTES')}

    def reg_all(self, table):
        entries = table.get(regex=True, pipe=R2C1_PIPE, from_hw=True,
                            print_ents=False, return_ents=True)
        return {_key_index(e): _fields(e) for e in entries}

    def poll(self):
        """Software carry for the 32-bit sums (P4 carry is unreliable on HW).
        Valid while each sum grows by < 2^32 between polls."""
        for key, table in (('residence', self.egress.r2c1_residence_sum),
                           ('queue', self.egress.r2c1_queue_sum)):
            value = self.reg(table)['f1']
            delta = (value - self.last[key]) % R2C1_WRAP
            self.last[key] = value
            self.total[key] += delta
            self.max_delta[key] = max(self.max_delta[key], delta)
        self.polls += 1

    def snapshot(self):
        self.poll()
        eg = self.egress
        out = {
            'program': self.name,
            'eval': self.ctr(eg.r2c1_eval_pkts),
            'residence_sum_ns': self.total['residence'],
            'queue_sum_raw': self.total['queue'],
            'sum_polls': self.polls,
            'sum_max_poll_delta': dict(self.max_delta),
            'residence_low32_final': self.last['residence'],
            'residence_max_ns': self.reg(eg.r2c1_residence_max)['f1'],
            'seq': self.reg(eg.r2c1_seq_reg)['f1'],
            'slots_used': self.reg(eg.r2c1_slot_reg)['f1'],
            'ingress_port_pkts': {str(p): self.ctr(self.ingress.r2c1_ingress_port_pkts, p)['packets']
                                  for p in (128, 136, 137)},
            'egress_port_pkts': {str(p): self.ctr(eg.r2c1_egress_port_pkts, p)['packets']
                                 for p in (136, 137)},
        }
        used = min(out['slots_used'], R2C1_RING)
        residence = self.reg_all(eg.r2c1_residence_ring)
        queue = self.reg_all(eg.r2c1_queue_ring)
        out['samples'] = [[residence[i]['f1'], queue[i]['f1']] for i in range(used)]
        if self.icefe:
            out['entries'] = self.entries()
        return out

    def entries(self):
        ig, eg = self.ingress, self.egress
        first = self.reg_all(ig.r2c1_first_eligible)
        decision = self.reg_all(ig.r2c1_decision_store)
        shared = self.reg_all(ig.shared_register)
        pkt = self.reg_all(eg.r2c1_pkt_cnt)
        frm = self.reg_all(eg.r2c1_frm_cnt)
        rows = []
        for index in range(256):
            if not first[index]['seen'] and not decision[index]['seen'] and not pkt[index]['f1']:
                continue
            row = {'entry': index,
                   'first_seen': first[index]['seen'], 'first_stamp': first[index]['stamp'],
                   'decision_seen': decision[index]['seen'], 'decision_stamp': decision[index]['stamp'],
                   'final_decision': shared[index]['f1'],
                   'egress_pkt_count': pkt[index]['f1'], 'egress_frame_count': frm[index]['f1']}
            for name, table in (('clone_tx', eg.r2c1_clone_tx), ('clone_rx', ig.r2c1_clone_rx),
                                ('rf_exec', ig.r2c1_rf_exec),
                                ('clone_after_decision', ig.r2c1_clone_after_decision),
                                ('orig_pkts', ig.r2c1_orig_pkts),
                                ('orig_with_decision', ig.r2c1_orig_with_decision)):
                row[name] = self.ctr(table, index)['packets']
            rows.append(row)
        return rows


def _wait_until(epoch):
    while True:
        remaining = epoch - time.time()
        if remaining <= 0:
            return
        time.sleep(min(remaining, 0.2))


def r2c1_run(run_id, program_name, direction, budget=None, poll_s=0.25, drain_s=2.0):
    """Follow the shared schedule in raw/runs/<run_id>/start.json.

    For each session: reset + mask before its slot, poll sums during replay,
    wait drain_s after the last scheduled packet, then snapshot."""
    run_dir = R2C1_ROOT / 'raw' / 'runs' / run_id
    start = json.loads((run_dir / 'start.json').read_text())
    assert start['program'] == program_name and start['direction'] == direction
    r = R2C1(program_name)
    meta = {'run_id': run_id, 'program': program_name, 'direction': direction,
            'budget': budget, 'start': start, 'port_state': r.port_state(),
            'tm_state': r.tm_state(), 'sessions': []}
    if r.icefe:
        meta['budget_entries'] = str(r.egress.r2c1_budget.get(regex=True, print_ents=False, return_ents=True))
    (run_dir / 'switch_meta.json').write_text(json.dumps(meta, indent=2, default=str))
    for item in start['schedule']:
        # Reset and arm before the slot opens.
        cleared = r.reset()
        r.set_mask(item['mask'])
        armed = time.time()
        if armed > item['start_epoch'] - 1.0:
            item_status = 'LATE_RESET'
        else:
            item_status = 'ok'
        _wait_until(item['start_epoch'])
        # Snapshot only after the replay has really stopped: tcpreplay can run
        # ~1% longer than the trace, so wait until the evaluated-packet counter
        # has been unchanged for drain_s (also drains outstanding clones).
        end = item['start_epoch'] + item['duration_s']
        last_count, last_change = -1, time.time()
        while True:
            r.poll()
            count = r.ctr(r.egress.r2c1_eval_pkts)['packets']
            now = time.time()
            if count != last_count:
                last_count, last_change = count, now
            if now >= end and now - last_change >= drain_s:
                break
            if now > end + 60:
                item_status = 'NOT_QUIESCENT'
                break
            time.sleep(poll_s)
        quiescent_epoch = time.time()
        snap = r.snapshot()
        snap.update({'session': item['session'], 'mask': item['mask'], 'status': item_status,
                     'quiescent_epoch': quiescent_epoch, 'last_count_change_epoch': last_change,
                     'armed_epoch': armed, 'snapshot_epoch': time.time(),
                     'cleared_tables': len(cleared)})
        (run_dir / ('switch_%s.json' % item['session'])).write_text(json.dumps(snap))
        meta['sessions'].append({k: snap[k] for k in ('session', 'status', 'armed_epoch',
                                                      'snapshot_epoch', 'slots_used')})
        print('r2c1', item['session'], item_status, snap['eval'], 'slots', snap['slots_used'])
    r.reset()
    (run_dir / 'switch_meta.json').write_text(json.dumps(meta, indent=2, default=str))
    (run_dir / 'switch_done.json').write_text(json.dumps({'done_epoch': time.time()}))
    print('r2c1 run complete:', run_dir)
