"""Queue-sample freshness and DualPI2 core; no BFRT or switch side effects."""
import math


class CouplingAQM:
    def __init__(self, target_ms=15, interval_ms=16, alpha_hz=0.16,
                 beta_hz=3.2, initial_probability=0.0, stale_ms=64):
        if min(target_ms, interval_ms, stale_ms) <= 0:
            raise ValueError("Delay, update interval and stale timeout must be positive")
        self.target_s = target_ms / 1000
        self.interval_s = interval_ms / 1000
        self.alpha = alpha_hz
        self.beta = beta_hz
        self.probability = initial_probability
        self.stale_s = stale_ms / 1000
        self.samples = {}
        self.previous_delay_s = None
        self.previous_update_s = None

    def update(self, q0, q1, now):
        """Samples are (delay_ns, stamp_and_busy); now is host monotonic seconds.

        Never infer queue emptiness from absence of new dequeue samples.
        Stale busy samples hold the probability; stale last-empty samples
        contribute zero. This is an approximation, not live queue occupancy.
        """
        delays = []
        stale_busy = False
        seen_any = False
        for queue, (delay_ns, stamp) in enumerate((q0, q1)):
            if not 0 <= delay_ns <= 4294967295 or not 0 <= stamp <= 4294967295:
                raise ValueError("Invalid 32-bit queue sample")
            if delay_ns == 0 and stamp == 0 and queue not in self.samples:
                delays.append(0.0)
                continue
            seen_any = True
            previous = self.samples.get(queue)
            if previous is None or previous[:2] != (delay_ns, stamp):
                self.samples[queue] = (delay_ns, stamp, now)
            last_seen = self.samples[queue][2]
            stale = now - last_seen > self.stale_s
            busy = bool(stamp & 2147483648)
            if stale and busy:
                stale_busy = True
            delays.append(0.0 if stale else delay_ns / 1000000000)

        if not seen_any or stale_busy:
            # Resume with a fresh derivative and no integration across the gap.
            self.previous_delay_s = None
            self.previous_update_s = None
            return None, "stale-busy" if stale_busy else "no-samples"

        delay_s = max(delays)
        previous_delay = delay_s if self.previous_delay_s is None else self.previous_delay_s
        elapsed = self.interval_s if self.previous_update_s is None else now - self.previous_update_s
        if elapsed <= 0 or not math.isfinite(elapsed):
            raise ValueError("Controller time must advance")
        # Account for small polling jitter. Large scheduling overruns are
        # rejected by the BFRT loop rather than silently applying these gains.
        delta = self.alpha * (elapsed / self.interval_s) * (delay_s - self.target_s)
        delta += self.beta * (delay_s - previous_delay)
        self.probability = min(1.0, max(0.0, self.probability + delta))
        self.previous_delay_s = delay_s
        self.previous_update_s = now
        return min(65535, max(0, round(self.probability * 65536))), "updated"

    def queue_status(self, now):
        """Explain the freshness decision without changing controller state."""
        result = {}
        for queue in (0, 1):
            sample = self.samples.get(queue)
            if sample is None:
                result[queue] = {"state": "no-samples"}
                continue
            delay, stamp, seen_at = sample
            age_ms = max(0, now - seen_at) * 1000
            busy = bool(stamp & 2147483648)
            result[queue] = {
                "delay_ms": round(delay / 1000000, 6),
                "unchanged_ms": round(age_ms, 1),
                "last_dequeue_busy": busy,
                "state": "fresh" if age_ms <= self.stale_s * 1000 else
                         "stale-busy" if busy else "stale-last-empty"}
        return result


def bfrt_field(entry, suffix):
    """Read one pipe's scalar register field from a BFRT CLI TableEntry."""
    if isinstance(entry, (list, tuple)):
        if len(entry) != 1:
            raise ValueError("Expected exactly one BFRT register entry")
        entry = entry[0]
    if entry is None or not hasattr(entry, "data"):
        raise ValueError("BFRT did not return a register entry")
    values = []
    for name, value in entry.data.items():
        name = name.decode() if isinstance(name, bytes) else name
        if name.rsplit(".", 1)[-1] == suffix:
            values.append(value)
    if len(values) != 1:
        raise ValueError("Missing or ambiguous BFRT field " + suffix)
    value = values[0]
    if isinstance(value, (list, tuple)):
        if len(value) != 1:
            raise ValueError("Select a single pipe for register reads")
        value = value[0]
    if isinstance(value, (bytes, bytearray)):
        value = int.from_bytes(value, "big")
    return int(value)
