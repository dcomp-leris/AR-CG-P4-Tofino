"""Offline tests of the c7 coupling_aqm change: PYTHONPATH=ICEFE python3 -m unittest scripts/test_c7_aqm.py"""
import unittest
from coupling_aqm import CouplingAQM

BUSY = 2 ** 31


def run(c, q0_fn, q1_fn, cycles, t0=0.0):
    t, r = t0, None
    for i in range(cycles):
        r = c.update(q0_fn(i), q1_fn(i), t)
        t += 0.016
    return r, t


class C7Tests(unittest.TestCase):
    def test_hardware_trace_original_freezes(self):
        c = CouplingAQM(stale_busy_holds=True)
        r, _ = run(c, lambda i: (26973676, BUSY | 1), lambda i: (102, BUSY | (100 + i)), 200)
        self.assertEqual(r[1], 'stale-busy')
        self.assertGreater(c.probability, 0.005)

    def test_hardware_trace_c7_drains(self):
        c = CouplingAQM()
        r, _ = run(c, lambda i: (26973676, BUSY | 1), lambda i: (102, BUSY | (100 + i)), 200)
        self.assertEqual(r[1], 'updated')
        self.assertEqual(c.probability, 0.0)

    def test_single_busy_queue_is_controlled(self):
        # Only Q0 carries a 28 ms standing queue; Q1 idle (stale). p must rise.
        c = CouplingAQM()
        run(c, lambda i: (28000000, BUSY | (10 + i)), lambda i: (102, BUSY | 1), 300)
        self.assertGreater(c.probability, 0.05)

    def test_no_samples_still_holds(self):
        c = CouplingAQM(initial_probability=0.1)
        r = c.update((0, 0), (0, 0), 0.0)
        self.assertEqual(r, (None, 'no-samples'))
        self.assertEqual(c.probability, 0.1)


if __name__ == '__main__':
    unittest.main()
