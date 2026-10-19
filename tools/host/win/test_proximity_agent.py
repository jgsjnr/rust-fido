"""Decision-logic tests for proximity_agent (no hardware, no Windows)."""

import sys
import os
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from proximity_agent import ProximityDecider, run_loop


class TestProximityDecider(unittest.TestCase):
    def test_stays_near_above_threshold(self):
        d = ProximityDecider(threshold_dbm=-75, lock_secs=10.0)
        for _ in range(5):
            self.assertFalse(d.update(-60, 2.0))
        self.assertEqual(d.away_secs, 0.0)
        self.assertFalse(d.locked)

    def test_locks_after_sustained_away(self):
        d = ProximityDecider(threshold_dbm=-75, lock_secs=10.0)
        results = [d.update(-90, 2.0) for _ in range(5)]
        self.assertEqual(results, [False, False, False, False, True])
        self.assertTrue(d.locked)

    def test_hysteresis_band_holds_state(self):
        d = ProximityDecider(threshold_dbm=-75, hysteresis_db=5, lock_secs=10.0)
        # -72 esta na banda [-75, -70): nem acumula nem zera.
        self.assertFalse(d.update(-90, 2.0))
        away = d.away_secs
        self.assertFalse(d.update(-72, 2.0))
        self.assertEqual(d.away_secs, away)
        # -70 ou acima zera (NEAR).
        self.assertFalse(d.update(-70, 2.0))
        self.assertEqual(d.away_secs, 0.0)

    def test_missing_read_counts_as_away_fail_closed(self):
        d = ProximityDecider(threshold_dbm=-75, lock_secs=6.0)
        self.assertFalse(d.update(None, 2.0))
        self.assertFalse(d.update(None, 2.0))
        self.assertTrue(d.update(None, 2.0))

    def test_source_error_counts_as_away_fail_closed(self):
        d = ProximityDecider(threshold_dbm=-75, lock_secs=4.0)
        self.assertFalse(d.update(None, 2.0, source_error=True))
        self.assertTrue(d.update(None, 2.0, source_error=True))

    def test_no_auto_unlock_latch_until_near(self):
        d = ProximityDecider(threshold_dbm=-75, lock_secs=4.0)
        d.update(-90, 2.0)
        self.assertTrue(d.update(-90, 2.0))
        # Ainda AWAY apos lock: nao dispara lock de novo, segue travado.
        self.assertFalse(d.update(-90, 2.0))
        self.assertTrue(d.locked)
        # So volta a NEAR com RSSI forte; proximo ciclo pode travar de novo.
        d.update(-60, 2.0)
        self.assertFalse(d.locked)

    def test_watchdog_forces_lock_on_repeated_errors(self):
        d = ProximityDecider(threshold_dbm=-75, lock_secs=600.0)

        def boom():
            raise OSError("BLE down")

        calls = []
        outcome = run_loop(
            boom,
            d,
            lock_fn=lambda: calls.append(1) or True,
            poll_secs=2.0,
            max_ticks=50,
            sleep_fn=lambda s: None,
            log_fn=lambda m: None,
        )
        self.assertEqual(outcome, "locked")
        self.assertEqual(len(calls), 1)

    def test_run_loop_locks_with_scripted_source(self):
        d = ProximityDecider(threshold_dbm=-75, lock_secs=6.0)
        script = iter([-60, -90, -90, -90, -90])
        calls = []
        outcome = run_loop(
            lambda: next(script, -90),
            d,
            lock_fn=lambda: calls.append(1) or True,
            poll_secs=2.0,
            max_ticks=20,
            sleep_fn=lambda s: None,
            log_fn=lambda m: None,
        )
        self.assertEqual(outcome, "locked")
        self.assertEqual(len(calls), 1)


if __name__ == "__main__":
    unittest.main()
