"""Decision-logic tests for linux proximity_agent (no hardware, no Linux)."""

import sys
import os
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from proximity_agent import ProximityDecider, run_loop, lock_session
from proximity_agent import (
    _device_rssi,
    _match_bonded_device,
    _normalize_ble_address,
    make_polling_source,
)


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
        self.assertFalse(d.update(-90, 2.0))
        away = d.away_secs
        self.assertFalse(d.update(-72, 2.0))
        self.assertEqual(d.away_secs, away)
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
        self.assertFalse(d.update(-90, 2.0))
        self.assertTrue(d.locked)
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

    def test_lock_session_rejects_non_linux(self):
        with mock.patch.object(sys, "platform", "win32"):
            with self.assertRaises(OSError):
                lock_session()


class FakeDevice:
    def __init__(self, address="", rssi=None, metadata=None):
        self.address = address
        self.rssi = rssi
        self.metadata = metadata or {}


class TestBondedBackend(unittest.TestCase):
    def test_normalize_address_case_and_space(self):
        self.assertEqual(_normalize_ble_address(" AA:BB:CC:DD:EE:FF "), "aa:bb:cc:dd:ee:ff")
        self.assertEqual(_normalize_ble_address("aa:bb:cc:dd:ee:ff"), "aa:bb:cc:dd:ee:ff")
        self.assertEqual(_normalize_ble_address(""), "")

    def test_match_bonded_device_exact_address(self):
        devices = [FakeDevice("AA:BB:CC:DD:EE:00"), FakeDevice("AA:BB:CC:DD:EE:FF")]
        hit = _match_bonded_device(devices, "aa:bb:cc:dd:ee:ff")
        self.assertIsNotNone(hit)
        self.assertEqual(hit.address, "AA:BB:CC:DD:EE:FF")

    def test_match_bonded_device_no_match_returns_none(self):
        devices = [FakeDevice("AA:BB:CC:DD:EE:00")]
        self.assertIsNone(_match_bonded_device(devices, "AA:BB:CC:DD:EE:FF"))
        self.assertIsNone(_match_bonded_device([], "AA:BB:CC:DD:EE:FF"))

    def test_device_rssi_prefers_device_field(self):
        d = FakeDevice("AA:BB:CC:DD:EE:FF", rssi=-70, metadata={"rssi": -99})
        self.assertEqual(_device_rssi(d, None), -70)

    def test_device_rssi_falls_back_to_advertisement(self):
        d = FakeDevice("AA:BB:CC:DD:EE:FF")
        self.assertEqual(_device_rssi(d, {"rssi": -80}), -80)
        d2 = FakeDevice("AA:BB:CC:DD:EE:FF", metadata={"rssi": -81})
        self.assertEqual(_device_rssi(d2, None), -81)

    def test_device_rssi_none_when_hidden(self):
        d = FakeDevice("AA:BB:CC:DD:EE:FF")
        self.assertIsNone(_device_rssi(d, None))

    def test_make_polling_source_rejects_empty_fob_id_fail_closed(self):
        with self.assertRaises(OSError):
            make_polling_source("")

    def test_make_polling_source_accepts_valid_fob_id(self):
        src = make_polling_source("AA:BB:CC:DD:EE:FF", scanner=lambda: [])
        self.assertTrue(callable(src))

    def test_make_polling_source_returns_rssi_for_bonded_device(self):
        bonded = FakeDevice("AA:BB:CC:DD:EE:FF", rssi=-70)
        stranger = FakeDevice("AA:BB:CC:DD:EE:00", rssi=-40)
        src = make_polling_source(
            "aa:bb:cc:dd:ee:ff", scanner=lambda: [stranger, bonded]
        )
        self.assertEqual(src(), -70)

    def test_make_polling_source_returns_none_when_bonded_missing_fail_closed(self):
        src = make_polling_source(
            "AA:BB:CC:DD:EE:FF",
            scanner=lambda: [FakeDevice("AA:BB:CC:DD:EE:00", rssi=-40)],
        )
        self.assertIsNone(src())

    def test_make_polling_source_propagates_transport_error_fail_closed(self):
        def boom():
            raise OSError("BLE down")

        src = make_polling_source("AA:BB:CC:DD:EE:FF", scanner=boom)
        with self.assertRaises(OSError):
            src()

    def test_bonded_source_drives_lock_only_on_away(self):
        src = make_polling_source(
            "AA:BB:CC:DD:EE:FF",
            scanner=lambda: [FakeDevice("AA:BB:CC:DD:EE:00", rssi=-40)],
        )
        d = ProximityDecider(threshold_dbm=-75, lock_secs=6.0)
        calls = []
        outcome = run_loop(
            src,
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
