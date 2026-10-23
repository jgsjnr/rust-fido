"""Decision-logic tests for macos proximity_agent (no hardware, no macOS)."""

import sys
import os
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from proximity_agent import ProximityDecider, run_loop, lock_session
from proximity_agent import (
    PROXIMITY_MAX_CTR_JUMP,
    RollingCodeVerifier,
    _device_adv_payload,
    _device_rssi,
    _match_bonded_device,
    _normalize_ble_address,
    make_polling_source,
    parse_proximity_payload,
    verify_proximity_tag,
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

    def test_lock_session_rejects_non_macos(self):
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
        import proximity_agent as pa

        payload = bytes([0x01]) + int(1).to_bytes(4, "little") + b"\x09\x09\x09\x09"
        bonded = FakeDevice(
            "AA:BB:CC:DD:EE:FF",
            rssi=-70,
            metadata={"service_data": {pa.PROXIMITY_SERVICE_UUID_STR: payload}},
        )
        stranger = FakeDevice("AA:BB:CC:DD:EE:00", rssi=-40)
        src = make_polling_source(
            "aa:bb:cc:dd:ee:ff",
            scanner=lambda: [stranger, bonded],
            verifier=RollingCodeVerifier(tag_fn=lambda c, t: True),
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


def _payload(ctr, ver=0x01, tag=b"\x09\x09\x09\x09"):
    return bytes([ver]) + int(ctr).to_bytes(4, "little") + bytes(tag)


class TestRollingCode(unittest.TestCase):
    def test_parse_valid_payload_ver_ctr_tag(self):
        self.assertEqual(
            parse_proximity_payload(bytes([0x01, 7, 0, 0, 0, 1, 2, 3, 4])),
            (0x01, 7, b"\x01\x02\x03\x04"),
        )

    def test_parse_rejects_bad_length(self):
        self.assertIsNone(parse_proximity_payload(b"short"))
        self.assertIsNone(parse_proximity_payload(None))
        self.assertIsNone(parse_proximity_payload(bytes(9 + 1)))

    def test_verifier_accepts_increasing_ctr_with_tag_fn(self):
        v = RollingCodeVerifier(tag_fn=lambda ctr, tag: True)
        self.assertTrue(v.verify(_payload(1)))
        self.assertTrue(v.verify(_payload(2)))

    def test_verifier_rejects_replay_and_reorder_fail_closed(self):
        v = RollingCodeVerifier(tag_fn=lambda ctr, tag: True)
        self.assertTrue(v.verify(_payload(5)))
        self.assertFalse(v.verify(_payload(5)))
        self.assertFalse(v.verify(_payload(4)))

    def test_verifier_rejects_unknown_ver_fail_closed(self):
        v = RollingCodeVerifier(tag_fn=lambda ctr, tag: True)
        self.assertFalse(v.verify(_payload(6, ver=0x02)))

    def test_verifier_rejects_jump_over_max_fail_closed(self):
        v = RollingCodeVerifier(tag_fn=lambda ctr, tag: True)
        self.assertTrue(v.verify(_payload(1)))
        self.assertFalse(v.verify(_payload(1 + PROXIMITY_MAX_CTR_JUMP + 1)))
        self.assertTrue(v.verify(_payload(2)))

    def test_verifier_rejects_bad_tag_fail_closed(self):
        v = RollingCodeVerifier(tag_fn=lambda ctr, tag: False)
        self.assertFalse(v.verify(_payload(1)))
        self.assertFalse(verify_proximity_tag(1, b"1234", None))

    def test_verifier_rejects_missing_sample_unavailable_fail_closed(self):
        v = RollingCodeVerifier(tag_fn=lambda c, t: True)
        self.assertFalse(v.verify(None))  # Unavailable fail-closed (lock-only)

    def test_poll_returns_none_on_replay_fail_closed(self):
        from types import SimpleNamespace as NS

        payload = _payload(9)
        dev = NS(
            address="AA:BB:CC:DD:EE:FF",
            rssi=-60,
            metadata={"service_data": {"0000fffe-0000-1000-8000-00805f9a34fb": payload}},
        )
        verifier = RollingCodeVerifier(tag_fn=lambda ctr, tag: True)
        src = make_polling_source(
            "AA:BB:CC:DD:EE:FF", scanner=lambda: [dev], verifier=verifier
        )
        self.assertEqual(src(), -60)
        self.assertIsNone(src())

    def test_poll_returns_none_when_rssi_missing(self):
        from types import SimpleNamespace as NS

        src = make_polling_source(
            "AA:BB:CC:DD:EE:FF",
            scanner=lambda: [NS(address="AA:BB:CC:DD:EE:FF", metadata={})],
            verifier=RollingCodeVerifier(tag_fn=lambda c, t: True),
        )
        self.assertIsNone(src())

    def test_adv_payload_from_service_data_fffe_ignores_fffd(self):
        from types import SimpleNamespace as NS

        payload = _payload(3)
        dev = NS(
            address="AA:BB:CC:DD:EE:FF",
            rssi=-60,
            metadata={"service_data": {"0000fffe-0000-1000-8000-00805f9a34fb": payload}},
        )
        self.assertEqual(_device_adv_payload(dev), payload)
        dev_fffd = NS(
            address="AA:BB:CC:DD:EE:FF",
            rssi=-60,
            metadata={"service_data": {"0000fffd-0000-1000-8000-00805f9a34fb": payload}},
        )
        self.assertIsNone(_device_adv_payload(dev_fffd))

    def test_bleak_scan_missing_dep_raises_fail_closed(self):
        import proximity_agent as pa

        real = sys.modules.get("bleak")
        sys.modules["bleak"] = None
        try:
            with self.assertRaises(OSError):
                pa._bleak_scan("AA:BB:CC:DD:EE:FF")
        finally:
            if real is not None:
                sys.modules["bleak"] = real
            else:
                del sys.modules["bleak"]


if __name__ == "__main__":
    unittest.main()

class TestFirmwareTagVector(unittest.TestCase):
    def test_fob_id_bytes_mac(self):
        import proximity_agent as pa

        self.assertEqual(pa._fob_id_bytes("AA:BB:CC:DD:EE:FF"), bytes([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]))
        self.assertEqual(pa._fob_id_bytes("aa:bb:cc:dd:ee:ff"), bytes([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]))
        with self.assertRaises(OSError):
            pa._fob_id_bytes("not-a-mac")
        with self.assertRaises(OSError):
            pa._fob_id_bytes("AA:BB:CC:DD:EE")

    def test_ccm_tag_real_vector_ctr7(self):
        import proximity_agent as pa

        key = bytes([0x42]) * 16
        fob = pa._fob_id_bytes("AA:BB:CC:DD:EE:FF")
        tag = pa._ccm_tag(key, 0x01, 7, fob)
        self.assertEqual(len(tag), 4)
        self.assertEqual(tag, pa._ccm_tag(key, 0x01, 7, fob))  # deterministico
        self.assertNotEqual(tag, pa._ccm_tag(key, 0x01, 8, fob))
        self.assertTrue(pa.verify_proximity_tag(7, tag, key, fob))
        self.assertFalse(pa.verify_proximity_tag(7, b"\x00\x00\x00\x00", key, fob))
        self.assertFalse(pa.verify_proximity_tag(8, tag, key, fob))
        self.assertFalse(pa.verify_proximity_tag(7, tag, key, pa._fob_id_bytes("AA:BB:CC:DD:EE:00")))
        self.assertFalse(pa.verify_proximity_tag(7, tag, None, fob))  # sem chave => fail-closed
        self.assertFalse(pa.verify_proximity_tag(7, tag, key, None))  # sem fob => fail-closed

    def test_verifier_real_key_and_fob(self):
        import proximity_agent as pa

        key = bytes([0x42]) * 16
        fob = "AA:BB:CC:DD:EE:FF"
        tag = pa._ccm_tag(key, 0x01, 7, pa._fob_id_bytes(fob))
        payload = bytes([0x01]) + int(7).to_bytes(4, "little") + bytes(tag)
        v = pa.RollingCodeVerifier(key=key, fob_id=fob)
        self.assertTrue(v.verify(payload))
        self.assertEqual(v.last_reason, "Ok")
        self.assertFalse(v.verify(payload))  # replay
        self.assertEqual(v.last_reason, "Replay")


if __name__ == "__main__":
    unittest.main()
