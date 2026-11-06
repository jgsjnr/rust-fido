#!/usr/bin/env python3
"""Stub tests for POST /api/secure-guard/unlock silicon verdict (0x3B strict).

No hardware, no push, no eFuse/secure-boot touched: HW_MANAGER.send_vendor_strict
and SECURE_GUARD_ENGINE are stubbed in-memory.
"""

import json
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import host_hardware_android_bridge as bridge


def _cbor_unlock_payload(success, failed=0, remaining=5, state_name="Unlocked", state=0x04):
    return bridge.cbor_encode({
        "success": success,
        "state": state,
        "state_name": state_name,
        "failed_attempts": failed,
        "remaining_attempts": remaining,
        "rate_limit_remaining_ms": 0,
        "error": None if success else "Invalid PIN",
    })


class _FakeHandler:
    """Minimal stand-in for DualProtocolHandler unlock block."""

    def __init__(self, pin="1234"):
        self.pin = pin
        self.sent = None
        self.code = None

    def send_json(self, obj, status_code=200):
        self.sent = obj
        self.code = status_code

    def run_unlock(self):
        # Mirrors do_POST /api/secure-guard/unlock logic under test.
        pin = self.pin
        ecdh_used = False
        cbor_payload = bridge.cbor_encode({"action": "unlock", "pin": pin.encode("utf-8")})
        silicon_reachable = False
        hw_status = None
        hw_verdict = {}
        silicon_error = None
        try:
            hw_status, hw_payload = bridge.HW_MANAGER.send_vendor_strict(0x3B, cbor_payload, timeout_s=4.0)
            silicon_reachable = True
            hw_verdict = bridge.parse_silicon_unlock_verdict(hw_status, hw_payload)
        except Exception as ex:  # noqa: BLE001 - stub asserts fail-closed path
            silicon_error = str(ex)
        if not silicon_reachable:
            fallback = bridge.SECURE_GUARD_ENGINE.get_status_dict()
            self.send_json({
                "ok": False,
                "success": False,
                "silicon_reachable": False,
                "silicon_status": None,
                "status": None,
                "state": fallback.get("state"),
                "state_name": fallback.get("state_name"),
                "failed_attempts": fallback.get("failed_attempts"),
                "remaining_attempts": fallback.get("remaining_attempts"),
                "rate_limit_remaining_ms": fallback.get("rate_limit_remaining_ms", 0),
                "ecdh_encrypted_channel": ecdh_used,
                "error": f"silicon unreachable (fail-closed): {silicon_error}",
            }, status_code=503)
            return
        silicon = hw_verdict.get("silicon") or {}
        try:
            bridge.SECURE_GUARD_ENGINE.unlock(pin)
        except Exception:
            pass
        ok = bool(silicon.get("success", hw_status == 0x00 and silicon.get("state_name") == "Unlocked"))
        compat = {
            "ok": ok,
            "success": bool(silicon.get("success", ok)),
            "silicon_reachable": True,
            "silicon_status": hw_status,
            "status": hw_status,
            "state": silicon.get("state"),
            "state_name": silicon.get("state_name"),
            "failed_attempts": hw_verdict.get("failed_attempts"),
            "remaining_attempts": hw_verdict.get("remaining_attempts"),
            "rate_limit_remaining_ms": silicon.get("rate_limit_remaining_ms", 0),
            "ecdh_encrypted_channel": ecdh_used,
            "error": silicon.get("error"),
        }
        self.send_json(compat, status_code=200 if ok else 401)


class SiliconUnlockTests(unittest.TestCase):
    def setUp(self):
        self._orig_strict = bridge.HW_MANAGER.send_vendor_strict
        self._orig_engine = bridge.SECURE_GUARD_ENGINE

    def tearDown(self):
        bridge.HW_MANAGER.send_vendor_strict = self._orig_strict
        bridge.SECURE_GUARD_ENGINE = self._orig_engine

    def _stub_engine(self):
        class Eng:
            def get_status_dict(self):
                return {"state": 0x02, "state_name": "Locked",
                        "failed_attempts": 1, "remaining_attempts": 4,
                        "rate_limit_remaining_ms": 0}

            def unlock(self, pin):
                return {"success": True}
        bridge.SECURE_GUARD_ENGINE = Eng()

    def test_silicon_success_authoritative(self):
        bridge.HW_MANAGER.send_vendor_strict = lambda op, pl, timeout_s=4.0: (
            0x00, _cbor_unlock_payload(True, failed=0, remaining=5))
        self._stub_engine()
        h = _FakeHandler(pin="1234")
        h.run_unlock()
        self.assertEqual(h.code, 200)
        self.assertTrue(h.sent["ok"])
        self.assertTrue(h.sent["silicon_reachable"])
        self.assertEqual(h.sent["silicon_status"], 0x00)
        self.assertEqual(h.sent["status"], 0x00)
        self.assertEqual(h.sent["failed_attempts"], 0)
        self.assertEqual(h.sent["remaining_attempts"], 5)
        # compat fields present
        for k in ("ok", "success", "state", "state_name", "failed_attempts",
                  "remaining_attempts", "rate_limit_remaining_ms",
                  "ecdh_encrypted_channel", "error"):
            self.assertIn(k, h.sent, k)

    def test_silicon_failure_counters(self):
        bridge.HW_MANAGER.send_vendor_strict = lambda op, pl, timeout_s=4.0: (
            0x00, _cbor_unlock_payload(False, failed=2, remaining=3,
                                       state_name="Locked", state=0x02))
        self._stub_engine()
        h = _FakeHandler(pin="wrong")
        h.run_unlock()
        self.assertEqual(h.code, 401)
        self.assertFalse(h.sent["ok"])
        self.assertEqual(h.sent["failed_attempts"], 2)
        self.assertEqual(h.sent["remaining_attempts"], 3)

    def test_unreachable_fail_closed(self):
        def _boom(op, pl, timeout_s=4.0):
            raise ConnectionError("no silicon (stub)")
        bridge.HW_MANAGER.send_vendor_strict = _boom
        self._stub_engine()
        h = _FakeHandler(pin="1234")
        h.run_unlock()
        self.assertEqual(h.code, 503)
        self.assertFalse(h.sent["ok"])
        self.assertFalse(h.sent["success"])
        self.assertFalse(h.sent["silicon_reachable"])
        self.assertIn("fail-closed", h.sent["error"])

    def test_parse_unparseable_stays_fail_closed_safe(self):
        out = bridge.parse_silicon_unlock_verdict(0x00, b"\xff\xff")
        self.assertIsNone(out["failed_attempts"])
        self.assertIsNone(out["remaining_attempts"])
        self.assertIsNotNone(out["decode_error"])


if __name__ == "__main__":
    unittest.main()
