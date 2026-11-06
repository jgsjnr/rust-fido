#!/usr/bin/env python3
"""Tests for POST /bridge/text_line (allowlist, timeout, no-hardware stub).

No physical hardware required: HardwareBridgeManager.send_text_line is
exercised against an in-memory serial stub. Never flashes firmware.
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from host_hardware_android_bridge import (
    TEXT_LINE_ALLOWLIST,
    HardwareBridgeManager,
    validate_text_line,
)


class FakeLink:
    def __init__(self, ack_bytes=b"up_latched source=software\n", hang=False):
        self.ack_bytes = ack_bytes
        self.hang = hang
        self.written = b""
        self.flushed = False
        self._pos = 0

    def flush_input(self):
        self.flushed = True

    def write(self, data):
        self.written += bytes(data)

    def read_exact(self, n, deadline_s=1.0):
        if self.hang or self._pos >= len(self.ack_bytes):
            raise TimeoutError("no data (stub)")
        chunk = self.ack_bytes[self._pos:self._pos + n]
        self._pos += n
        return chunk


class FakeSession:
    def __init__(self, link):
        self.link = link


class ValidateTextLineTests(unittest.TestCase):
    def test_allowlist_accepts_all_documented_hooks(self):
        expected = {
            "TEST_UP", "TEST_DOWNLOAD", "TEST_USB_RECONNECT",
            "TEST_PAIRING_OPEN", "TEST_PAIRING_OPEN_300", "TEST_PAIRING_CLOSE",
            "TEST_LIFETIME_DUMP", "TEST_LED_STATE", "TEST_LED_RED",
            "TEST_LED_GREEN", "TEST_LED_BLUE", "TEST_LED_OFF",
            "TEST_LED_RELEASE", "TEST_BENCH_ON", "TEST_BENCH_OFF",
            "TEST_OTA_COMMIT_HOOK", "TEST_BLE_PREINIT",
        }
        self.assertTrue(expected.issubset(TEXT_LINE_ALLOWLIST))
        for hook in expected:
            ok, cleaned = validate_text_line(hook)
            self.assertTrue(ok, hook)
            self.assertEqual(cleaned, hook)

    def test_rejects_missing_prefix(self):
        ok, _ = validate_text_line("up_latched source=software")
        self.assertFalse(ok)
        ok, _ = validate_text_line("PAIRING_OPEN")
        self.assertFalse(ok)

    def test_rejects_unknown_test_hook(self):
        for bad in ("TEST_RM_RF", "TEST_UP_EXTRA", "TEST_", "TEST_PAIRING_OPEN ", "TEST_UP\nDROP"):
            if bad.strip() in TEXT_LINE_ALLOWLIST:
                continue
            ok, _ = validate_text_line(bad)
            # "TEST_PAIRING_OPEN " strips to an allowlisted hook -> accepted
            if bad.strip() in TEXT_LINE_ALLOWLIST:
                self.assertTrue(ok)
            else:
                self.assertFalse(ok, bad)

    def test_rejects_non_string(self):
        for bad in (None, 123, b"TEST_UP", ["TEST_UP"]):
            ok, _ = validate_text_line(bad)
            self.assertFalse(ok)

    def test_rejects_empty(self):
        ok, _ = validate_text_line("")
        self.assertFalse(ok)

    def test_strips_whitespace(self):
        ok, cleaned = validate_text_line("  TEST_UP\n")
        self.assertTrue(ok)
        self.assertEqual(cleaned, "TEST_UP")


class SendTextLineTests(unittest.TestCase):
    def _manager_with_stub(self, link):
        mgr = HardwareBridgeManager.__new__(HardwareBridgeManager)
        import threading
        mgr.lock = threading.Lock()
        mgr.transport = "UART"
        mgr.session = FakeSession(link)
        mgr.is_connected = True
        mgr.ensure_connected = lambda: None
        return mgr

    def test_writes_line_to_serial_and_returns_ack(self):
        link = FakeLink()
        mgr = self._manager_with_stub(link)
        ack = mgr.send_text_line("TEST_UP", timeout_s=2.0)
        self.assertEqual(link.written, b"TEST_UP\n")
        self.assertTrue(link.flushed)
        self.assertIn("up_latched", ack)

    def test_timeout_without_ack(self):
        link = FakeLink(hang=True)
        mgr = self._manager_with_stub(link)
        with self.assertRaises(TimeoutError):
            mgr.send_text_line("TEST_UP", timeout_s=0.5)

    def test_no_hardware_stub_without_uart(self):
        import threading
        mgr = HardwareBridgeManager.__new__(HardwareBridgeManager)
        mgr.lock = threading.Lock()
        mgr.transport = None
        mgr.session = None
        mgr.is_connected = False
        mgr.ensure_connected = lambda: (_ for _ in ()).throw(
            ConnectionError("Chave fisica AegisKey nao encontrada"))
        with self.assertRaises(ConnectionError):
            mgr.send_text_line("TEST_UP", timeout_s=0.5)

    def test_usb_transport_rejected(self):
        link = FakeLink()
        mgr = self._manager_with_stub(link)
        mgr.transport = "USB"
        with self.assertRaises(ConnectionError):
            mgr.send_text_line("TEST_UP", timeout_s=0.5)


if __name__ == "__main__":
    unittest.main()
