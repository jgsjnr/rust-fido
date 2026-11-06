#!/usr/bin/env python3
"""Unit tests: silicon-authoritative unlock via vendor 0x3B (no board, no push).

Proven bug: app said "PIN incorreto" for the correct PIN 1111 because the
unlock verdict never reached silicon (0x3B direct on silicon gives 0x00
while the bridge mirror says Unprovisioned and the app trusted it).

Contract under test (app-tray only, stdlib only):
- POST unlock goes to the device as POST /bridge/vendor opcode 0x3B with
  CBOR map(2){"action": "unlock", "pin": bytes(pin)}.
- The displayed verdict is the silicon's (status, CBOR) frame; the mirror
  (GET /api/secure-guard/status) is display-only fail-closed and never
  decides authentication.
- Silicon denial surfaces the real silicon error + attempt counters.

Run: python -m unittest test_unlock_silicon_authority -v
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path
from typing import Any, Dict, Optional

BASE_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(BASE_DIR))

from hardware_client import (
    OP_SECURE_GUARD_UNLOCK,
    AegisHardwareClient,
    SecureGuardStatus,
    _cbor_decode_unlock_response,
    _cbor_encode_unlock_request,
)


def _cbor_text(s: str) -> bytes:
    b = s.encode("utf-8")
    if len(b) < 24:
        return bytes([0x60 + len(b)]) + b
    assert len(b) < 256
    return bytes([0x78, len(b)]) + b


def _cbor_uint(v: int) -> bytes:
    assert v >= 0
    if v < 24:
        return bytes([v])
    if v < 256:
        return bytes([0x18, v])
    return bytes([0x19, (v >> 8) & 0xFF, v & 0xFF])


def _cbor_bool(v: bool) -> bytes:
    return bytes([0xF5 if v else 0xF4])


def _cbor_null() -> bytes:
    return bytes([0xF6])


def _cbor_response_map(fields: Dict[str, Any]) -> bytes:
    out = bytearray()
    out.append(0xA0 + len(fields))
    for k, v in fields.items():
        out.extend(_cbor_text(k))
        if v is None:
            out.extend(_cbor_null())
        elif isinstance(v, bool):
            out.extend(_cbor_bool(v))
        elif isinstance(v, int):
            out.extend(_cbor_uint(v))
        elif isinstance(v, str):
            out.extend(_cbor_text(v))
        else:  # pragma: no cover - test helper only
            raise AssertionError(f"unsupported test value for {k}: {v!r}")
    return bytes(out)


class _FakeSiliconClient(AegisHardwareClient):
    """AegisHardwareClient with canned bridge answers (no network, no board)."""

    def __init__(
        self,
        *,
        vendor_status: Optional[int],
        vendor_cbor: Optional[bytes],
        mirror: SecureGuardStatus,
    ) -> None:
        super().__init__(base_url="http://127.0.0.1:9")
        self._vendor_status = vendor_status
        self._vendor_cbor = vendor_cbor
        self._mirror = mirror
        self.seen_vendor_posts: list[Dict[str, Any]] = []

    def _http_post(self, path: str, payload: Optional[Dict[str, Any]] = None) -> Optional[Dict[str, Any]]:
        if path != "/bridge/vendor":
            raise AssertionError(f"unlock must use POST /bridge/vendor 0x3B, got {path}")
        self.seen_vendor_posts.append(dict(payload or {}))
        assert (payload or {}).get("opcode") == OP_SECURE_GUARD_UNLOCK == 0x3B
        req_hex = str((payload or {}).get("payload_hex") or "")
        req = bytes.fromhex(req_hex)
        # App-path parity: map(2) action=unlock pin=bytes.
        assert req[:1] == b"\xa2", f"CBOR map(2) header, got {req[:1].hex()}"
        assert b"action" in req and b"unlock" in req and b"pin" in req
        if self._vendor_status is None or self._vendor_cbor is None:
            return None  # silicon unreachable
        status = int(self._vendor_status)
        body_hex = bytes(self._vendor_cbor).hex()
        return {
            "ok": True,
            "opcode": OP_SECURE_GUARD_UNLOCK,
            "status": status,
            "payload_hex": body_hex,
            "response_hex": f"3b{status:02x}" + body_hex,
            "data_hex": body_hex,
        }

    def get_secure_guard_status(self) -> SecureGuardStatus:
        # Mirror is display-only; tests set it to Unprovisioned on purpose.
        return self._mirror


_MIRROR_UNPROVISIONED = SecureGuardStatus(
    state=0,
    state_name="Unprovisioned",
    provisioned=False,
    unlocked=False,
    connected=True,
    failed_attempts=0,
    remaining_attempts=5,
    max_attempts=5,
)


class TestSiliconAuthoritativeUnlock(unittest.TestCase):
    def test_request_bytes_match_app_path_for_pin_1111(self) -> None:
        req = _cbor_encode_unlock_request(b"1111")
        # Byte-identical to tools/app_path_replay.py app-bytes expectation.
        self.assertEqual(req.hex(), "a266616374696f6e66756e6c6f636b6370696e4431313131")

    def test_mirror_unprovisioned_silicon_ok_unlocks(self) -> None:
        """Mirror Unprovisioned + silicon 0x00/success -> UNLOCKED (silicon wins)."""
        silicon_cbor = _cbor_response_map({
            "success": True,
            "state": 4,
            "state_name": "Unlocked",
            "failed_attempts": 0,
            "remaining_attempts": 5,
            "max_attempts": 5,
            "rate_limit_remaining_ms": 0,
            "session_remaining_ms": 300000,
            "error": None,
        })
        client = _FakeSiliconClient(
            vendor_status=0x00, vendor_cbor=silicon_cbor, mirror=_MIRROR_UNPROVISIONED
        )
        res = client.unlock_secure_guard("1111")
        self.assertEqual(len(client.seen_vendor_posts), 1)
        self.assertTrue(res.get("ok"), f"silicon 0x00 must unlock, got {res}")
        self.assertTrue(res.get("silicon_authority"))
        self.assertEqual(res.get("transport"), "bridge-vendor-0x3B")
        self.assertEqual(res.get("opcode"), 0x3B)
        self.assertTrue(res.get("unlocked"))
        self.assertEqual(res.get("state_name"), "Unlocked")

    def test_silicon_denies_shows_real_error_and_counter(self) -> None:
        """Silicon denial -> ok False with the real silicon error + counters."""
        real_error = "Invalid PIN (1/5). Backoff 1s"
        silicon_cbor = _cbor_response_map({
            "success": False,
            "state": 6,
            "state_name": "RateLimited",
            "failed_attempts": 1,
            "remaining_attempts": 4,
            "max_attempts": 5,
            "rate_limit_remaining_ms": 1000,
            "error": real_error,
        })
        client = _FakeSiliconClient(
            vendor_status=0x00, vendor_cbor=silicon_cbor, mirror=_MIRROR_UNPROVISIONED
        )
        res = client.unlock_secure_guard("0000")
        self.assertFalse(res.get("ok"))
        self.assertTrue(res.get("silicon_authority"))
        # Real silicon error verbatim, not the mirror "Not provisioned".
        self.assertEqual(res.get("error"), real_error)
        self.assertNotIn("provision", str(res.get("error")).lower())
        # Authoritative counters verbatim.
        self.assertEqual(res.get("failed_attempts"), 1)
        self.assertEqual(res.get("remaining_attempts"), 4)
        self.assertFalse(res.get("unlocked"))

    def test_silicon_unreachable_fail_closed_never_claims_unlocked(self) -> None:
        """No silicon frame -> fail-closed, mirror attached display-only."""
        client = _FakeSiliconClient(
            vendor_status=None, vendor_cbor=None, mirror=_MIRROR_UNPROVISIONED
        )
        res = client.unlock_secure_guard("1111")
        self.assertFalse(res.get("ok"))
        self.assertFalse(res.get("silicon_authority"))
        self.assertFalse(res.get("unlocked"))
        self.assertEqual(res.get("mirror_state_name"), "Unprovisioned")

    def test_cbor_decode_rejects_non_map(self) -> None:
        self.assertIsNone(_cbor_decode_unlock_response(b""))
        self.assertIsNone(_cbor_decode_unlock_response(bytes([0x66, 0x75, 0x6E, 0x6C, 0x6F, 0x63, 0x6B])))


if __name__ == "__main__":
    unittest.main(verbosity=2)
