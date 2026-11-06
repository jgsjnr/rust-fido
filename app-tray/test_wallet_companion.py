#!/usr/bin/env python3
"""Host-only tests for the F7 desktop wallet companion (no board, no net).

Run: ``python -m unittest test_wallet_companion -v`` from ``app-tray/``.
"""

from __future__ import annotations

import unittest

import wallet_companion as wc


class CompanionVocabularyTest(unittest.TestCase):
    def test_opcodes_match_sdk_facade(self) -> None:
        self.assertEqual(
            (wc.WALLET_OP_XPUB, wc.WALLET_OP_PSBT, wc.WALLET_OP_PENDING),
            (0x49, 0x4A, 0x4B),
        )
        self.assertEqual(tuple(wc.COMPANION_OPS), (0x49, 0x4A, 0x4B))
        for op in wc.COMPANION_OPS:
            self.assertTrue(wc.is_companion_opcode(op))
        for op in (0x00, 0x35, 0x36, 0x37, 0x48, 0x4C):
            self.assertFalse(wc.is_companion_opcode(op))

    def test_only_psbt_requires_app_approval(self) -> None:
        self.assertTrue(wc.requires_app_approval(wc.WALLET_OP_PSBT))
        self.assertFalse(wc.requires_app_approval(wc.WALLET_OP_PENDING))
        self.assertFalse(wc.requires_app_approval(wc.WALLET_OP_XPUB))

    def test_receipt_never_forges_approve(self) -> None:
        self.assertEqual(wc.receipt_for("approve", True), b"approve")
        self.assertIsNone(wc.receipt_for("approve", False))
        self.assertEqual(wc.receipt_for("deny", True), b"deny")
        self.assertEqual(wc.receipt_for("deny", False), b"deny")
        self.assertIsNone(wc.receipt_for("maybe", True))

    def test_preview_shape_validation(self) -> None:
        good = wc.PendingPreview(slot=3, tx_hash_hex="ab" * 32, inputs=1, outputs=2)
        self.assertTrue(good.is_well_formed())
        self.assertFalse(
            wc.PendingPreview(slot=32, tx_hash_hex="ab" * 32, inputs=1, outputs=2).is_well_formed()
        )
        self.assertFalse(
            wc.PendingPreview(slot=3, tx_hash_hex="AB" * 32, inputs=1, outputs=2).is_well_formed()
        )
        self.assertFalse(
            wc.PendingPreview(slot=3, tx_hash_hex="ab" * 31, inputs=1, outputs=2).is_well_formed()
        )
        self.assertFalse(
            wc.PendingPreview(slot=3, tx_hash_hex="ab" * 32, inputs=-1, outputs=2).is_well_formed()
        )

    def test_requests_stay_opaque_without_local_framing(self) -> None:
        req = wc.preview_request(3, "70736274")
        self.assertEqual(req, {"opcode": 0x4B, "slot": 3, "psbt_hex": "70736274"})
        self.assertIsNone(wc.preview_request(32, "70736274"))
        self.assertIsNone(wc.preview_request(3, ""))
        self.assertIsNone(wc.preview_request(3, "zz"))
        self.assertIsNone(wc.preview_request(3, "aa" * (wc.COMPANION_PSBT_MAX_BYTES + 1)))
        sign = wc.sign_request(3, "70736274", b"approve")
        self.assertEqual(sign["opcode"], 0x4A)
        self.assertEqual(sign["receipt"], b"approve")
        self.assertIsNone(wc.sign_request(3, "70736274", None))
        self.assertIsNone(wc.sign_request(3, "70736274", b"maybe"))
        self.assertIsNone(wc.sign_request(3, "70736274", b""))

    def test_status_set_is_closed(self) -> None:
        self.assertEqual(
            [wc.describe_status(s) for s in (0x00, 0x01, 0x02, 0x03, 0x04, 0x05)],
            ["Ok", "NeedUp", "NeedPin", "NoSlot", "BadEnvelope", "NeedBinding"],
        )
        self.assertEqual(wc.describe_status(0xFF), "Unknown")


if __name__ == "__main__":
    unittest.main()
