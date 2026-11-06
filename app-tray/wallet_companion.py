#!/usr/bin/env python3
"""AegisKey wallet companion flows (F7, desktop side, facade-first).

Thin stdlib-only vocabulary mirror over the ``universal-device-sdk``
companion contract: the desktop tray never frames TLV, never derives keys
and never signs — it only validates display fields, gates the approval
receipt on an explicit owner decision, and passes opaque PSBT bytes through
the local bridge daemon (``hardware_client`` HTTP), which frames them
device-side. Single source of truth for framing stays in the Rust SDK;
every constant below is a documented copy with a parity test in
``test_wallet_companion.py``.

Fail-closed: malformed shapes return ``None``/``False`` (never a forged
``approve``); wire statuses follow the closed §9.5 set.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Optional

#: Watch-only xpub export opcode (SDK ``WALLET_OP_XPUB``).
WALLET_OP_XPUB: int = 0x49
#: PSBT signing opcode (SDK ``WALLET_OP_PSBT``; needs app-mediated approval).
WALLET_OP_PSBT: int = 0x4A
#: Pending-preview opcode (SDK ``WALLET_OP_PENDING``; display first).
WALLET_OP_PENDING: int = 0x4B

#: Companion round-trip opcodes (xpub watch-only + PSBT sign + preview).
COMPANION_OPS: tuple = (WALLET_OP_XPUB, WALLET_OP_PSBT, WALLET_OP_PENDING)

#: Wallet slots addressable by companions (firmware ``WalletStore``).
COMPANION_MAX_SLOTS: int = 32

#: Max PSBT bytes per companion envelope (bridge transport ceiling).
COMPANION_PSBT_MAX_BYTES: int = 512

#: Approval receipt sent after an explicit owner approve (SDK ``approve``).
RECEIPT_APPROVE: bytes = b"approve"
#: Explicit deny receipt (any non-``approve`` value denies device-side).
RECEIPT_DENY: bytes = b"deny"

#: Closed wire status set (§9.5): never extended here.
STATUS_NAMES: Dict[int, str] = {
    0x00: "Ok",
    0x01: "NeedUp",
    0x02: "NeedPin",
    0x03: "NoSlot",
    0x04: "BadEnvelope",
    0x05: "NeedBinding",
}


def is_companion_opcode(op: int) -> bool:
    """True for the F7 companion round-trip surface (xpub/PSBT/preview)."""
    return op in COMPANION_OPS


def requires_app_approval(op: int) -> bool:
    """True only for PSBT signing (the preview never needs approval)."""
    return op == WALLET_OP_PSBT


def describe_status(status: int) -> str:
    """Names a wire status byte for logs only (never attached to payloads)."""
    return STATUS_NAMES.get(status, "Unknown")


@dataclass(frozen=True)
class PendingPreview:
    """Display-only pending summary (public metadata, never secrets)."""

    slot: int
    tx_hash_hex: str
    inputs: int
    outputs: int

    def is_well_formed(self) -> bool:
        """Strict display shape: slot ``0..32``, 64 lowercase hex, counts."""
        if not 0 <= self.slot < COMPANION_MAX_SLOTS:
            return False
        if len(self.tx_hash_hex) != 64 or any(
            c not in "0123456789abcdef" for c in self.tx_hash_hex
        ):
            return False
        if self.inputs < 0 or self.outputs < 0:
            return False
        return True


def receipt_for(decision: str, biometric_ok: bool) -> Optional[bytes]:
    """Receipt bytes for an owner decision, gated on a live biometric.

    ``"approve"`` yields the approve receipt ONLY with ``biometric_ok`` —
    without it nothing is sent (``None``), never a forged approve.
    ``"deny"`` always yields the explicit deny receipt (safe to withdraw).
    Unknown decisions yield ``None`` (fail-closed).
    """
    if decision == "deny":
        return RECEIPT_DENY
    if decision == "approve" and biometric_ok:
        return RECEIPT_APPROVE
    return None


def preview_request(slot: int, psbt_hex: str) -> Optional[Dict[str, object]]:
    """Opaque preview request through the bridge daemon (no local framing).

    Returns ``{"opcode", "slot", "psbt_hex"}`` for ``hardware_client`` to
    forward; the TLV framing happens device-side. ``None`` on malformed
    shapes (bad slot, empty/odd-hex/oversize PSBT).
    """
    raw = _decode_psbt_hex(psbt_hex)
    if raw is None or not 0 <= slot < COMPANION_MAX_SLOTS:
        return None
    return {"opcode": WALLET_OP_PENDING, "slot": slot, "psbt_hex": psbt_hex.lower()}


def sign_request(slot: int, psbt_hex: str, receipt: Optional[bytes]) -> Optional[Dict[str, object]]:
    """Opaque sign request through the bridge daemon (no local framing).

    ``receipt`` must be exactly ``approve``/``deny``; anything else (incl.
    ``None``) yields ``None`` — the companion sends nothing unapproved.
    """
    raw = _decode_psbt_hex(psbt_hex)
    if raw is None or not 0 <= slot < COMPANION_MAX_SLOTS:
        return None
    if receipt not in (RECEIPT_APPROVE, RECEIPT_DENY):
        return None
    return {
        "opcode": WALLET_OP_PSBT,
        "slot": slot,
        "psbt_hex": psbt_hex.lower(),
        "receipt": bytes(receipt),
    }


def _decode_psbt_hex(psbt_hex: str) -> Optional[bytes]:
    try:
        raw = bytes.fromhex(psbt_hex or "")
    except (ValueError, TypeError):
        return None
    if not raw or len(raw) > COMPANION_PSBT_MAX_BYTES:
        return None
    return raw
