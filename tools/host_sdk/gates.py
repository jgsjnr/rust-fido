"""Fail-closed gates: binding -> UP -> PIN. Sanitized logs only (no secrets)."""
from __future__ import annotations

import time as _time

from tools.host_sdk import ops as _ops

NEED_BINDING = 0x05
NEED_UP = 0x01
NEED_PIN = 0x02
BAD_ENVELOPE = 0x04

PRIVILEGED = frozenset((
    "make_credential", "pin_set", "pin_change", "key_gen", "key_import",
    "key_delete", "oath_put", "oath_delete", "wifi_config",
))

_LOG = []


def log_event(name: str, detail: str = "") -> None:
    _LOG.append((_time.time(), name, detail))
    print("[log] %s%s" % (name, (" " + detail) if detail else ""))


def _sanitize_label(label) -> str:
    if isinstance(label, (bytes, bytearray)):
        return "label_bytes=%d" % len(label)
    return "label_bytes=%d" % len(str(label))


class GateDenied(PermissionError):
    def __init__(self, status: int, reason: str) -> None:
        super().__init__(reason)
        self.status = status


def check_pairing_window(op: str, pairing_open: bool) -> None:
    if op in PRIVILEGED and not pairing_open:
        log_event("GATE_PAIRING_DENIED", "op=%s" % op)
        raise GateDenied(BAD_ENVELOPE, "pairing-mode required")


def check_binding(binding_ok: bool, op: str = "") -> None:
    if not binding_ok:
        log_event("GATE_BINDING_DENIED", "op=%s" % op)
        raise GateDenied(NEED_BINDING, "binding required (NEED_BINDING 0x05)")


def check_up(presence: bool, op: str = "") -> None:
    if not presence:
        log_event("GATE_UP_DENIED", "op=%s" % op)
        raise GateDenied(NEED_UP, "presence required")


def check_pin(opcode: int, pin_ok: bool, op: str = "") -> None:
    if opcode in _ops.VENDOR_PRIVILEGED and not pin_ok:
        log_event("GATE_PIN_DENIED", "op=%s" % op)
        raise GateDenied(NEED_PIN, "pin required")


def authorize_config_op(opcode: int, binding_ok: bool, presence: bool,
                        pin_ok: bool, op: str = "") -> None:
    """Canonical order binding -> UP -> PIN (fail-closed, no secrets logged)."""
    check_binding(binding_ok, op)
    check_up(presence, op)
    check_pin(opcode, pin_ok, op)
    log_event("GATE_OK", "op=%s opcodes=1" % op)


def authorize_usage_op(presence: bool, op: str = "") -> None:
    """Usage ops (LIST/CODE): UP only, never binding."""
    check_up(presence, op)
    log_event("GATE_OK", "op=%s" % op)


def authorize_fw_log(bonded: bool) -> None:
    if not bonded:
        log_event("GATE_BINDING_DENIED", "op=fw_log")
        raise GateDenied(NEED_BINDING, "binding required (NEED_BINDING 0x05)")
    log_event("GATE_OK", "op=fw_log")
