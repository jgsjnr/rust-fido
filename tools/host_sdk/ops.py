"""Op builders: wallet / vendor / rescue / fw-log (stdlib-only, no I/O)."""
from __future__ import annotations

from tools.host_sdk import tlv as _t

OP_KEY_GEN = 0x20
OP_KEY_IMPORT = 0x21
OP_KEY_LIST = 0x22
OP_KEY_DELETE = 0x23
OP_OATH_PUT = 0x24
OP_OATH_LIST = 0x25
OP_OATH_CODE = 0x26
OP_OATH_DELETE = 0x27

OP_WALLET_GEN = 0x35
OP_WALLET_LIST = 0x36
OP_WALLET_ADDR = 0x37

# F3: OTA range 0x30-0x34 + reserved 0x2F (map ble_gatt.rs wallet section).
OP_RESERVED_2F = 0x2F
OP_OTA_BEGIN = 0x30
OP_OTA_CHUNK = 0x31
OP_OTA_VERIFY = 0x32
OP_OTA_COMMIT = 0x33
OP_OTA_ABORT = 0x34

# F3: PIV AID + INS set (CCID path, fuera enroll 0x39). No firmware touch.
# Oath-data INS 01/02/03/04/A1-A4 + PIV VERIFY 0x20 + SELECT 0xA4.
PIV_AID = bytes((0xA0, 0x00, 0x00, 0x05, 0x27, 0x21, 0x01))
PIV_INS = frozenset((0x01, 0x02, 0x03, 0x04, 0xA1, 0xA2, 0xA3, 0xA4))
PIV_EXTRA_INS = frozenset((0x20, 0xA4))  # VERIFY + SELECT

# F3: proximity service 0xFFFE (never FFF1-FFF4).
PROXIMITY_SERVICE = 0xFFFE

# F3: rescue killswitch (never execute here; jig+HSM only).
RESCUE_CMD_KILLSWITCH = 0x06
KILLSWITCH_CONFIRM = "WIPE-ACK"

# F3: external OTP routes (honest 6D00 outside scope).
EXT_ROUTES = frozenset(("ykman", "nitrokey", "yubiotp"))
EXT_STATUS_6D00 = bytes((0x6D, 0x00))

VENDOR_PRIVILEGED = frozenset((OP_KEY_IMPORT, OP_KEY_DELETE, OP_OATH_PUT, OP_OATH_DELETE))

RESCUE_MAGIC = b"RESC"
RESCUE_VERSION = 0x01


def _check_slot(slot: int) -> None:
    if not 0 <= slot <= 0xFF:
        raise ValueError("slot must fit in one byte")


def _check_label(label: bytes) -> None:
    if not 1 <= len(label) <= _t.MAX_LABEL_BYTES:
        raise ValueError("label must be 1..32 bytes")


def wallet_gen(slot: int, label: bytes, network: int) -> bytes:
    """GEN request body (without op byte): TLV(01 slot, 02 label, 08 network)."""
    _check_slot(slot)
    _check_label(bytes(label))
    if not 0 <= network <= 0xFF:
        raise ValueError("network must fit in one byte")
    return (
        _t.write_tlv(_t.TAG_WALLET_SLOT, bytes((slot,)))
        + _t.write_tlv(_t.TAG_WALLET_LABEL, bytes(label))
        + _t.write_tlv(_t.TAG_WALLET_NETWORK, bytes((network,)))
    )


def wallet_addr_req(slot: int) -> bytes:
    _check_slot(slot)
    return _t.write_tlv(_t.TAG_WALLET_SLOT, bytes((slot,)))


def wallet_list_req() -> bytes:
    return b""


def vendor_key_gen(slot: int, label: bytes, alg: int, usage: int) -> bytes:
    _check_slot(slot)
    _check_label(bytes(label))
    if not 0 <= usage <= 0xFF or usage == 0:
        raise ValueError("usage must be a non-zero byte")
    import struct as _s
    return (
        _t.append_slot_label(slot, bytes(label))
        + _t.write_tlv(_t.TAG_ALG_HINT, _s.pack(">i", alg))
        + _t.write_tlv(_t.TAG_USAGE_HINT, bytes((usage,)))
    )


def vendor_slot_only(slot: int) -> bytes:
    _check_slot(slot)
    return _t.write_tlv(_t.TAG_SLOT, bytes((slot,)))


def vendor_slot_label(slot: int, label: bytes) -> bytes:
    _check_slot(slot)
    _check_label(bytes(label))
    return _t.append_slot_label(slot, bytes(label))


def rescue_frame(cmd: int, payload: bytes) -> bytes:
    """Mirror of rescue.rs build_packet: MAGIC|VER|CMD|LEN_BE|PAYLOAD."""
    if not 0 <= cmd <= 0xFF:
        raise ValueError("cmd must fit in one byte")
    p = bytes(payload)
    if len(p) > 0xFFFF:
        raise ValueError("payload too large")
    return RESCUE_MAGIC + bytes((RESCUE_VERSION, cmd)) + len(p).to_bytes(2, "big") + p


def fw_log_req() -> bytes:
    return b""


# ---------------------------------------------------------------------------
# F3 item 1: OTA 0x30-0x34 (builders only; COMMIT is USB-only, never here).
# Gate: binding -> UP -> PIN (authorize_config_op on device side).
#
# DIVERGENCIA DOCUMENTADA (device manifest 104 B): os builders legados
# `ota_begin(total_len, sha256)` (TLV) e `ota_chunk(seq u16, data)` NAO
# conversam com o fio do device — o firmware (`crates/aegis-fido-firmware/
# src/ota.rs` + `src/stores/ota_store.rs`) exige manifesto fixo de 104 B
# `version BE u32 || size BE u32 || sha256(32) || signature Ed25519(64)` no
# BEGIN e CHUNK `offset BE u32 || dados` (VERIFY vazio). Os legados seguem
# congelados p/ compat (`--self-test` os cobre); app novo DEVE usar
# `ota_manifest_build` + `ota_chunk_at` abaixo. COMMIT (`0x33`) executa
# SOMENTE via USB/CTAPHID (app usa HID): pelo BLE o device nega `0x04`
# sem tocar a sessao (ver `dispatch_ble_ota`); NUNCA executar COMMIT aqui.
# ---------------------------------------------------------------------------

# Tamanho fixo do manifesto OTA no fio (ver `OTA_MANIFEST_LEN` no firmware).
OTA_MANIFEST_LEN = 104
# Teto BLE por CHUNK: dados uteis (sem o offset) por mensagem (control-point
# 512 B; ver `BLE_OTA_MAX_CHUNK_BYTES` no firmware). Fail-closed nos dois
# lados: builder nega acima do teto, device desfaz a sessao.
BLE_OTA_MAX_CHUNK_BYTES = 512


def ota_begin(total_len: int, sha256: bytes) -> bytes:
    """OTA BEGIN body: TLV u32-BE total + 32B sha256 (tags 0x01/0x02 reuse).

    LEGADO/INCOMPATIVEL com o fio do device (mantido p/ `--self-test`).
    App novo: usar `ota_manifest_build` (104 B fixos).
    """
    import struct as _s
    digest = bytes(sha256)
    if not 0 < total_len <= 0xFFFFFF:
        raise ValueError("total_len out of range")
    if len(digest) != 32:
        raise ValueError("sha256 must be 32 bytes")
    return _t.write_tlv(0x01, _s.pack(">I", total_len)) + _t.write_tlv(0x02, digest)


def ota_chunk(seq: int, data: bytes) -> bytes:
    """OTA CHUNK body: seq u16-BE + chunk bytes (max 512, BLE control-point).

    LEGADO/INCOMPATIVEL com o fio do device (mantido p/ `--self-test`).
    App novo: usar `ota_chunk_at` (offset BE u32 + dados).
    """
    import struct as _s
    chunk = bytes(data)
    if not 0 <= seq <= 0xFFFF:
        raise ValueError("seq must fit in u16")
    if not 1 <= len(chunk) <= 512:
        raise ValueError("chunk must be 1..512 bytes")
    return _s.pack(">H", seq) + chunk


def ota_manifest_build(version: int, size: int, sha256: bytes, signature: bytes) -> bytes:
    """OTA BEGIN body compativel com o device: manifesto fixo de 104 B.

    Layout: `version BE u32 || size BE u32 || sha256(32) || signature(64)`.
    Fail-closed: versao 0, tamanho 0 e comprimentos errados negam (o device
    nega com `BadManifest`/`Downgrade`/`Overflow` + rollback).
    """
    import struct as _s
    digest = bytes(sha256)
    sig = bytes(signature)
    if not 1 <= version <= 0xFFFFFFFF:
        raise ValueError("version must be a non-zero u32")
    if not 1 <= size <= 0xFFFFFFFF:
        raise ValueError("size must be a non-zero u32")
    if len(digest) != 32:
        raise ValueError("sha256 must be 32 bytes")
    if len(sig) != 64:
        raise ValueError("signature must be 64 bytes")
    return _s.pack(">I", version) + _s.pack(">I", size) + digest + sig


def ota_begin_manifest(manifest104: bytes) -> bytes:
    """BEGIN a partir de manifesto ja montado (valida os 104 B, sem TLV)."""
    raw = bytes(manifest104)
    if len(raw) != OTA_MANIFEST_LEN:
        raise ValueError("manifest must be exactly 104 bytes")
    return raw


def ota_chunk_at(offset: int, data: bytes) -> bytes:
    """OTA CHUNK body compativel com o device: offset BE u32 + dados.

    Fail-closed: offset negativo, dado vazio e dado acima do teto BLE
    (512 B) negam (o device nega com `OutOfOrder`/`Overflow` + rollback).
    """
    import struct as _s
    chunk = bytes(data)
    if not 0 <= offset <= 0xFFFFFFFF:
        raise ValueError("offset must fit in u32")
    if not 1 <= len(chunk) <= BLE_OTA_MAX_CHUNK_BYTES:
        raise ValueError("chunk must be 1..512 bytes")
    return _s.pack(">I", offset) + chunk


def ota_verify() -> bytes:
    return b""


def ota_commit() -> bytes:
    """COMMIT marker (empty body). USB-ONLY on device; NEVER execute here.

    Regra (ver `dispatch_ble_ota` no firmware): `0x33` executa SOMENTE via
    USB/CTAPHID (o app usa HID). Pelo BLE o device nega `0x04` sem tocar a
    sessao `Verified`; a janela fisica valida o BOOT + o COMMIT via USB.
    """
    return b""


def ota_abort() -> bytes:
    return b""


# ---------------------------------------------------------------------------
# F3 item 2: CCID / PIV APDU builders (outside enroll 0x39). No firmware touch.
# ---------------------------------------------------------------------------

def piv_apdu(cla: int, ins: int, p1: int, p2: int, data: bytes = b"", le: int = -1) -> bytes:
    """Short APDU builder. Fail-closed: INS must be PIV data/oath, VERIFY or SELECT."""
    for name, v in (("cla", cla), ("ins", ins), ("p1", p1), ("p2", p2)):
        if not 0 <= v <= 0xFF:
            raise ValueError("%s must fit in one byte" % name)
    body = bytes(data)
    if len(body) > 255:
        raise ValueError("apdu data too large (short APDU only)")
    if ins not in PIV_INS and ins not in PIV_EXTRA_INS:
        raise ValueError("unsupported INS for PIV scope")
    out = bytes((cla, ins, p1, p2))
    if body:
        out += bytes((len(body),)) + body
    if le >= 0:
        if not 0 <= le <= 256:
            raise ValueError("le out of range")
        out += bytes((0x00 if le == 256 else le,))
    return out


def piv_select_aid() -> bytes:
    return piv_apdu(0x00, 0xA4, 0x04, 0x00, PIV_AID, le=0)


def piv_verify_pin(pin: bytes) -> bytes:
    p = bytes(pin)
    if not 6 <= len(p) <= 8 or not all(48 <= b <= 57 for b in p):
        raise ValueError("pin must be 6..8 ASCII digits")
    return piv_apdu(0x00, 0x20, 0x00, 0x80, p)


def piv_apdu_ins_name(ins: int) -> str:
    return {0x01: "PUT", 0x02: "GET", 0x03: "DEL", 0x04: "LIST",
            0xA1: "A1", 0xA2: "A2", 0xA3: "A3", 0xA4: "SELECT"}.get(ins, "UNKNOWN")


# ---------------------------------------------------------------------------
# F3 item 3: keyboard HID OTP typer input (app side, digits only, fail-closed).
# Never log the returned secret; caller logs counts only.
# ---------------------------------------------------------------------------

def otp_typer_input(s: str) -> bytes:
    """Validate app typer input: ASCII digits only, 6..8 chars. Fail-closed."""
    if not isinstance(s, str):
        raise ValueError("otp input must be str")
    if not 6 <= len(s) <= 8 or not s.isdigit() or not s.isascii():
        raise ValueError("otp must be 6..8 ASCII digits")
    return s.encode("ascii")


# ---------------------------------------------------------------------------
# F3 item 4: ykman / nitrokey / YubiOTP routes + honest 6D00 outside scope.
# ---------------------------------------------------------------------------

def ext_route_status(route: str) -> bytes:
    """Any ext route answers honest 0x6D00 (not supported in app scope)."""
    if route not in EXT_ROUTES:
        raise ValueError("unknown ext route")
    return EXT_STATUS_6D00


def ext_route_deny(route: str, op: str = "") -> None:
    raise PermissionError("ExternalBlocked: route=%s op=%s answers 6D00" % (route, op))


# ---------------------------------------------------------------------------
# F3 item 5: 0xFFFE proximity (K_prox / adv walkaway). RAM-only, no NVS here.
# Never uses FFF1-FFF4.
# ---------------------------------------------------------------------------

def prox_walkaway(timeout_s: int) -> bytes:
    """Walkaway adv request body: timeout u16-BE, 5..300 s. RAM-only."""
    import struct as _s
    if not 5 <= timeout_s <= 300:
        raise ValueError("timeout must be 5..300 s")
    return _s.pack(">H", timeout_s)


def prox_k_prox_begin() -> bytes:
    """K_prox handshake opener (empty body; key stays in RAM, no NVS)."""
    return b""


# ---------------------------------------------------------------------------
# F3 item 6: PIV OpenSC / F4 helpers: VERIFY + GEN/AUTH + strip-FF norm.
# ---------------------------------------------------------------------------

def piv_strip_ff(data: bytes) -> bytes:
    """Normalize F4 padding: strip trailing 0xFF bytes (fail-closed empty)."""
    raw = bytes(data)
    if not raw:
        raise ValueError("empty piv record")
    return raw.rstrip(b"\xFF") or raw[:0]


def piv_gen_auth(challenge: bytes) -> bytes:
    """GEN AUTH envelope: Lc-prefixed 32B challenge (fail-closed length)."""
    c = bytes(challenge)
    if len(c) != 32:
        raise ValueError("challenge must be 32 bytes")
    return bytes((len(c),)) + c


# ---------------------------------------------------------------------------
# F3 item 7: killswitch 0x06 / wipe token. Builder only; kill real = blocked.
# ---------------------------------------------------------------------------

def rescue_killswitch_frame(confirm: str) -> bytes:
    """Build killswitch frame only with exact confirm 'WIPE-ACK' (else deny)."""
    if confirm != KILLSWITCH_CONFIRM:
        raise ValueError("confirm must be 'WIPE-ACK'")
    return rescue_frame(RESCUE_CMD_KILLSWITCH, b"")


def killswitch_execute_denied() -> None:
    raise PermissionError("ExternalBlocked: kill real needs jig+HSM, never here")


def wrap_op(op: int, body: bytes) -> bytes:
    if not 0 <= op <= 0xFF:
        raise ValueError("op must fit in one byte")
    return bytes((op,)) + bytes(body)
