#!/usr/bin/env python3
"""Fido BLE proximity agent (macOS, host-only, lock-only).

Polls fob RSSI/proximity and suspends the session (`CGSession -suspend`,
best available API: fast-user-switch to the login window) when the fob
stays AWAY for >= lock_secs. Fail-closed: BLE errors, missing reads, or
a dead agent loop result in lock after timeout, never silent fail-open.
No auto-unlock (manual login required).

Usage:
    python tools/host/macos/proximity_agent.py --fob-id AA:BB:CC:DD:EE:FF
    python tools/host/macos/proximity_agent.py --fob-id AA:BB:CC:DD:EE:FF --threshold-db -75 --lock-secs 10 --poll-secs 2
    python tools/host/macos/proximity_agent.py --self-test   # offline, no hardware, no macOS needed

BLE backend is scanner-injectable (lock-only): production passes a
bleak-backed scanner filtered by the bonded fob_id (needs `pip install
bleak`); offline envs and tests pass a lambda or use SimulatedSource.
Without bleak/scanner the default raises OSError (fail-closed stub).
"""

import argparse
import os
import subprocess
import sys
import time
from typing import Callable, Dict, List, Optional, Tuple

DEFAULT_THRESHOLD_DBM = -75
DEFAULT_HYSTERESIS_DB = 5
DEFAULT_LOCK_SECS = 10.0
DEFAULT_POLL_SECS = 2.0
MAX_CONSECUTIVE_ERRORS = 3

# Firmware proximity compat: service UUID 0xFFFE
# (crates/aegis-fido-firmware/src/ble_gatt.rs PROXIMITY_SERVICE_UUID).
# Path de presenca filtra SOMENTE 0xFFFE; UUID FFFD (CTAP2-BLE) e ignorada.
PROXIMITY_SERVICE_UUID = 0xFFFE
PROXIMITY_SERVICE_UUID_STR = "0000fffe-0000-1000-8000-00805f9a34fb"
IGNORED_SERVICE_UUID_STR = "0000fffd-0000-1000-8000-00805f9a34fb"

# Rolling-code contratual: VER(1) || CTR(u32 LE) || TAG(4B, AES-CCM c/ K_prox).
# Total 9 bytes no service_data do 0xFFFE. VER desconhecido => Unsupported,
# sem amostra => Unavailable; ambos fail-closed (None/AWAY, lock-only).
PROXIMITY_VER = 0x01
PROXIMITY_PAYLOAD_LEN = 9
PROXIMITY_TAG_LEN = 4
# Salto de ctr acima disso nao e aceito no tick: re-verify conservador
# (conta None/AWAY nesse tick, sem avancar last_ctr).
PROXIMITY_MAX_CTR_JUMP = 1000

CGSESSION = "/System/Library/CoreServices/Menu Extras/User.menu/Contents/Resources/CGSession"


def lock_session() -> bool:
    """Suspend to the login window via CGSession. Returns True on success.

    Raises OSError on non-macOS or when CGSession fails. Separated for
    test injection (pass a fake `lock_fn` instead).
    """
    if sys.platform != "darwin":
        raise OSError("lock_session requires macOS")
    try:
        subprocess.run(
            [CGSESSION, "-suspend"],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=10,
        )
    except (subprocess.SubprocessError, OSError) as exc:
        raise OSError("CGSession -suspend failed: %s" % exc)
    return True


class ProximityDecider:
    """Pure decision logic: histerese + dwell-to-lock, sem hardware.

    AWAY quando rssi is None (leitura perdida) ou rssi < threshold_dbm.
    Volta a NEAR quando rssi >= threshold_dbm + hysteresis_db.
    should_lock fica True uma vez quando away_secs >= lock_secs; trava
    (latch) ate rssi voltar a NEAR (sem auto-unlock: apos lock, o SO
    exige login manual; o latch so libera o proximo ciclo).
    """

    def __init__(
        self,
        threshold_dbm: int = DEFAULT_THRESHOLD_DBM,
        hysteresis_db: int = DEFAULT_HYSTERESIS_DB,
        lock_secs: float = DEFAULT_LOCK_SECS,
    ) -> None:
        if lock_secs <= 0:
            raise ValueError("lock_secs must be > 0")
        if hysteresis_db < 0:
            raise ValueError("hysteresis_db must be >= 0")
        self.threshold_dbm = threshold_dbm
        self.hysteresis_db = hysteresis_db
        self.lock_secs = lock_secs
        self.away_secs = 0.0
        self.locked = False
        self.consecutive_errors = 0

    @property
    def near_threshold(self) -> int:
        return self.threshold_dbm + self.hysteresis_db

    def update(self, rssi: Optional[int], dt: float, source_error: bool = False) -> bool:
        """Advance state by dt seconds. Returns True on the tick that locks."""
        if dt < 0:
            raise ValueError("dt must be >= 0")
        if source_error:
            self.consecutive_errors += 1
            # Fail-closed: erro conta como AWAY.
            self.away_secs += dt
        elif rssi is None:
            self.consecutive_errors = 0
            self.away_secs += dt
        elif rssi >= self.near_threshold:
            self.consecutive_errors = 0
            self.away_secs = 0.0
            self.locked = False
            return False
        elif rssi >= self.threshold_dbm:
            # Banda de histerese: mantem estado atual, nao acumula nem zera.
            self.consecutive_errors = 0
            return False
        else:
            self.consecutive_errors = 0
            self.away_secs += dt
        if not self.locked and self.away_secs >= self.lock_secs:
            self.locked = True
            return True
        return False


# Type: returns RSSI dBm, None on missed read, raises on transport failure.
RssiFn = Callable[[], Optional[int]]


class SimulatedSource:
    """Offline/demo source: replays a scripted RSSI sequence (testes manuais)."""

    def __init__(self, script=(-60, -60, -90, -90, None, None)) -> None:
        self.script = list(script)
        self.index = 0

    def __call__(self) -> Optional[int]:
        value = self.script[self.index % len(self.script)]
        self.index += 1
        return value


def _normalize_ble_address(address: str) -> str:
    """Normaliza endereco BLE para comparacao bonded (lower + trim)."""
    if not address:
        return ""
    return address.strip().lower()


def _match_bonded_device(devices: List, fob_id: str):
    """Retorna device cujo address casa com fob_id bonded, ou None."""
    target = _normalize_ble_address(fob_id)
    if not target:
        return None
    for dev in devices:
        if _normalize_ble_address(getattr(dev, "address", "") or "") == target:
            return dev
    return None


def _device_rssi(device, advertisement: Optional[Dict] = None) -> Optional[int]:
    """Extrai RSSI: campo device -> advertisement -> metadata, ou None."""
    rssi = getattr(device, "rssi", None)
    if rssi is not None:
        return rssi
    if isinstance(advertisement, dict):
        adv = advertisement.get("rssi")
        if adv is not None:
            return adv
    metadata = getattr(device, "metadata", None)
    if isinstance(metadata, dict):
        meta = metadata.get("rssi")
        if meta is not None:
            return meta
    return None


def parse_proximity_payload(data: bytes) -> Optional[Tuple[int, int, bytes]]:
    """Parse payload contratual do service_data 0xFFFE.

    Formato: ``VER(1) || CTR(u32 LE) || TAG(4B)`` (9 bytes).
    Retorna ``(ver, ctr, tag)`` ou None se malformado. VER != 0x01 e
    considerado Unsupported pelo verificador (fail-closed). TAG e
    verificada via AES-CCM com K_prox (fail-closed sem chave/backend).
    """

    if data is None or len(data) != PROXIMITY_PAYLOAD_LEN:
        return None
    ver = data[0]
    ctr = int.from_bytes(data[1:5], "little")
    tag = bytes(data[5:9])
    if len(tag) != PROXIMITY_TAG_LEN:
        return None
    return (ver, ctr, tag)


def _fob_id_bytes(address) -> bytes:
    """Converte MAC bonded ``AA:BB:CC:DD:EE:FF`` em 6 bytes (fail-closed).

    Raises OSError quando o formato e invalido; chamador trata como
    AWAY/False (nunca autentica sem identidade ligada ao fob real).
    """
    if isinstance(address, (bytes, bytearray)):
        raw = bytes(address)
        if len(raw) == 6:
            return raw
        raise OSError("fob_id invalido (6B)")
    parts = str(address or "").strip().split(":")
    if len(parts) != 6:
        raise OSError("fob_id invalido (MAC AA:BB:CC:DD:EE:FF)")
    try:
        raw = bytes(int(p, 16) for p in parts)
    except ValueError:
        raise OSError("fob_id invalido (hex)")
    if len(raw) != 6 or any(len(p) != 2 for p in parts):
        raise OSError("fob_id invalido (MAC AA:BB:CC:DD:EE:FF)")
    return raw


def _aes_ecb_encrypt(key: bytes, block: bytes) -> bytes:
    """AES-ECB de 1 bloco (16B). cryptography primeiro, PyCryptodome depois.

    Sem backend => OSError (fail-closed: chamador retorna False).
    """
    if len(block) != 16:
        raise OSError("bloco AES deve ter 16B")
    try:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

        cipher = Cipher(algorithms.AES(bytes(key)), modes.ECB())
        enc = cipher.encryptor()
        return enc.update(bytes(block)) + enc.finalize()
    except ImportError:
        pass
    try:
        from Cryptodome.Cipher import AES as _AES  # type: ignore

        return bytes(_AES.new(bytes(key), _AES.MODE_ECB).encrypt(bytes(block)))
    except ImportError:
        raise OSError("sem backend AES (cryptography/PyCryptodome)")
    except OSError:
        raise
    except Exception as exc:
        raise OSError("AES-ECB falhou: %s" % exc)


def _ccm_tag(key: bytes, ver: int, ctr: int, fob: bytes) -> bytes:
    """TAG 4B replicando o firmware ``proximity.rs`` passo a passo.

    nonce (11B) = VER || CTR_LE || fob_id[6B]; AAD (5B) = VER || CTR_LE.
    CBC-MAC custom T=4 L=4: B0 = 0x4B || nonce || 0x0000, AAD com prefixo
    de comprimento BE u16 + pad de zeros ate multiplo de 16; S0 =
    0x03 || nonce || ctr0; TAG = CBC-MAC ^ S0 truncado em 4B.
    """
    nonce = bytes([int(ver) & 0xFF]) + int(ctr).to_bytes(4, "little") + bytes(fob[:6])
    x = bytearray(16)
    x[0] = 0x4B
    x[1:12] = nonce
    x = bytearray(_aes_ecb_encrypt(bytes(key), bytes(x)))
    aad = bytes([int(ver) & 0xFF]) + int(ctr).to_bytes(4, "little")
    aad_len = len(aad)
    block = bytearray(16)
    block[0] = (aad_len >> 8) & 0xFF
    block[1] = aad_len & 0xFF
    head = min(aad_len, 14)
    block[2:2 + head] = aad[:head]
    for i in range(16):
        x[i] ^= block[i]
    x = bytearray(_aes_ecb_encrypt(bytes(key), bytes(x)))
    off = head
    while off < aad_len:
        take = min(aad_len - off, 16)
        block = bytearray(16)
        block[:take] = aad[off:off + take]
        for i in range(16):
            x[i] ^= block[i]
        x = bytearray(_aes_ecb_encrypt(bytes(key), bytes(x)))
        off += take
    s0 = bytearray(_aes_ecb_encrypt(bytes(key), bytes(bytes([0x03]) + nonce + b"\x00\x00\x00\x00")))
    return bytes(x[i] ^ s0[i] for i in range(PROXIMITY_TAG_LEN))


def verify_proximity_tag(ctr: int, tag: bytes, key=None, fob=None) -> bool:
    """Verifica TAG AES-CCM do rolling-code com K_prox + fob bonded.

    Replica ``proximity.rs proximity_tag`` (nonce 11B VER||CTR_LE||fob_id,
    AAD 5B VER||CTR_LE, CBC-MAC custom T=4 L=4). `fob` aceita 6 bytes ou
    MAC ``AA:BB:...``. Sem `key`/`fob` validos ou sem backend AES =>
    False (fail-closed). Comparacao em tempo constante.
    """
    import hmac as _hmac

    try:
        if key is None or tag is None or fob is None:
            return False
        if len(bytes(tag)) != PROXIMITY_TAG_LEN:
            return False
        kb = bytes(key)
        if len(kb) not in (16, 24, 32):
            return False
        fb = _fob_id_bytes(fob)
        expected = _ccm_tag(kb, PROXIMITY_VER, int(ctr), fb)
        return bool(_hmac.compare_digest(bytes(expected), bytes(tag)))
    except Exception:
        return False



def _device_adv_payload(device) -> Optional[bytes]:
    """Extrai payload de proximidade SOMENTE do service_data 0xFFFE.

    UUID 0xFFFD e qualquer outra sao ignoradas no path de presenca.
    Retorna os bytes do 0xFFFE ou None (Unavailable => AWAY fail-closed).
    """
    metadata = getattr(device, "metadata", None)
    if not isinstance(metadata, dict):
        adv = getattr(device, "advertisement_data", None)
        if adv is None:
            return None
        metadata = {"service_data": getattr(adv, "service_data", None)}
    svc = metadata.get("service_data")
    if not isinstance(svc, dict):
        return None
    for key, value in svc.items():
        kl = str(key).lower()
        if "fffd" in kl:
            continue  # path presenca ignora FFFD
        if PROXIMITY_SERVICE_UUID_STR in kl or "fffe" in kl:
            raw = bytes(value) if not isinstance(value, (bytes, bytearray)) else bytes(value)
            return raw if raw else None
    return None
class RollingCodeVerifier:
    """Anti-replay contratual do rolling-code (fail-closed, lock-only).

    - Sem amostra (None) => Unavailable => False (AWAY).
    - VER desconhecido => Unsupported => False (AWAY).
    - ctr <= last_ctr => replay => False (AWAY, descarta como None).
    - salto ctr > 1000 => re-verify conservador: False nesse tick SEM
      avancar last_ctr (proximo tick reavalia).
    - TAG AES-CCM (firmware ``proximity.rs``: nonce 11B VER||CTR_LE||fob_id)
      com K_prox + fob bonded invalida => False (AWAY).
    - `tag_fn(ctr, tag)` 2-arg injetavel substitui o backend real nos testes.
    Lock-only: nunca destrava nada, so decide se a amostra RSSI vale
    como evidencia de presenca (NEAR).
    """

    def __init__(
        self,
        key: Optional[bytes] = None,
        fob_id=None,
        tag_fn: Optional[Callable[[int, bytes], bool]] = None,
    ) -> None:
        self.key = key
        self.fob_id = fob_id
        self.tag_fn = tag_fn
        self.last_ctr: Optional[int] = None
        self.last_reason: str = "Unavailable"

    def _check_tag(self, ctr: int, tag: bytes) -> bool:
        if self.tag_fn is not None:
            try:
                return bool(self.tag_fn(ctr, tag))
            except Exception:
                return False
        try:
            fob = self.fob_id if isinstance(self.fob_id, (bytes, bytearray)) else _fob_id_bytes(self.fob_id)
        except Exception:
            return False
        return verify_proximity_tag(ctr, tag, self.key, fob)

    def verify(self, payload: Optional[bytes]) -> bool:
        """True somente p/ VER conhecido + ctr crescente + TAG valida."""
        if payload is None:
            self.last_reason = "Unavailable"
            return False
        parsed = parse_proximity_payload(payload)
        if parsed is None:
            self.last_reason = "Unsupported"
            return False
        ver, ctr, tag = parsed
        if ver != PROXIMITY_VER:
            self.last_reason = "Unsupported"
            return False
        if self.last_ctr is not None:
            if ctr <= self.last_ctr:
                self.last_reason = "Replay"
                return False
            if ctr - self.last_ctr > PROXIMITY_MAX_CTR_JUMP:
                self.last_reason = "Reverify"
                return False  # conservador: nao avanca last_ctr nesse tick
        if not self._check_tag(ctr, tag):
            self.last_reason = "BadTag"
            return False
        self.last_ctr = ctr
        self.last_reason = "Ok"
        return True


def _load_prox_key(hex_str: Optional[str]) -> Optional[bytes]:
    """Carrega K_prox (16/24/32B hex) de flag/env; None => fail-closed."""
    raw = (hex_str or os.environ.get("FIDO_PROX_KEY_HEX") or "").strip()
    if not raw:
        return None
    try:
        key = bytes.fromhex(raw)
    except ValueError:
        raise OSError("K_prox invalida (hex)")
    if len(key) not in (16, 24, 32):
        raise OSError("K_prox deve ter 16/24/32 bytes")
    return key


def _bleak_scan(fob_id: str) -> List:
    """One-shot scan via bleak (optional dep). Raises OSError when bleak
    is missing or the scan fails (fail-closed: caller counts AWAY)."""
    try:
        import asyncio

        from bleak import BleakScanner
    except ImportError:
        raise OSError("bleak not installed (pip install bleak); cannot scan")
    try:
        devices = asyncio.run(BleakScanner.discover(timeout=5.0))
    except Exception as exc:
        raise OSError("bleak scan failed: %s" % exc)
    return [d for d in devices or []]


def make_polling_source(
    fob_id: str,
    scanner: Optional[Callable[[], List]] = None,
    verifier: Optional[RollingCodeVerifier] = None,
) -> RssiFn:
    """BLE polling backend com scanner injetavel (lock-only).

    - `fob_id` vazio => OSError (fail-closed, nunca opera sem identidade bonded).
    - `scanner` injeta a fonte de scan (producao: bleak filtrado pelo fob
      bonded; testes: lambda). Sem scanner, usa bleak quando instalado;
      sem bleak, levanta OSError (stub fail-closed).
    - Retorna RssiFn: RSSI do fob bonded (match case-insensitive), None
      quando ausente (AWAY), propaga OSError de transporte para o loop
      contar como AWAY e travar apos lock_secs (fail-closed).
    - Rolling-code 0xFFFE ``VER(0x01)||CTR(LE)||TAG(4B)``: replay, salto,
      VER/TAG invalidos ou RSSI ausente => None (AWAY fail-closed); sem
      payload (fob legado) => RSSI puro (compat firmware proximity).
    """
    if not _normalize_ble_address(fob_id):
        raise OSError("make_polling_source requires a bonded fob_id")
    verify = verifier if verifier is not None else RollingCodeVerifier(fob_id=fob_id)

    def _default_scanner() -> List:
        return _bleak_scan(fob_id)

    scan = scanner if scanner is not None else _default_scanner

    def _poll() -> Optional[int]:
        devices = scan()  # propaga OSError de transporte (fail-closed)
        bonded = _match_bonded_device(devices or [], fob_id)
        if bonded is None:
            return None
        rssi = _device_rssi(bonded)
        if rssi is None:
            return None  # sem RSSI nao ha evidencia de presenca (AWAY)
        payload = _device_adv_payload(bonded)
        if not verify.verify(payload):
            return None  # replay/VER/TAG invalidos => AWAY fail-closed
        return rssi

    return _poll


def run_loop(
    read_rssi: RssiFn,
    decider: ProximityDecider,
    lock_fn: Callable[[], bool] = lock_session,
    poll_secs: float = DEFAULT_POLL_SECS,
    max_ticks: Optional[int] = None,
    sleep_fn: Callable[[float], None] = time.sleep,
    log_fn: Callable[[str], None] = print,
) -> str:
    """Poll loop. Returns 'locked' | 'ticks-exhausted'. Fail-closed watchdog."""
    ticks = 0
    while True:
        try:
            rssi = read_rssi()
            error = False
        except Exception as exc:  # noqa: BLE-001 -- watchdog fail-closed
            rssi = None
            error = True
            log_fn("warn: rssi source error (%s); counting as AWAY" % exc)
        if decider.update(rssi, poll_secs, source_error=error):
            log_fn("state=AWAY away_secs=%.1f -> locking session" % decider.away_secs)
            lock_fn()
            return "locked"
        if decider.consecutive_errors >= MAX_CONSECUTIVE_ERRORS:
            log_fn(
                "watchdog: %d consecutive source errors; forcing lock (fail-closed)"
                % decider.consecutive_errors
            )
            lock_fn()
            return "locked"
        ticks += 1
        if max_ticks is not None and ticks >= max_ticks:
            return "ticks-exhausted"
        sleep_fn(poll_secs)


def self_test() -> int:
    import struct as _st

    def _pay(ctr: int, tag: bytes = b"\x00\x00\x00\x00") -> bytes:
        return bytes([PROXIMITY_VER]) + _st.pack("<I", ctr) + bytes(tag)

    d = ProximityDecider()
    assert d.update(-60, 2.0) is False
    assert d.update(None, 10.0) is True  # fail-closed: miss conta como AWAY
    # Contrato rolling-code offline (TAG injetada, sem hardware/AES).
    v = RollingCodeVerifier(tag_fn=lambda c, t: True)
    assert v.verify(_pay(1)) is True
    assert v.verify(_pay(1)) is False and v.last_reason == "Replay"
    assert v.verify(_pay(2)) is True
    assert v.verify(b"\x02" + _st.pack("<I", 3) + b"\x00\x00\x00\x00") is False  # Unsupported
    assert v.verify(None) is False  # Unavailable fail-closed
    vj = RollingCodeVerifier(tag_fn=lambda c, t: True)
    assert vj.verify(_pay(10)) is True
    assert vj.verify(_pay(10 + PROXIMITY_MAX_CTR_JUMP + 1)) is False  # Reverify
    assert vj.last_ctr == 10 and vj.last_reason == "Reverify"
    assert vj.verify(_pay(11)) is True  # re-verify no proximo tick ok
    vb = RollingCodeVerifier(tag_fn=lambda c, t: False)
    assert vb.verify(_pay(1)) is False  # BadTag fail-closed
    assert parse_proximity_payload(b"short") is None
    # Vetor real firmware: K=0x42*16, fob=AA:BB:CC:DD:EE:FF, ctr=7.
    _rv_key = bytes([0x42]) * 16
    _rv_fob = _fob_id_bytes("AA:BB:CC:DD:EE:FF")
    _rv_tag = _ccm_tag(_rv_key, PROXIMITY_VER, 7, _rv_fob)
    assert verify_proximity_tag(7, _rv_tag, _rv_key, _rv_fob) is True
    assert verify_proximity_tag(7, b"\x00\x00\x00\x00", _rv_key, _rv_fob) is False
    assert verify_proximity_tag(8, _rv_tag, _rv_key, _rv_fob) is False  # ctr diverge
    assert verify_proximity_tag(7, _rv_tag, _rv_key, _fob_id_bytes("AA:BB:CC:DD:EE:00")) is False
    assert verify_proximity_tag(7, _rv_tag, None, _rv_fob) is False  # sem chave => fail-closed
    _rv = RollingCodeVerifier(key=_rv_key, fob_id=_rv_fob)
    assert _rv.verify(bytes([PROXIMITY_VER]) + _st.pack("<I", 7) + bytes(_rv_tag)) is True
    # Path presenca ignora FFFD: so 0xFFFE vale.
    from types import SimpleNamespace as _NS

    only_fffd = _NS(
        address="AA:BB:CC:DD:EE:FF",
        rssi=-60,
        metadata={"service_data": {"0000fffd-0000-1000-8000-00805f9a34fb": _pay(1)}},
    )
    assert _device_adv_payload(only_fffd) is None
    # Backend injetavel offline: bonded filtra por fob-id, erro propaga.
    src = make_polling_source(
        "AA:BB:CC:DD:EE:FF",
        scanner=lambda: [
            _NS(
                address="AA:BB:CC:DD:EE:FF",
                rssi=-60,
                metadata={"service_data": {PROXIMITY_SERVICE_UUID_STR: _pay(1)}},
            )
        ],
        verifier=RollingCodeVerifier(tag_fn=lambda c, t: True),
    )
    assert src() == -60
    src_away = make_polling_source(
        "AA:BB:CC:DD:EE:FF",
        scanner=lambda: [_NS(address="AA:BB:CC:DD:EE:00", rssi=-40, metadata={})],
    )
    assert src_away() is None
    print("self-test ok")
    return 0


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Fido BLE proximity lock agent (macOS)")
    parser.add_argument("--fob-id", default="", help="bonded fob address/ID (required unless --self-test or --simulate)")
    parser.add_argument("--threshold-db", type=int, default=DEFAULT_THRESHOLD_DBM)
    parser.add_argument("--lock-secs", type=float, default=DEFAULT_LOCK_SECS)
    parser.add_argument("--poll-secs", type=float, default=DEFAULT_POLL_SECS)
    parser.add_argument("--simulate", action="store_true", help="offline demo source, no BLE hardware")
    parser.add_argument("--self-test", action="store_true", help="offline check, no hardware")
    parser.add_argument("--k-prox-hex", default="", help="K_prox hex (16/24/32B) p/ TAG AES-CCM; ou env FIDO_PROX_KEY_HEX")
    args = parser.parse_args(argv)

    if args.self_test:
        return self_test()
    if args.poll_secs <= 0 or args.lock_secs <= 0:
        parser.error("--poll-secs and --lock-secs must be > 0")
    if not args.simulate and not args.fob_id:
        parser.error("--fob-id is required (or use --simulate / --self-test)")

    decider = ProximityDecider(
        threshold_dbm=args.threshold_db, lock_secs=args.lock_secs
    )
    if args.simulate:
        source: RssiFn = SimulatedSource()
    else:
        key = _load_prox_key(args.k_prox_hex)
        if key is None:
            print("warn: sem K_prox (--k-prox-hex/FIDO_PROX_KEY_HEX); TAG nao verifica => AWAY fail-closed")
        source = make_polling_source(args.fob_id, verifier=RollingCodeVerifier(key=key, fob_id=args.fob_id))

    outcome = run_loop(source, decider, poll_secs=args.poll_secs)
    print("outcome=%s" % outcome)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
