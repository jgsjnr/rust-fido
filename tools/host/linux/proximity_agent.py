#!/usr/bin/env python3
"""Fido BLE proximity agent (Linux, host-only, lock-only).

Polls fob RSSI/proximity and locks the session via logind (`loginctl
lock-session`) when the fob stays AWAY for >= lock_secs. Fail-closed:
BLE errors, missing reads, or a dead agent loop result in lock after
timeout, never silent fail-open. No auto-unlock (manual login required).

Usage:
    python tools/host/linux/proximity_agent.py --fob-id AA:BB:CC:DD:EE:FF
    python tools/host/linux/proximity_agent.py --fob-id AA:BB:CC:DD:EE:FF --threshold-db -75 --lock-secs 10 --poll-secs 2
    python tools/host/linux/proximity_agent.py --self-test   # offline, no hardware, no Linux needed

BLE backend is scanner-injectable (lock-only): production passes a
bleak-backed scanner filtered by the bonded fob_id (needs `pip install
bleak` + BlueZ); offline envs and tests pass a lambda or use
SimulatedSource. Without bleak/scanner the default raises OSError
(fail-closed stub).
"""

import argparse
import subprocess
import sys
import time
from typing import Callable, Dict, List, Optional

DEFAULT_THRESHOLD_DBM = -75
DEFAULT_HYSTERESIS_DB = 5
DEFAULT_LOCK_SECS = 10.0
DEFAULT_POLL_SECS = 2.0
MAX_CONSECUTIVE_ERRORS = 3


def lock_session() -> bool:
    """Lock the current logind session. Returns True on success.

    Raises OSError on non-Linux or when `loginctl lock-session` fails.
    Separated for test injection (pass a fake `lock_fn` instead).
    """
    if not sys.platform.startswith("linux"):
        raise OSError("lock_session requires Linux (logind)")
    try:
        subprocess.run(
            ["loginctl", "lock-session"],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=10,
        )
    except (subprocess.SubprocessError, OSError) as exc:
        raise OSError("loginctl lock-session failed: %s" % exc)
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


def _bleak_scan(fob_id: str) -> List:
    """One-shot BlueZ scan via bleak (optional dep). Raises OSError when
    bleak is missing or the scan fails (fail-closed: caller counts AWAY)."""
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


def make_polling_source(fob_id: str, scanner: Optional[Callable[[], List]] = None) -> RssiFn:
    """BLE polling backend com scanner injetavel (lock-only).

    - `fob_id` vazio => OSError (fail-closed, nunca opera sem identidade bonded).
    - `scanner` injeta a fonte de scan (producao: BlueZ/bleak filtrado pelo
      fob bonded; testes: lambda). Sem scanner, usa bleak quando instalado;
      sem bleak, levanta OSError (stub fail-closed).
    - Retorna RssiFn: RSSI do fob bonded (match case-insensitive), None
      quando ausente (AWAY), propaga OSError de transporte para o loop
      contar como AWAY e travar apos lock_secs (fail-closed).
    """
    if not _normalize_ble_address(fob_id):
        raise OSError("make_polling_source requires a bonded fob_id")

    def _default_scanner() -> List:
        return _bleak_scan(fob_id)

    scan = scanner if scanner is not None else _default_scanner

    def _poll() -> Optional[int]:
        devices = scan()  # propaga OSError de transporte (fail-closed)
        bonded = _match_bonded_device(devices or [], fob_id)
        if bonded is None:
            return None
        return _device_rssi(bonded)

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
    d = ProximityDecider()
    assert d.update(-60, 2.0) is False
    assert d.update(None, 10.0) is True  # fail-closed: miss conta como AWAY
    print("self-test ok")
    return 0


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Fido BLE proximity lock agent (Linux/logind)")
    parser.add_argument("--fob-id", default="", help="bonded fob address/ID (required unless --self-test or --simulate)")
    parser.add_argument("--threshold-db", type=int, default=DEFAULT_THRESHOLD_DBM)
    parser.add_argument("--lock-secs", type=float, default=DEFAULT_LOCK_SECS)
    parser.add_argument("--poll-secs", type=float, default=DEFAULT_POLL_SECS)
    parser.add_argument("--simulate", action="store_true", help="offline demo source, no BLE hardware")
    parser.add_argument("--self-test", action="store_true", help="offline check, no hardware")
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
        fob = args.fob_id

        def source() -> Optional[int]:
            return make_polling_source(fob)

    outcome = run_loop(source, decider, poll_secs=args.poll_secs)
    print("outcome=%s" % outcome)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
