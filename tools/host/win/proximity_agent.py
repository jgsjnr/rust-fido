#!/usr/bin/env python3
"""Fido BLE proximity agent (Windows, host-only, lock-only).

Polls fob RSSI/proximity and calls LockWorkStation via ctypes when the
fob stays AWAY for >= lock_secs. Fail-closed: BLE errors, missing reads,
or a dead agent loop result in lock after timeout, never silent fail-open.
No auto-unlock (manual login required after lock).

Usage:
    python tools/host/win/proximity_agent.py --fob-id AA:BB:CC:DD:EE:FF
    python tools/host/win/proximity_agent.py --fob-id AA:BB:CC:DD:EE:FF --threshold-db -75 --lock-secs 10 --poll-secs 2
    python tools/host/win/proximity_agent.py --self-test   # offline, no hardware, no Windows needed

 real BLE backend: TODO Wave 2 (requires `bleak`; offline envs run with an
injectable RssiSource -- see make_polling_source / SimulatedSource).
"""

import argparse
import ctypes
import sys
import time
from typing import Callable, Optional

DEFAULT_THRESHOLD_DBM = -75
DEFAULT_HYSTERESIS_DB = 5
DEFAULT_LOCK_SECS = 10.0
DEFAULT_POLL_SECS = 2.0
MAX_CONSECUTIVE_ERRORS = 3


def lock_workstation() -> bool:
    """Lock the Windows workstation. Returns True on success.

    Raises OSError on non-Windows or when the native call fails.
    Separated for test injection (pass a fake `lock_fn` instead).
    """
    if sys.platform != "win32":
        raise OSError("lock_workstation requires Windows")
    result = ctypes.windll.user32.LockWorkStation()
    if not result:
        raise OSError("LockWorkStation failed")
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


def make_polling_source(fob_id: str) -> RssiFn:
    """Real BLE polling backend (TODO Wave 2 -- fail-closed stub).

    TODO Wave 2:
      - Implement with `bleak` (BleakScanner / BleakClient): scan filtrado
        pelo fob_id bonded, ler RSSI a cada poll.
      - H-2: validar identidade bonded (MAC/IRK + pairing) antes de aceitar
        RSSI; documentar anti-replay (nonce/desafio) -- sem canal autenticado
        o agente NAO deve destravar nada (lock-only ja respeita isso).
    Fail-closed: enquanto o backend real nao existe, levanta OSError para
    que o loop conte como AWAY e trave apos lock_secs em vez de fail-open.
    """
    raise OSError(
        "real BLE backend not implemented (TODO Wave 2, needs bleak + bonded %s)" % fob_id
    )


def run_loop(
    read_rssi: RssiFn,
    decider: ProximityDecider,
    lock_fn: Callable[[], bool] = lock_workstation,
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
            log_fn("state=AWAY away_secs=%.1f -> locking workstation" % decider.away_secs)
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
    parser = argparse.ArgumentParser(description="Fido BLE proximity lock agent (Windows)")
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
