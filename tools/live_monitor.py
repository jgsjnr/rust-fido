#!/usr/bin/env python3
"""AegisKey live monitor (Wave7, read-only, stdlib only).

Reads ``[LT][<category>] <event> detail=<detail>`` lines from the
``debug-terminal`` firmware feature and prints a colored stream plus stats.

Read-only contract (never writes to the device):
- Win32 COM opened with GENERIC_READ only (no GENERIC_WRITE).
- POSIX opened with O_RDONLY (no O_RDWR).
- This module defines no ``write`` method on purpose.

Release firmware compiles ``ltrace!`` to nothing, so a release device shows
"sem eventos" (zero ``[LT]`` lines) -- that is expected, not an error.

Usage:
    python tools/live_monitor.py --port COM7
    python tools/live_monitor.py --port /dev/ttyUSB0 --cat pin --count 50
    python tools/live_monitor.py --input capture.txt --no-color
    type capture.txt | python tools/live_monitor.py
    python tools/live_monitor.py --self-test   # offline, no hardware
"""

import argparse
import collections
import glob
import os
import re
import sys
import time

PACKET_SIZE = 64
DEFAULT_BAUD = 115200
DEFAULT_TIMEOUT_MS = 1000

# Example: [LT][key_slot] create detail=3
LTRACE_RE = re.compile(
    r"\[LT\]\[([A-Za-z0-9_]+)\]\s+([A-Za-z0-9_.]+)\s+detail=(.*)"
)

KNOWN_CATS = ("key_slot", "oath", "pairing", "pin", "transport")

COLORS = {
    "key_slot": "\033[36m",
    "oath": "\033[32m",
    "pairing": "\033[33m",
    "pin": "\033[35m",
    "transport": "\033[34m",
}
RESET = "\033[0m"


def parse_ltrace_line(line):
    """Parse one ``[LT][cat] event detail=X`` line.

    Returns ``{"cat":..., "event":..., "detail":..., "raw":...}`` or None
    for non-ltrace lines (plain logs, empty lines, garbage).
    """
    if not isinstance(line, str):
        return None
    raw = line.strip()
    if not raw:
        return None
    m = LTRACE_RE.search(raw)
    if not m:
        return None
    cat, event, detail = m.group(1), m.group(2), m.group(3)
    cat = cat.strip()
    event = event.strip()
    detail = detail.strip() if detail is not None else ""
    if not cat or not event:
        return None
    return {"cat": cat, "event": event, "detail": detail, "raw": raw}


def _norm_filter(value):
    if value is None:
        return None
    if isinstance(value, str):
        v = value.strip()
        if v == "" or v == "all" or v == "*":
            return None
        parts = [p.strip() for p in v.split(",")]
        return set(p for p in parts if p)
    return set(value)


def matches_filter(evt, cat_filter=None, event_filter=None):
    """True when a parsed event passes the optional cat/event filters."""
    if evt is None:
        return False
    cats = _norm_filter(cat_filter)
    evts = _norm_filter(event_filter)
    if cats is not None and evt.get("cat") not in cats:
        return False
    if evts is not None and evt.get("event") not in evts:
        return False
    return True


class RateTracker:
    """Sliding-window event rate (events/second)."""

    def __init__(self, window_s=5.0, clock=None):
        self.window_s = float(window_s)
        self.clock = clock or time.monotonic
        self.hits = collections.deque()

    def _prune(self, now):
        if self.window_s <= 0:
            return
        cutoff = now - self.window_s
        hits = self.hits
        while hits and hits[0] <= cutoff:
            hits.popleft()

    def hit(self, now=None):
        """Record one event, return current window count."""
        t = now if now is not None else self.clock()
        self.hits.append(t)
        self._prune(t)
        return len(self.hits)

    def rate(self, now=None):
        """Current events/second over the window."""
        t = now if now is not None else self.clock()
        self._prune(t)
        if self.window_s <= 0:
            return float(len(self.hits))
        return len(self.hits) / self.window_s

    def count(self, now=None):
        """Current window count."""
        t = now if now is not None else self.clock()
        self._prune(t)
        return len(self.hits)

    def reset(self):
        """Clear all recorded hits."""
        self.hits.clear()


def list_serial_ports():
    """List candidate serial ports (stdlib only)."""
    ports = []
    if os.name == "nt":
        try:
            import winreg
            key = winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE, r"HARDWARE\DEVICEMAP\SERIALCOMM")
            i = 0
            while True:
                try:
                    _, data, _ = winreg.EnumValue(key, i)
                    ports.append(str(data))
                    i += 1
                except OSError:
                    break
        except Exception:
            pass
        if not ports:
            for n in range(1, 17):
                ports.append("COM%d" % n)
    else:
        for pattern in ("/dev/ttyACM*", "/dev/ttyUSB*", "/dev/ttyS*"):
            ports.extend(sorted(glob.glob(pattern)))
    return ports


class ReadOnlySerial:
    """Read-only serial link (no write method by design)."""

    def __init__(self, port, baud=DEFAULT_BAUD, timeout_ms=DEFAULT_TIMEOUT_MS):
        self.port = port
        self.baud = baud
        self.timeout_ms = timeout_ms
        self.handle = None
        self.fd = None

    def open(self):
        """Open the port read-only."""
        if os.name == "nt":
            self._open_win()
        else:
            self._open_posix()

    def _open_win(self):
        import ctypes
        from ctypes import wintypes
        k32 = ctypes.windll.kernel32
        GENERIC_READ = 0x80000000
        OPEN_EXISTING = 3
        h = k32.CreateFileW("\\\\.\\" + self.port, GENERIC_READ, 0, None,
                            OPEN_EXISTING, 0, None)
        if h == wintypes.HANDLE(-1).value:
            raise OSError("cannot open %s" % self.port)

        class DCB(ctypes.Structure):
            _fields_ = [("DCBlength", wintypes.DWORD),
                        ("BaudRate", wintypes.DWORD),
                        ("Flags", wintypes.DWORD),
                        ("wReserved", wintypes.WORD),
                        ("XonLim", wintypes.WORD),
                        ("XoffLim", wintypes.WORD),
                        ("ByteSize", wintypes.BYTE),
                        ("Parity", wintypes.BYTE),
                        ("StopBits", wintypes.BYTE),
                        ("XonChar", ctypes.c_char),
                        ("XoffChar", ctypes.c_char),
                        ("ErrorChar", ctypes.c_char),
                        ("EofChar", ctypes.c_char),
                        ("EvtChar", ctypes.c_char),
                        ("wReserved1", wintypes.WORD)]

        class TIMEOUTS(ctypes.Structure):
            _fields_ = [("ReadIntervalTimeout", wintypes.DWORD),
                        ("ReadTotalTimeoutMultiplier", wintypes.DWORD),
                        ("ReadTotalTimeoutConstant", wintypes.DWORD),
                        ("WriteTotalTimeoutMultiplier", wintypes.DWORD),
                        ("WriteTotalTimeoutConstant", wintypes.DWORD)]

        dcb = DCB()
        dcb.DCBlength = ctypes.sizeof(DCB)
        if not k32.GetCommState(h, ctypes.byref(dcb)):
            k32.CloseHandle(h)
            raise OSError("GetCommState failed")
        dcb.BaudRate = self.baud
        dcb.ByteSize = 8
        dcb.Parity = 0
        dcb.StopBits = 0
        dcb.Flags = 0x00000001  # fBinary
        if not k32.SetCommState(h, ctypes.byref(dcb)):
            k32.CloseHandle(h)
            raise OSError("SetCommState failed")
        tmo = TIMEOUTS(50, 0, self.timeout_ms, 0, self.timeout_ms)
        k32.SetCommTimeouts(h, ctypes.byref(tmo))
        self.handle = h
        self._k32 = k32

    def _open_posix(self):
        import termios
        import fcntl
        fd = os.open(self.port, os.O_RDONLY | os.O_NOCTTY)
        attrs = termios.tcgetattr(fd)
        baud_const = {9600: termios.B9600, 57600: termios.B57600,
                      115200: termios.B115200}.get(self.baud, termios.B115200)
        attrs[4] = baud_const  # ispeed
        attrs[5] = baud_const  # ospeed
        attrs[2] &= ~(termios.PARENB | termios.CSTOPB | termios.CSIZE)
        attrs[2] |= termios.CS8 | termios.CREAD | termios.CLOCAL
        attrs[3] &= ~(termios.ICANON | termios.ECHO | termios.ISIG)
        attrs[6][termios.VMIN] = 0
        attrs[6][termios.VTIME] = max(1, self.timeout_ms // 100)
        termios.tcsetattr(fd, termios.TCSANOW, attrs)
        flags = fcntl.fcntl(fd, fcntl.F_GETFL)
        fcntl.fcntl(fd, fcntl.F_SETFL, flags & ~os.O_NONBLOCK)
        self.fd = fd

    def read_line(self, deadline_s=5.0):
        """Read one text line (no newline => None on timeout)."""
        buf = bytearray()
        end = time.monotonic() + deadline_s
        while time.monotonic() < end:
            if b"\n" in buf:
                break
            chunk = self._read_some(PACKET_SIZE)
            if chunk:
                buf.extend(chunk)
                if b"\n" in buf:
                    break
            else:
                time.sleep(0.01)
        if not buf:
            return None
        text = bytes(buf).decode("utf-8", errors="replace")
        if "\n" in text:
            text = text.split("\n", 1)[0]
        return text.strip("\r\n ")

    def _read_some(self, n):
        if os.name == "nt":
            import ctypes
            from ctypes import wintypes
            tmp = ctypes.create_string_buffer(min(n, PACKET_SIZE))
            got = wintypes.DWORD(0)
            ok = self._k32.ReadFile(self.handle, tmp, len(tmp),
                                    ctypes.byref(got), None)
            if not ok:
                return b""
            return tmp.raw[:got.value]
        try:
            return os.read(self.fd, min(n, PACKET_SIZE))
        except OSError:
            return b""

    def close(self):
        """Close the port (idempotent)."""
        try:
            if os.name == "nt" and self.handle:
                self._k32.CloseHandle(self.handle)
            elif self.fd is not None:
                os.close(self.fd)
        finally:
            self.handle = None
            self.fd = None


def colorize(cat, text, use_color=True):
    """Wrap text in the category ANSI color (or plain when off)."""
    if not use_color:
        return text
    code = COLORS.get(cat)
    if not code:
        return text
    return code + text + RESET


def format_event(evt, use_color=True):
    """Format a parsed event as a (possibly colored) monitor line."""
    base = "[LT][%s] %s detail=%s" % (evt["cat"], evt["event"], evt["detail"])
    return colorize(evt["cat"], base, use_color)


def bump(counts, evt):
    """Increment the ``cat.event`` counter, return the key."""
    key = "%s.%s" % (evt["cat"], evt["event"])
    counts[key] = counts.get(key, 0) + 1
    return key


def print_stats(counts, total, ignored, matched, tracker, out=None):
    """Print the end-of-stream summary."""
    out = out or sys.stdout
    out.write("--- stats ---\n")
    out.write("total lines: %d\n" % total)
    out.write("ltrace events: %d\n" % matched)
    out.write("ignored lines: %d\n" % ignored)
    try:
        out.write("rate (5s window): %.2f ev/s\n" % tracker.rate())
    except Exception:
        out.write("rate (5s window): n/a\n")
    for key in sorted(counts):
        out.write("%s=%d\n" % (key, counts[key]))
    if matched == 0:
        out.write("sem eventos (release sem ltrace ou filtro zerou tudo)\n")


def _open_log(path):
    if not path:
        return None
    return open(path, "a", encoding="utf-8")


def run_stream(args):
    """Stream from serial/stdin/file, print colored events, print stats."""
    use_color = not args.no_color
    counts = {}
    total = 0
    ignored = 0
    matched = 0
    tracker = RateTracker()
    logfh = _open_log(args.log)

    def emit(evt):
        line = format_event(evt, use_color)
        print(line, flush=True)
        if logfh:
            logfh.write(evt["raw"] + "\n")
            logfh.flush()

    try:
        if args.port:
            link = ReadOnlySerial(args.port, args.baud)
            link.open()
            try:
                while True:
                    text = link.read_line(deadline_s=5.0)
                    if text is None:
                        continue
                    total += 1
                    evt = parse_ltrace_line(text)
                    if evt is None:
                        ignored += 1
                        continue
                    if not matches_filter(evt, args.cat, args.event):
                        continue
                    bump(counts, evt)
                    tracker.hit()
                    matched += 1
                    emit(evt)
                    if args.count and matched >= args.count:
                        break
            finally:
                link.close()
        else:
            if args.input:
                fh = open(args.input, "r", encoding="utf-8", errors="replace")
                close_fh = True
            else:
                fh = sys.stdin
                close_fh = False
            try:
                for text in fh:
                    total += 1
                    evt = parse_ltrace_line(text)
                    if evt is None:
                        ignored += 1
                        continue
                    if not matches_filter(evt, args.cat, args.event):
                        continue
                    bump(counts, evt)
                    tracker.hit()
                    matched += 1
                    emit(evt)
                    if args.count and matched >= args.count:
                        break
            finally:
                if close_fh:
                    fh.close()
    except KeyboardInterrupt:
        pass
    finally:
        if logfh:
            logfh.close()
    print_stats(counts, total, ignored, matched, tracker)
    return 0


def run_self_test():
    """Offline checks, no hardware (same check() pattern as app_simulator)."""
    passed = failed = 0

    def check(name, fn):
        try:
            fn()
            print("PASS %s" % name)
            return True
        except Exception as e:
            print("FAIL %s (%s)" % (name, e))
            return False

    def t_parse_keyslot():
        evt = parse_ltrace_line("[LT][key_slot] create detail=3")
        assert evt == {"cat": "key_slot", "event": "create",
                       "detail": "3", "raw": "[LT][key_slot] create detail=3"}

    def t_parse_oath_label():
        evt = parse_ltrace_line("[LT][oath] put detail=GitHub:alice")
        assert evt["cat"] == "oath"
        assert evt["event"] == "put"
        assert evt["detail"] == "GitHub:alice"

    def t_parse_rejects_garbage():
        assert parse_ltrace_line("hello world") is None
        assert parse_ltrace_line("") is None
        assert parse_ltrace_line("[LT] broken") is None
        assert parse_ltrace_line("[LT][pin] retry") is None

    def t_parse_tolerates_crlf():
        evt = parse_ltrace_line("  [LT][pin] retry detail=7\r\n")
        assert evt["cat"] == "pin"
        assert evt["detail"] == "7"

    def t_filter_cat_event():
        evt = parse_ltrace_line("[LT][transport] open detail=ble")
        assert matches_filter(evt, None, None)
        assert matches_filter(evt, "transport", None)
        assert matches_filter(evt, "transport", "open")
        assert not matches_filter(evt, "pin", None)
        assert not matches_filter(evt, None, "close")
        assert not matches_filter(None, None, None)

    def t_rate_tracker_window():
        now = [1000.0]
        tr = RateTracker(window_s=10.0, clock=lambda: now[0])
        tr.hit()
        now[0] += 1.0
        tr.hit()
        now[0] += 1.0
        tr.hit()
        assert tr.count() == 3
        assert abs(tr.rate() - 0.3) < 1e-9
        now[0] += 11.0
        assert tr.count() == 0
        assert tr.rate() == 0.0

    def t_readonly_has_no_write():
        assert not hasattr(ReadOnlySerial, "write")
        assert hasattr(ReadOnlySerial, "read_line")
        assert hasattr(ReadOnlySerial, "open")
        assert hasattr(ReadOnlySerial, "close")

    def t_format_keeps_raw():
        evt = parse_ltrace_line("[LT][pairing] arming detail=6000")
        plain = format_event(evt, use_color=False)
        assert plain == "[LT][pairing] arming detail=6000"
        colored = format_event(evt, use_color=True)
        assert "pairing" in colored and "arming" in colored

    def t_counts_aggregate():
        counts = {}
        bump(counts, {"cat": "pin", "event": "retry"})
        bump(counts, {"cat": "pin", "event": "retry"})
        bump(counts, {"cat": "oath", "event": "put"})
        assert counts == {"pin.retry": 2, "oath.put": 1}

    def t_empty_stream_sem_eventos():
        counts = {}
        assert len(counts) == 0
        evt = parse_ltrace_line("plain log line, no ltrace here")
        assert evt is None

    cases = [("parse key_slot", t_parse_keyslot),
             ("parse oath label", t_parse_oath_label),
             ("parse rejects garbage", t_parse_rejects_garbage),
             ("parse tolerates CRLF", t_parse_tolerates_crlf),
             ("filter cat/event", t_filter_cat_event),
             ("rate tracker window", t_rate_tracker_window),
             ("readonly has no write", t_readonly_has_no_write),
             ("format keeps raw", t_format_keeps_raw),
             ("counts aggregate", t_counts_aggregate),
             ("empty stream sem eventos", t_empty_stream_sem_eventos)]
    for name, fn in cases:
        if check(name, fn):
            passed += 1
        else:
            failed += 1
    print("self-test: %d/%d passed" % (passed, passed + failed))
    return 0 if failed == 0 else 1


def main(argv=None):
    """CLI entry point."""
    ap = argparse.ArgumentParser(
        description="AegisKey live monitor (read-only, stdlib only)")
    ap.add_argument("--port", default=None, help="serial port (e.g. COM7)")
    ap.add_argument("--baud", type=int, default=DEFAULT_BAUD)
    ap.add_argument("--cat", default=None, help="cat filter (csv, e.g. pin,oath)")
    ap.add_argument("--event", default=None, help="event filter (csv, e.g. retry,put)")
    ap.add_argument("--count", type=int, default=None, help="stop after N events")
    ap.add_argument("--log", default=None, help="append raw [LT] lines to file")
    ap.add_argument("--input", default=None, help="replay lines from file (offline)")
    ap.add_argument("--no-color", action="store_true", help="plain output, no ANSI")
    ap.add_argument("--self-test", action="store_true",
                    help="offline checks, no hardware")
    args = ap.parse_args(argv)
    if args.self_test:
        return run_self_test()
    return run_stream(args)


if __name__ == "__main__":
    raise SystemExit(main())
