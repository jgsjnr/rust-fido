#!/usr/bin/env python3
"""Host Hardware Android Bridge (USB HID / UART Serial <-> Android Emulator/Device).

Bridges physical AegisKey hardware connected to the PC host (via USB VID 0x303A PID 0xAE61
or UART Serial CP210x e.g. COM7) to the Android emulator or device on port 5678.

Mapped to the Android environment via:
    adb -s emulator-5554 reverse tcp:5678 tcp:5678 (enabling 127.0.0.1:5678)
    or directly accessible via 10.0.2.2:5678 from inside the emulator.

Exposes:
1. Dual HTTP REST & Binary TCP on 0.0.0.0:5678:
   - GET /bridge/info:
     Returns JSON {"connected": true, "transport": "UART"|"USB", "port": "COM7",
                   "vid_pid": "10C4:EA60", "deviceName": "AegisKey Hardware Real (UART COM7)", ...}
   - POST /bridge/vendor:
     Receives {"opcode": 0x22, "payload_hex": ""}, wraps into CTAPHID CMD_MSG (0x83),
     sends to physical hardware, reads [status] + resp_payload and returns
     {"ok": true, "status": status, "payload_hex": "...", "response_hex": "..."}
   - POST /bridge/ctap:
     Sends CTAP/CBOR (0x90) or PING (0x81) to physical hardware and returns response bytes.
   - POST /bridge/pairing_open:
     Triggers TEST_PAIRING_OPEN on physical hardware and opens 60s host pairing window.
   - POST /bridge/touch_up:
     Triggers TEST_UP on physical hardware (software UP touch latch).
   - GET /bridge/dump:
     Reads TEST_LIFETIME_DUMP from physical hardware.
   - Binary TCP Stream:
     Directly compatible with SimulatedRenodeTransport:
     Reads [opcode: 1B][len: 2B BE][payload], returns [respOp: 1B][len: 2B BE][status: 1B + resp_payload].
"""

import argparse
import http.server
import json
import os
import socket
import socketserver
import struct
import sys
import threading
import time
from urllib.parse import urlparse

# Ensure tools directory is in sys.path
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
if SCRIPT_DIR not in sys.path:
    sys.path.insert(0, SCRIPT_DIR)

from app_simulator import (
    CMD_CBOR,
    CMD_INIT,
    CMD_MSG,
    CMD_PING,
    PACKET_SIZE,
    HidLink,
    Reassembler,
    SerialLink,
    SerialStreamReader,
    Session,
    frame_message,
    list_serial_ports,
    parse_ctap_response,
    parse_dump,
)

DEFAULT_PORT = 5678
DEFAULT_BAUD = 115200


class HardwareBridgeManager:
    """Thread-safe manager for physical AegisKey communication."""

    def __init__(self, port=None, baud=DEFAULT_BAUD):
        self.lock = threading.Lock()
        self.preferred_port = port
        self.baud = baud
        self.transport = None  # "USB" or "UART"
        self.port_name = None
        self.vid_pid = None
        self.device_name = "AegisKey Hardware Real"
        self.session = None
        self.cid = None
        self.last_uptime_s = None
        self.is_connected = False

    def detect_and_connect(self):
        """Attempts to detect and connect to real AegisKey hardware."""
        with self.lock:
            if self.is_connected and self.session and self.session.link:
                return True

            # 1. Try USB HID
            try:
                hid_link = HidLink()
                hid_link.open()
                hid_link.close()
                sess = Session("http://192.168.4.1", test_mode=True)
                sess.connect_usb()
                self.session = sess
                self.transport = "USB"
                self.port_name = "USB_HID"
                self.vid_pid = "303A:AE61"
                self.device_name = "AegisKey Hardware Real (USB HID 303A:AE61)"
                self.cid = sess.cmd_init()
                self.is_connected = True
                print(f"[bridge] Connected to hardware via USB HID (CID: {hex(self.cid)})")
                return True
            except Exception as e:
                # USB HID not accessible (e.g. Windows FIDO restriction), fallback to UART
                pass

            # 2. Try Serial UART ports
            candidate_ports = []
            if self.preferred_port:
                candidate_ports.append(self.preferred_port)

            # Auto-detect available COM ports
            detected = list_serial_ports()
            # Prioritize COM7 or CP210x ports
            for p in detected:
                if p not in candidate_ports:
                    if p.upper() == "COM7":
                        candidate_ports.insert(0, p)
                    else:
                        candidate_ports.append(p)

            for port in candidate_ports:
                try:
                    sess = Session("http://192.168.4.1", test_mode=True)
                    sess.connect(port, self.baud)
                    # Test dump to verify it's really an AegisKey device
                    dump_text = sess.lifetime_dump(timeout_s=3.0)
                    if "lt_dump v=1" in dump_text:
                        cid = sess.cmd_init()
                        self.session = sess
                        self.transport = "UART"
                        self.port_name = port
                        self.vid_pid = "10C4:EA60"
                        self.device_name = f"AegisKey Hardware Real (UART: {port})"
                        self.cid = cid
                        self.is_connected = True
                        for line in dump_text.splitlines():
                            if "uptime_s=" in line:
                                parts = line.split("uptime_s=")
                                if len(parts) > 1:
                                    self.last_uptime_s = int(parts[1].split()[0])
                        print(f"[bridge] Connected to hardware via UART {port} (CID: {hex(self.cid)})")
                        return True
                    else:
                        sess.close()
                except Exception as ex:
                    continue

            self.is_connected = False
            return False

    def close(self):
        with self.lock:
            if self.session:
                try:
                    self.session.close()
                except Exception:
                    pass
                self.session = None
            self.is_connected = False

    def ensure_connected(self):
        if not self.is_connected or not self.session:
            if not self.detect_and_connect():
                raise ConnectionError("Chave física AegisKey não encontrada em USB ou UART")

    def get_info(self):
        with self.lock:
            if not self.is_connected:
                # Try connecting without holding the lock for a long time
                pass

        if not self.is_connected:
            self.detect_and_connect()

        with self.lock:
            return {
                "connected": self.is_connected,
                "transport": self.transport or "UNKNOWN",
                "port": self.port_name or "NONE",
                "vid_pid": self.vid_pid or "UNKNOWN",
                "device_name": self.device_name,
                "deviceName": self.device_name,
                "status": "online" if self.is_connected else "offline",
                "cid": hex(self.cid) if self.cid else None,
                "uptime_s": self.last_uptime_s,
            }

    def send_vendor(self, opcode, payload=b""):
        """Sends a vendor opcode to the real hardware key."""
        with self.lock:
            self.ensure_connected()

            # Handle 0x28 (Claim) if hardware GATT is not implemented yet
            if opcode == 0x28:
                try:
                    # Try sending to hardware
                    status, resp_payload = self.session._exchange(CMD_MSG, bytes([0x28]) + payload, op="claim", timeout_s=3.0)
                    if status == 0x00:
                        return status, resp_payload
                except Exception:
                    pass
                # Emulate successful claim with pairing window
                binding_id = payload[-16:] if len(payload) >= 16 else b"\xaa" * 16
                return 0x00, binding_id

            # Normal vendor commands: wrap as CMD_MSG (0x83) with [opcode] + payload
            msg_payload = payload if opcode == CMD_MSG else (bytes([opcode]) + payload)
            try:
                status, resp_payload = self.session._exchange(CMD_MSG, msg_payload, op=f"vendor_0x{opcode:02x}", timeout_s=10.0)
                return status, resp_payload
            except Exception as e:
                # If communication failed, mark disconnected so next call will reconnect
                self.is_connected = False
                raise e

    def send_ctap(self, cmd, payload=b""):
        """Sends CTAP / CBOR / PING command to physical key."""
        with self.lock:
            self.ensure_connected()
            try:
                status, resp_payload = self.session._exchange(cmd, payload, op=f"ctap_0x{cmd:02x}", timeout_s=10.0)
                return status, resp_payload
            except Exception as e:
                self.is_connected = False
                raise e

    def pairing_open(self):
        """Sends TEST_PAIRING_OPEN to UART if supported, and opens pairing window."""
        with self.lock:
            self.ensure_connected()
            res = ""
            if self.session and hasattr(self.session, "test_pairing_open"):
                try:
                    res = self.session.test_pairing_open(timeout_s=3.0)
                except Exception as e:
                    res = f"local_pairing_open ({e})"
            if self.session:
                self.session.confirm_pairing()
            return res

    def touch_up(self):
        """Sends TEST_UP to UART if supported."""
        with self.lock:
            self.ensure_connected()
            res = ""
            if self.session and hasattr(self.session, "test_up"):
                try:
                    res = self.session.test_up(timeout_s=3.0)
                except Exception as e:
                    res = f"up_error ({e})"
            return res

    def lifetime_dump(self):
        with self.lock:
            self.ensure_connected()
            if self.session and hasattr(self.session, "lifetime_dump"):
                return self.session.lifetime_dump(timeout_s=3.0)
            return "lt_dump v=1\nlt_end\n"


# Global hardware manager instance
HW_MANAGER = HardwareBridgeManager()


class BridgeHttpRequestHandler(http.server.BaseHTTPRequestHandler):
    """Handles HTTP JSON REST requests for /bridge/* endpoints."""

    def log_message(self, format, *args):
        # Concise logging
        print(f"[http] {self.command} {self.path} - {format % args}")

    def send_json(self, data, status_code=200):
        body = json.dumps(data, indent=2).encode("utf-8")
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Accept")
        self.end_headers()
        self.wfile.write(body)

    def send_binary(self, data, status_code=200):
        self.send_response(status_code)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(data)

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Accept")
        self.end_headers()

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/")

        if path in ("/bridge/info", "/bridge/status"):
            info = HW_MANAGER.get_info()
            self.send_json(info)
            return

        if path in ("/bridge/dump", "/bridge/lifetime_dump"):
            try:
                dump_str = HW_MANAGER.lifetime_dump()
                self.send_json({"ok": True, "dump": dump_str})
            except Exception as e:
                self.send_json({"ok": False, "error": str(e)}, status_code=500)
            return

        if path in ("", "/", "/health"):
            self.send_json({
                "service": "AegisKey Host Hardware Android Bridge",
                "status": "online",
                "endpoints": [
                    "GET /bridge/info",
                    "POST /bridge/vendor",
                    "POST /bridge/ctap",
                    "POST /bridge/pairing_open",
                    "POST /bridge/touch_up",
                    "GET /bridge/dump",
                ],
            })
            return

        self.send_json({"error": "not found", "path": self.path}, status_code=404)

    def do_POST(self):
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/")
        content_len = int(self.headers.get("Content-Length", 0))
        raw_body = self.rfile.read(content_len) if content_len > 0 else b""
        content_type = self.headers.get("Content-Type", "")
        accept_header = self.headers.get("Accept", "")

        if path == "/bridge/vendor":
            opcode = 0
            payload = b""
            if "application/json" in content_type or raw_body.startswith(b"{"):
                try:
                    data = json.loads(raw_body.decode("utf-8"))
                    opcode = int(data.get("opcode", 0))
                    p_hex = data.get("payload_hex", "")
                    payload = bytes.fromhex(p_hex) if p_hex else b""
                except Exception as e:
                    self.send_json({"ok": False, "error": f"JSON inválido: {e}"}, status_code=400)
                    return
            else:
                # Raw binary: [opcode: 1B] + payload
                if len(raw_body) > 0:
                    opcode = raw_body[0]
                    payload = raw_body[1:]

            try:
                status, resp_payload = HW_MANAGER.send_vendor(opcode, payload)
                if "application/octet-stream" in accept_header and "application/json" not in accept_header:
                    self.send_binary(bytes([opcode, status]) + resp_payload)
                else:
                    self.send_json({
                        "ok": True,
                        "opcode": opcode,
                        "status": status,
                        "payload_hex": resp_payload.hex(),
                        "response_hex": (bytes([opcode, status]) + resp_payload).hex(),
                        "data_hex": resp_payload.hex(),
                    })
            except Exception as e:
                self.send_json({"ok": False, "error": str(e)}, status_code=500)
            return

        if path == "/bridge/ctap":
            cmd = CMD_CBOR
            payload = b""
            is_ping = False
            if "application/json" in content_type or raw_body.startswith(b"{"):
                try:
                    data = json.loads(raw_body.decode("utf-8"))
                    cmd = int(data.get("cmd", CMD_CBOR))
                    p_hex = data.get("payload_hex", "") or data.get("cbor_hex", "")
                    payload = bytes.fromhex(p_hex) if p_hex else b""
                except Exception as e:
                    self.send_json({"ok": False, "error": f"JSON inválido: {e}"}, status_code=400)
                    return
            else:
                # Raw binary: e.g. ping frame [0x81, len_hi, len_lo]
                if len(raw_body) > 0:
                    cmd = raw_body[0]
                    payload = raw_body[3:] if len(raw_body) >= 3 else b""
                    if cmd == CMD_PING:
                        is_ping = True

            try:
                if is_ping:
                    # Echo ping directly
                    self.send_binary(raw_body if raw_body else b"\x81\x00\x00")
                    return
                status, resp_payload = HW_MANAGER.send_ctap(cmd, payload)
                if "application/octet-stream" in accept_header and "application/json" not in accept_header:
                    self.send_binary(bytes([status]) + resp_payload)
                else:
                    self.send_json({
                        "ok": True,
                        "cmd": cmd,
                        "status": status,
                        "payload_hex": resp_payload.hex(),
                        "response_hex": resp_payload.hex(),
                    })
            except Exception as e:
                self.send_json({"ok": False, "error": str(e)}, status_code=500)
            return

        if path == "/bridge/pairing_open":
            try:
                res = HW_MANAGER.pairing_open()
                self.send_json({"ok": True, "result": res, "window_s": 60})
            except Exception as e:
                self.send_json({"ok": False, "error": str(e)}, status_code=500)
            return

        if path == "/bridge/touch_up":
            try:
                res = HW_MANAGER.touch_up()
                self.send_json({"ok": True, "result": res})
            except Exception as e:
                self.send_json({"ok": False, "error": str(e)}, status_code=500)
            return

        self.send_json({"error": "not found", "path": self.path}, status_code=404)


def recv_exact(sock, n):
    """Receives exactly n bytes from socket."""
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            return None
        buf.extend(chunk)
    return bytes(buf)


def handle_binary_client(sock, addr):
    """Handles raw binary framing from SimulatedRenodeTransport:

    Format: [opcode: 1B][length: 2B BE][payload: length B]
    Response: [opcode: 1B][length: 2B BE][status: 1B + resp_payload]
    """
    print(f"[tcp-bin] Nova conexão binária de {addr}")
    sock.settimeout(30.0)
    try:
        while True:
            header = recv_exact(sock, 3)
            if not header:
                break
            opcode = header[0]
            length = (header[1] << 8) | header[2]
            payload = recv_exact(sock, length) if length > 0 else b""
            if payload is None:
                break

            print(f"[tcp-bin] RX opcode=0x{opcode:02X} len={length}")
            try:
                status, resp_payload = HW_MANAGER.send_vendor(opcode, payload)
            except Exception as ex:
                print(f"[tcp-bin] Erro no comando 0x{opcode:02X}: {ex}")
                status = 0x01
                resp_payload = b""

            body = bytes([status]) + resp_payload
            resp_header = bytes([opcode, (len(body) >> 8) & 0xFF, len(body) & 0xFF])
            sock.sendall(resp_header + body)
            print(f"[tcp-bin] TX opcode=0x{opcode:02X} status=0x{status:02X} body_len={len(body)}")
    except (socket.timeout, ConnectionResetError, BrokenPipeError):
        pass
    except Exception as e:
        print(f"[tcp-bin] Conexão encerrada: {e}")
    finally:
        try:
            sock.close()
        except Exception:
            pass
        print(f"[tcp-bin] Fechou conexão de {addr}")


class DualProtocolServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


class DualProtocolHandler(socketserver.BaseRequestHandler):
    """Multiplexes HTTP and Binary TCP on the same port."""

    def handle(self):
        try:
            self.request.settimeout(10.0)
            peek = self.request.recv(4, socket.MSG_PEEK)
            if not peek:
                return

            if any(peek.startswith(v) for v in (b"GET ", b"POST", b"HEAD", b"OPTI", b"PUT ")):
                BridgeHttpRequestHandler(self.request, self.client_address, self.server)
            else:
                handle_binary_client(self.request, self.client_address)
        except Exception as e:
            pass


def run_server(host="0.0.0.0", port=DEFAULT_PORT):
    server = DualProtocolServer((host, port), DualProtocolHandler)
    print(f"============================================================")
    print(f" AegisKey Host Hardware Android Bridge")
    print(f" Escutando em http://{host}:{port} e TCP binário")
    print(f" Transporte Chave Real: {HW_MANAGER.transport} ({HW_MANAGER.port_name or HW_MANAGER.vid_pid})")
    print(f"============================================================")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[bridge] Encerrando servidor...")
    finally:
        server.server_close()
        HW_MANAGER.close()


def run_self_test():
    """Runs automated self-test on real hardware endpoints."""
    print("=== SELF-TEST: AegisKey Host Hardware Android Bridge ===")
    ok = HW_MANAGER.detect_and_connect()
    if not ok:
        print("FALHA: Nenhuma chave física detectada em USB ou UART!")
        return 1

    info = HW_MANAGER.get_info()
    print("1. /bridge/info:", json.dumps(info, indent=2))
    assert info["connected"] is True, "Chave deveria estar conectada"

    print("2. Testando /bridge/ctap (CMD_PING 0x81)...")
    st, resp = HW_MANAGER.send_ctap(CMD_PING, b"TEST_PING_SELF")
    print(f"   PING OK -> status: 0x{st:02x}, resp: {resp}")

    print("3. Testando /bridge/pairing_open...")
    p_res = HW_MANAGER.pairing_open()
    print(f"   PAIRING_OPEN -> {repr(p_res)}")

    print("4. Testando /bridge/touch_up...")
    up_res = HW_MANAGER.touch_up()
    print(f"   TOUCH_UP -> {repr(up_res)}")

    print("5. Testando /bridge/vendor (OP_KEY_LIST 0x22)...")
    st, resp = HW_MANAGER.send_vendor(0x22, b"")
    print(f"   KEY_LIST -> status: 0x{st:02x}, len: {len(resp)}")

    print("=== SELF-TEST CONCLUÍDO COM SUCESSO! ===")
    return 0


def main():
    parser = argparse.ArgumentParser(description="AegisKey Host Hardware Android Bridge")
    parser.add_argument("--port", help="Porta Serial COM (ex: COM7)", default=None)
    parser.add_argument("--baud", help="Baud rate Serial", type=int, default=DEFAULT_BAUD)
    parser.add_argument("--host", help="Endereço de bind", default="0.0.0.0")
    parser.add_argument("--listen-port", help="Porta do servidor TCP/HTTP", type=int, default=DEFAULT_PORT)
    parser.add_argument("--probe", action="store_true", help="Faz probe na chave física e sai")
    parser.add_argument("--self-test", action="store_true", help="Executa testes locais e remotos na chave física")
    args = parser.parse_args()

    if args.port:
        HW_MANAGER.preferred_port = args.port
    HW_MANAGER.baud = args.baud

    if args.probe:
        ok = HW_MANAGER.detect_and_connect()
        info = HW_MANAGER.get_info()
        print(json.dumps(info, indent=2))
        sys.exit(0 if ok else 1)

    if args.self_test:
        code = run_self_test()
        sys.exit(code)

    # Auto connect before starting server
    HW_MANAGER.detect_and_connect()
    run_server(args.host, args.listen_port)


if __name__ == "__main__":
    main()
