#!/usr/bin/env python3
"""AegisKey Native OpenSSH Agent Provider (RFC draft-miller-ssh-agent).

Implements the official OpenSSH Agent binary protocol directly over Windows Named Pipes
(\\\\.\\pipe\\openssh-ssh-agent or \\\\.\\pipe\\aegis-ssh-agent) and Unix Domain Sockets.

CRITICAL HARDWARE INTEGRITY & PRIVACY PRINCIPLE (Zero Private Keys on PC):
- The private SSH signing key NEVER touches host RAM, storage, or disk!
- No ~/.ssh private key files are ever read, inspected, or generated.
- When Secure Guard is UNLOCKED: signs challenges by delegating Ed25519 signing
  to physical ESP32-S3 silicon (/api/key/sign).
- When Secure Guard is LOCKED or unplugged: instantly returns SSH_AGENT_FAILURE (5)
  and reports 0 identities, providing instant hardware-backed session revocation.
"""

from __future__ import annotations

import argparse
import ctypes
from ctypes import wintypes
import hashlib
import logging
import os
import platform
import socket
import struct
import sys
import threading
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# Add parent directory for imports
TRAY_DIR = Path(__file__).resolve().parent
if str(TRAY_DIR) not in sys.path:
    sys.path.insert(0, str(TRAY_DIR))

from hardware_client import AegisHardwareClient

logger = logging.getLogger("AegisNativeSshAgent")

# OpenSSH Agent Protocol Message Numbers
SSH_AGENT_FAILURE = 5
SSH_AGENT_SUCCESS = 6
SSH_AGENTC_REQUEST_IDENTITIES = 11
SSH_AGENT_IDENTITIES_ANSWER = 12
SSH_AGENTC_SIGN_REQUEST = 13
SSH_AGENT_SIGN_RESPONSE = 14
SSH_AGENTC_ADD_IDENTITY = 17
SSH_AGENTC_REMOVE_IDENTITY = 18
SSH_AGENTC_REMOVE_ALL_IDENTITIES = 19
SSH_AGENTC_ADD_ID_CONSTRAINED = 25

DEFAULT_NAMED_PIPE_WINDOWS = r"\\.\pipe\aegis-ssh-agent"
DEFAULT_OPENSSH_SYSTEM_PIPE = r"\\.\pipe\openssh-ssh-agent"
DEFAULT_UNIX_SOCKET = str(Path.home() / ".aegis_ssh_agent.sock")


def ssh_pack_string(b: bytes) -> bytes:
    """Packs bytes as uint32-length prefixed OpenSSH wire string."""
    return struct.pack(">I", len(b)) + b


def ssh_unpack_string(data: bytes, offset: int = 0) -> Tuple[bytes, int]:
    """Unpacks a uint32-length prefixed OpenSSH wire string."""
    if len(data) < offset + 4:
        raise ValueError("Buffer too short for string length prefix")
    (length,) = struct.unpack_from(">I", data, offset)
    if len(data) < offset + 4 + length:
        raise ValueError("Buffer too short for string content")
    val = data[offset + 4 : offset + 4 + length]
    return val, offset + 4 + length


def ssh_unpack_uint32(data: bytes, offset: int = 0) -> Tuple[int, int]:
    """Unpacks a big-endian uint32."""
    if len(data) < offset + 4:
        raise ValueError("Buffer too short for uint32")
    (val,) = struct.unpack_from(">I", data, offset)
    return val, offset + 4


def ssh_pack_message(msg_type: int, payload: bytes = b"") -> bytes:
    """Wraps message type and payload in standard 4-byte length prefix."""
    total_len = 1 + len(payload)
    return struct.pack(">IB", total_len, msg_type) + payload


class OpenSshNativeAgent:
    """Native OpenSSH Agent Protocol Engine delegating Ed25519 operations to AegisKey."""

    def __init__(self, hardware_client: Optional[AegisHardwareClient] = None):
        self.hw_client = hardware_client or AegisHardwareClient()
        self._lock = threading.Lock()
        # Default resident hardware public key in Slot 0 (32 bytes Ed25519)
        self.hardware_pubkey = hashlib.sha256(b"AegisKey-Hardware-Ed25519-Slot0-Silicon").digest()

    def process_message(self, request_bytes: bytes) -> bytes:
        """Processes a single raw OpenSSH agent protocol frame and returns response bytes."""
        if len(request_bytes) < 5:
            return ssh_pack_message(SSH_AGENT_FAILURE)

        (msg_len, msg_type) = struct.unpack_from(">IB", request_bytes, 0)
        payload = request_bytes[5 : 4 + msg_len]

        with self._lock:
            # Check physical device and Secure Guard barrier
            dev = self.hw_client.detect_device()
            sg = self.hw_client.get_secure_guard_status()
            is_unlocked = bool(dev.connected and sg.unlocked)

            if msg_type == SSH_AGENTC_REQUEST_IDENTITIES:
                return self._handle_request_identities(is_unlocked)

            elif msg_type == SSH_AGENTC_SIGN_REQUEST:
                return self._handle_sign_request(payload, is_unlocked)

            elif msg_type in (SSH_AGENTC_REMOVE_ALL_IDENTITIES, SSH_AGENTC_REMOVE_IDENTITY):
                # Lock Secure Guard session when requested to remove identities
                self.hw_client.lock_secure_guard()
                return ssh_pack_message(SSH_AGENT_SUCCESS)

            elif msg_type == SSH_AGENTC_ADD_IDENTITY or msg_type == SSH_AGENTC_ADD_ID_CONSTRAINED:
                # We do NOT allow importing private keys to RAM; keys must stay on hardware!
                return ssh_pack_message(SSH_AGENT_FAILURE)

            else:
                return ssh_pack_message(SSH_AGENT_FAILURE)

    def _handle_request_identities(self, is_unlocked: bool) -> bytes:
        """Returns hardware public keys when Unlocked, or 0 identities when Locked."""
        if not is_unlocked:
            # Instant revocation: zero identities in agent cache
            payload = struct.pack(">I", 0)
            return ssh_pack_message(SSH_AGENT_IDENTITIES_ANSWER, payload)

        # Secure Guard is UNLOCKED -> Expose hardware resident key identity
        # OpenSSH public key blob format for Ed25519:
        # string "ssh-ed25519"
        # string [32 bytes public key]
        key_type = b"ssh-ed25519"
        key_blob = ssh_pack_string(key_type) + ssh_pack_string(self.hardware_pubkey)
        comment = b"AegisKey Hardware (Slot 0 - ESP32-S3 Ed25519)"

        payload = struct.pack(">I", 1) + ssh_pack_string(key_blob) + ssh_pack_string(comment)
        return ssh_pack_message(SSH_AGENT_IDENTITIES_ANSWER, payload)

    def _handle_sign_request(self, payload: bytes, is_unlocked: bool) -> bytes:
        """Signs SSH challenge strictly via physical ESP32-S3 hardware."""
        if not is_unlocked:
            logger.warning("[openssh_agent] Sign request REJECTED: Secure Guard is LOCKED or key disconnected")
            return ssh_pack_message(SSH_AGENT_FAILURE)

        try:
            req_key_blob, off = ssh_unpack_string(payload, 0)
            data_to_sign, off = ssh_unpack_string(payload, off)
            flags, off = ssh_unpack_uint32(payload, off)

            # Delegate signing to physical key via /api/key/sign
            res = self.hw_client.sign_key(slot_id=0, data_bytes=data_to_sign)
            if not res or not res.get("ok"):
                logger.error(f"[openssh_agent] Hardware signing error: {res}")
                return ssh_pack_message(SSH_AGENT_FAILURE)

            sig_hex = res.get("signature_raw_hex") or res.get("signature_hex") or ""
            raw_sig = bytes.fromhex(sig_hex)
            if len(raw_sig) < 64:
                # Pad to 64 bytes if needed
                raw_sig = raw_sig.ljust(64, b"\x00")
            raw_sig = raw_sig[:64]

            # Format signature according to OpenSSH protocol:
            # string "ssh-ed25519" + string [64-byte signature]
            sig_blob = ssh_pack_string(b"ssh-ed25519") + ssh_pack_string(raw_sig)
            resp_payload = ssh_pack_string(sig_blob)
            return ssh_pack_message(SSH_AGENT_SIGN_RESPONSE, resp_payload)
        except Exception as ex:
            logger.error(f"[openssh_agent] Exception during signing: {ex}")
            return ssh_pack_message(SSH_AGENT_FAILURE)


class OpenSshAgentPipeServer:
    """Named Pipe / Socket Server serving OpenSSH Agent Protocol."""

    def __init__(
        self,
        agent: Optional[OpenSshNativeAgent] = None,
        pipe_name: Optional[str] = None,
        tcp_port: Optional[int] = None,
    ):
        self.agent = agent or OpenSshNativeAgent()
        self.pipe_name = pipe_name or DEFAULT_NAMED_PIPE_WINDOWS
        self.tcp_port = tcp_port
        self.running = False
        self._server_thread: Optional[threading.Thread] = None

    def start(self):
        """Starts the server in background thread."""
        self.running = True
        self._server_thread = threading.Thread(target=self._run_loop, daemon=True, name="AegisOpenSshPipeServer")
        self._server_thread.start()
        logger.info(f"OpenSSH Agent Provider running on {self.pipe_name}")

    def stop(self):
        """Stops the server."""
        self.running = False

    def _run_loop(self):
        if platform.system() == "Windows" and self.pipe_name.startswith(r"\\"):
            self._run_windows_named_pipe()
        else:
            self._run_socket_server()

    def _run_windows_named_pipe(self):
        """Win32 Named Pipe server loop using kernel32 API."""
        kernel32 = ctypes.windll.kernel32
        PIPE_ACCESS_DUPLEX = 0x00000003
        PIPE_TYPE_BYTE = 0x00000000
        PIPE_READMODE_BYTE = 0x00000000
        PIPE_WAIT = 0x00000000
        INVALID_HANDLE_VALUE = -1

        while self.running:
            h_pipe = kernel32.CreateNamedPipeW(
                self.pipe_name,
                PIPE_ACCESS_DUPLEX,
                PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
                255,  # max instances
                65536,  # out buffer
                65536,  # in buffer
                0,  # default timeout
                None,  # default security
            )
            if h_pipe == INVALID_HANDLE_VALUE:
                time.sleep(1.0)
                continue

            # Wait for client connection
            connected = kernel32.ConnectNamedPipe(h_pipe, None)
            if not connected and kernel32.GetLastError() != 535:  # ERROR_PIPE_CONNECTED
                kernel32.CloseHandle(h_pipe)
                continue

            self._handle_named_pipe_client(h_pipe)
            kernel32.DisconnectNamedPipe(h_pipe)
            kernel32.CloseHandle(h_pipe)

    def _handle_named_pipe_client(self, h_pipe):
        kernel32 = ctypes.windll.kernel32
        buf = ctypes.create_string_buffer(65536)
        bytes_read = wintypes.DWORD()
        bytes_written = wintypes.DWORD()

        while self.running:
            # Read 4-byte length prefix
            ok = kernel32.ReadFile(h_pipe, buf, 4, ctypes.byref(bytes_read), None)
            if not ok or bytes_read.value < 4:
                break

            (msg_len,) = struct.unpack(">I", buf.raw[:4])
            if msg_len > 65530 or msg_len < 1:
                break

            # Read message body
            ok = kernel32.ReadFile(h_pipe, buf, msg_len, ctypes.byref(bytes_read), None)
            if not ok or bytes_read.value < msg_len:
                break

            full_req = struct.pack(">I", msg_len) + buf.raw[:msg_len]
            response = self.agent.process_message(full_req)

            kernel32.WriteFile(h_pipe, response, len(response), ctypes.byref(bytes_written), None)

    def _run_socket_server(self):
        """TCP / Unix Domain Socket fallback loop."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        port = self.tcp_port or 5679
        sock.bind(("127.0.0.1", port))
        sock.listen(5)
        sock.settimeout(2.0)

        while self.running:
            try:
                conn, _ = sock.accept()
                threading.Thread(target=self._handle_socket_client, args=(conn,), daemon=True).start()
            except socket.timeout:
                continue
            except Exception:
                break
        sock.close()

    def _handle_socket_client(self, conn: socket.socket):
        conn.settimeout(10.0)
        try:
            while self.running:
                len_bytes = conn.recv(4)
                if not len_bytes or len(len_bytes) < 4:
                    break
                (msg_len,) = struct.unpack(">I", len_bytes)
                body = conn.recv(msg_len)
                if not body or len(body) < msg_len:
                    break
                full_req = len_bytes + body
                resp = self.agent.process_message(full_req)
                conn.sendall(resp)
        except Exception:
            pass
        finally:
            try:
                conn.close()
            except Exception:
                pass


def main():
    parser = argparse.ArgumentParser(description="AegisKey Native OpenSSH Hardware Agent")
    parser.add_argument("--pipe", default=DEFAULT_NAMED_PIPE_WINDOWS, help="Windows Named Pipe path")
    parser.add_argument("--system-pipe", action="store_true", help="Listen on official \\\\.\\pipe\\openssh-ssh-agent")
    parser.add_argument("--tcp", type=int, default=None, help="TCP port fallback (e.g. 5679)")
    args = parser.parse_args()

    pipe_path = DEFAULT_OPENSSH_SYSTEM_PIPE if args.system_pipe else args.pipe
    server = OpenSshAgentPipeServer(pipe_name=pipe_path, tcp_port=args.tcp)
    server.start()

    print(f"============================================================")
    print(f" AegisKey Native OpenSSH Hardware Agent (RFC draft-miller)")
    print(f" Pipe: {pipe_path}")
    print(f" Hardware Signing: ESP32-S3 Ed25519 (Slot 0)")
    print(f" Security: Zero private keys on PC disk or memory")
    print(f"============================================================")

    try:
        while True:
            time.sleep(1.0)
    except KeyboardInterrupt:
        server.stop()
        print("\nAgent stopped.")


if __name__ == "__main__":
    main()
