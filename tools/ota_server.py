#!/usr/bin/env python3
"""
AegisKey S3 OTA Update Server (Port 8899, dev only).
100% standard library Python (no pip dependencies).
Mirrors tools/server.py JSON + CORS conventions.

DEV NOTE: served firmware is a deterministic dummy blob so the
app-only-transport path can be tested end to end. Production blobs are
built and Ed25519-signed externally; this server never holds keys.
"""

import hashlib
import http.server
import json
import os
import socketserver
from urllib.parse import urlparse, parse_qs

PORT = 8899
HERE = os.path.dirname(os.path.abspath(__file__))
REGISTRY_PATH = os.path.join(HERE, "ota_registry.json")
REGISTRY_EXAMPLE = os.path.join(HERE, "ota_registry.json.example")

FIRMWARE_VERSION = "1.1.0-dev"
FIRMWARE_SIZE = 4096
# Dev placeholder: production manifest carries a real Ed25519 signature.
DEV_SIG_ED25519 = "00" * 64


def _firmware_blob(version=FIRMWARE_VERSION):
    """Deterministic dummy firmware blob for dev transport tests."""
    seed = hashlib.sha256(b"aegis-s3-ota-dev:" + version.encode()).digest()
    reps = (FIRMWARE_SIZE + len(seed) - 1) // len(seed)
    return (seed * reps)[:FIRMWARE_SIZE]


def load_registry(path=None):
    """Load registry from ota_registry.json, falling back to the example."""
    candidates = [p for p in (path, REGISTRY_PATH, REGISTRY_EXAMPLE) if p]
    for cand in candidates:
        if cand and os.path.isfile(cand):
            with open(cand, "r", encoding="utf-8") as fh:
                return json.load(fh)
    return {"devices": []}


def find_device(registry, serial):
    """Return the device entry for serial, or None."""
    for dev in registry.get("devices", []):
        if dev.get("serial") == serial:
            return dev
    return None


def build_manifest(registry, serial, current_fw=""):
    """Build the manifest dict for a registered serial, or None."""
    if find_device(registry, serial) is None:
        return None
    blob = _firmware_blob()
    return {
        "version": FIRMWARE_VERSION,
        "sha256": hashlib.sha256(blob).hexdigest(),
        "sig_ed25519": DEV_SIG_ED25519,
        "url": "/api/ota/firmware/%s" % FIRMWARE_VERSION,
        "size": len(blob),
    }


class OtaRequestHandler(http.server.BaseHTTPRequestHandler):
    server_version = "AegisOTA/1.0"

    def log_message(self, fmt, *args):  # keep dev output quiet
        pass

    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path == "/api/ota/validate":
            self.send_json_response({"error": "method_not_allowed"}, status=405)
            return
        if parsed.path == "/api/ota/manifest":
            qs = parse_qs(parsed.query)
            serial = (qs.get("serial") or [""])[0]
            fw = (qs.get("fw") or [""])[0]
            if not serial:
                self.send_json_response({"error": "serial_required"}, status=400)
                return
            manifest = build_manifest(load_registry(), serial, fw)
            if manifest is None:
                self.send_json_response({"error": "unregistered"}, status=403)
                return
            self.send_json_response(manifest)
            return
        if parsed.path.startswith("/api/ota/firmware/"):
            version = parsed.path.rsplit("/", 1)[-1]
            if version != FIRMWARE_VERSION:
                self.send_error(404, "Unknown firmware version")
                return
            blob = _firmware_blob(version)
            digest = hashlib.sha256(blob).hexdigest()
            self.send_response(200)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Content-Length", str(len(blob)))
            self.send_header("X-SHA256", digest)
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(blob)
            return
        self.send_error(404, "Endpoint not found")

    def do_POST(self):
        parsed = urlparse(self.path)
        if parsed.path != "/api/ota/validate":
            self.send_error(404, "Endpoint not found")
            return
        length = int(self.headers.get("Content-Length", 0) or 0)
        raw = self.rfile.read(length) if length > 0 else b""
        try:
            data = json.loads(raw.decode("utf-8")) if raw else {}
        except (ValueError, UnicodeDecodeError):
            self.send_json_response({"error": "invalid_json"}, status=400)
            return
        serial = data.get("serial")
        aaguid = data.get("aaguid")
        nonce = data.get("nonce")
        if not serial or not aaguid or not nonce:
            self.send_json_response({"error": "serial_aaguid_nonce_required"}, status=400)
            return
        if find_device(load_registry(), serial) is None:
            self.send_json_response({"allowed": False, "error": "unregistered"}, status=403)
            return
        self.send_json_response({"allowed": True, "serial": serial})

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()

    def do_PUT(self):
        self.send_json_response({"error": "method_not_allowed"}, status=405)

    def do_DELETE(self):
        self.send_json_response({"error": "method_not_allowed"}, status=405)

    def do_PATCH(self):
        self.send_json_response({"error": "method_not_allowed"}, status=405)

    def send_json_response(self, data, status=200):
        body = json.dumps(data, indent=2).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.send_header("Cache-Control", "no-cache")
        self.end_headers()
        self.wfile.write(body)


def serve_in_background(port=PORT):
    """Start the OTA server on a daemon thread (used by smoke tests)."""
    import threading

    socketserver.TCPServer.allow_reuse_address = True
    httpd = socketserver.TCPServer(("127.0.0.1", port), OtaRequestHandler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    return httpd


def main():
    print("AegisKey S3 OTA Server (dev) on http://localhost:%d" % PORT)
    socketserver.TCPServer.allow_reuse_address = True
    with socketserver.TCPServer(("", PORT), OtaRequestHandler) as httpd:
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\nShutting down OTA server...")


if __name__ == "__main__":
    main()
