#!/usr/bin/env python3
"""
AegisKey S3 WebAuthn & Management Server (Port 8888).
Serves the web/ suite and provides mock / bridge REST endpoints for FIDO2 / CTAP 2.3.
100% standard library Python (no external pip dependencies required).
"""

import http.server
import socketserver
import json
import os
import secrets
import base64
import time
import hashlib
from urllib.parse import urlparse, parse_qs

PORT = 8888
WEB_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "web")

# In-memory storage for WebAuthn RP simulation
STORED_CREDENTIALS = [
    {
        "id": "a4e29bf1c03d",
        "rpId": "localhost",
        "userName": "alice@aegiskey.dev",
        "displayName": "Alice Hamilton",
        "algo": "ES256 (P-256)",
        "signCount": 14,
        "createdAt": "2026-10-18T10:15:00Z"
    },
    {
        "id": "9c1184ffaa20",
        "rpId": "localhost",
        "userName": "alice.sec@gmail.com",
        "displayName": "Alice H.",
        "algo": "Ed25519",
        "signCount": 32,
        "createdAt": "2026-10-18T10:30:00Z"
    }
]

ACTIVE_CHALLENGES = {}

class AegisRequestHandler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=WEB_DIR, **kwargs)

    def do_GET(self):
        parsed = urlparse(self.path)

        if parsed.path == "/api/status":
            self.send_json_response({
                "status": "online",
                "product": "AegisKey S3 Authenticator",
                "chip": "ESP32-S3 (Dual Core Xtensa LX7 @ 240MHz)",
                "firmware": "1.0.0-rust",
                "vid": "0x303A",
                "pid": "0xAE61",
                "manufacturer": "Aegis Security",
                "serial": "AEGIS-S3-0001",
                "transports": ["CTAPHID", "CCID", "Keyboard", "WinUSB"],
                "efuse_master_key_provisioned": True,
                "encrypted_flash_active": True,
                "pin_retries_remaining": 8
            })
            return

        elif parsed.path == "/api/credentials":
            self.send_json_response(STORED_CREDENTIALS)
            return

        elif parsed.path == "/api/pin/status":
            self.send_json_response({
                "pin_set": True,
                "retries": 8,
                "min_pin_len": 4,
                "always_uv": True
            })
            return

        # Serve static files from web/
        super().do_GET()

    def do_POST(self):
        parsed = urlparse(self.path)
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length) if content_length > 0 else b""
        data = json.loads(body.decode("utf-8")) if body else {}

        if parsed.path == "/api/webauthn/register/options":
            challenge = secrets.token_bytes(32)
            challenge_b64 = base64.urlsafe_b64encode(challenge).decode("utf-8").rstrip("=")
            user_id = secrets.token_bytes(16)
            user_id_b64 = base64.urlsafe_b64encode(user_id).decode("utf-8").rstrip("=")

            username = data.get("username", "user@aegiskey.dev")
            ACTIVE_CHALLENGES[challenge_b64] = {"type": "register", "username": username}

            self.send_json_response({
                "challenge": challenge_b64,
                "rp": {
                    "name": "AegisKey Security Platform",
                    "id": "localhost"
                },
                "user": {
                    "id": user_id_b64,
                    "name": username,
                    "displayName": data.get("displayName", "AegisKey User")
                },
                "pubKeyCredParams": [
                    {"type": "public-key", "alg": -7},   # ES256
                    {"type": "public-key", "alg": -8},   # Ed25519
                    {"type": "public-key", "alg": -257}  # RS256
                ],
                "authenticatorSelection": {
                    "authenticatorAttachment": "cross-platform",
                    "residentKey": "required",
                    "userVerification": "preferred"
                },
                "timeout": 60000,
                "attestation": "direct"
            })
            return

        elif parsed.path == "/api/webauthn/register/verify":
            cred_id = secrets.token_hex(8)
            new_cred = {
                "id": cred_id,
                "rpId": "localhost",
                "userName": data.get("username", "user@aegiskey.dev"),
                "displayName": data.get("displayName", "AegisKey User"),
                "algo": "ES256 (P-256)",
                "signCount": 1,
                "createdAt": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
            }
            STORED_CREDENTIALS.append(new_cred)
            self.send_json_response({"status": "verified", "credential": new_cred})
            return

        elif parsed.path == "/api/webauthn/login/options":
            challenge = secrets.token_bytes(32)
            challenge_b64 = base64.urlsafe_b64encode(challenge).decode("utf-8").rstrip("=")
            ACTIVE_CHALLENGES[challenge_b64] = {"type": "login"}

            self.send_json_response({
                "challenge": challenge_b64,
                "rpId": "localhost",
                "timeout": 60000,
                "userVerification": "preferred"
            })
            return

        elif parsed.path == "/api/webauthn/login/verify":
            self.send_json_response({
                "status": "authenticated",
                "user": "alice@aegiskey.dev",
                "userPresenceVerified": True
            })
            return

        elif parsed.path == "/api/pin/set":
            self.send_json_response({"status": "pin_updated", "retries": 8})
            return

        self.send_error(404, "Endpoint not found")

    def send_json_response(self, data, status=200):
        response_bytes = json.dumps(data, indent=2).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(response_bytes)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.send_header("Cache-Control", "no-cache")
        self.end_headers()
        self.wfile.write(response_bytes)

def main():
    print("=" * 60)
    print(f"  AegisKey S3 Web Server & FIDO2 Bridge")
    print(f"  Listening on http://localhost:{PORT}")
    print(f"  Serving directory: {WEB_DIR}")
    print("=" * 60)
    server_address = ("", PORT)
    with socketserver.TCPServer(server_address, AegisRequestHandler) as httpd:
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\nShutting down AegisKey Web Server...")

if __name__ == "__main__":
    main()
