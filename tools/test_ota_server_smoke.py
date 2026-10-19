"""OTA server smoke test (TDD RED). Run: python tools/test_ota_server_smoke.py"""
import json
import os
import sys
import threading
import time
import urllib.request
import urllib.error
import hashlib

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__))))
import ota_server

BASE = "http://localhost:8899"


def post(path, payload):
    req = urllib.request.Request(
        BASE + path,
        data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req) as r:
            return r.status, json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        body = e.read().decode()
        try:
            return e.code, json.loads(body)
        except Exception:
            return e.code, {"raw": body}


def get(path, raw=False):
    try:
        with urllib.request.urlopen(BASE + path) as r:
            body = r.read()
            headers = dict(r.headers.items())
            if raw:
                return r.status, body, headers
            return r.status, json.loads(body.decode()), headers
    except urllib.error.HTTPError as e:
        body = e.read()
        try:
            return e.code, json.loads(body.decode()), dict(e.headers.items())
        except Exception:
            return e.code, body, dict(e.headers.items())


def main():
    srv = ota_server.serve_in_background(port=8899)
    time.sleep(0.3)
    try:
        # 1. validate allow for registered serial (first entry in example registry)
        reg = ota_server.load_registry()
        serials = [d["serial"] for d in reg["devices"]]
        assert len(serials) >= 2, "registry must have >= 2 example entries"
        s0 = serials[0]
        st, body = post("/api/ota/validate", {"serial": s0, "aaguid": reg["devices"][0]["aaguid"], "nonce": "abc"})
        assert st == 200 and body.get("allowed") is True, f"validate allow failed: {st} {body}"

        # 2. 403 for unknown serial
        st, body = post("/api/ota/validate", {"serial": "NOPE-0000", "aaguid": "00" * 16, "nonce": "x"})
        assert st == 403, f"unknown serial must be 403, got {st} {body}"

        # 3. manifest returns version/sha256/sig/url/size
        st, body, _ = get(f"/api/ota/manifest?serial={s0}&fw=1.0.0")
        for k in ("version", "sha256", "sig_ed25519", "url", "size"):
            assert k in body, f"manifest missing {k}: {body}"
        assert st == 200

        # 4. firmware binary bytes match sha256
        ver = body["version"]
        st, blob, headers = get(f"/api/ota/firmware/{ver}", raw=True)
        assert st == 200, f"firmware fetch failed: {st}"
        digest = hashlib.sha256(blob).hexdigest()
        assert digest == body["sha256"], f"sha256 mismatch {digest} != {body['sha256']}"
        assert len(blob) == body["size"]
        assert "X-SHA256" in headers or "X-sha256" in headers or "x-sha256" in {k.lower(): v for k, v in headers.items()}

        # 5. 400 on bad input (missing fields)
        st, body = post("/api/ota/validate", {"serial": s0})
        assert st == 400, f"bad input must be 400, got {st} {body}"

        # 6. manifest 403 for unknown serial
        st, body, _ = get("/api/ota/manifest?serial=NOPE-0000&fw=1.0.0")
        assert st == 403, f"manifest unknown serial must be 403, got {st}"

        print("OTA_SMOKE_OK")
    finally:
        srv.shutdown()


if __name__ == "__main__":
    main()
