import sys
import os
import time
import hashlib

sys.path.insert(0, os.path.abspath("tools"))
from app_simulator import (
    Session,
    CMD_MSG,
    CMD_CBOR,
    CTAP_CMD_MAKE_CREDENTIAL,
    CTAP_CMD_GET_INFO,
    parse_ctap_response
)

try:
    import cbor2
except ImportError:
    from e2e_harness import cbor_decode, cbor_encode
    class CborWrapper:
        dumps = staticmethod(cbor_encode)
        loads = staticmethod(lambda b: cbor_decode(b)[0])
    cbor2 = CborWrapper

def run_test():
    print("================================================================")
    print("  AEGISKEY FIDO2 / WEBAUTHN S24 COMPATIBILITY VERIFICATION")
    print("================================================================")
    sess = Session("http://127.0.0.1", test_mode=True)
    print("[*] Connecting to COM7 @ 115200 bps...")
    sess.connect("COM7", 115200)
    time.sleep(1.0)

    try:
        print("[*] Initializing CTAPHID CID...")
        cid = sess.cmd_init()
        print(f"[+] CID allocated: 0x{cid:08X}")

        def send_sg(opcode, req_dict):
            req_bytes = cbor2.dumps(req_dict) if req_dict else b""
            status, resp_bytes = sess._exchange(CMD_MSG, bytes([opcode]) + req_bytes, op=f"sg_0x{opcode:02X}")
            data = cbor2.loads(resp_bytes) if resp_bytes else {}
            return status, data

        # Step 1: Query Secure Guard Status
        print("\n[Step 1] Verifying Secure Guard Status (0x3A)...")
        status, st = send_sg(0x3A, {})
        print(f"    Status code: 0x{status:02X}, State: {st.get('state_name')} ({st.get('state')}), Provisioned: {st.get('provisioned')}, Unlocked: {st.get('unlocked')}")

        if not st.get("provisioned"):
            print("[*] Provisioning Secure Guard with PIN '2707'...")
            status, res = send_sg(0x3B, {"action": "provision", "pin": b"2707"})
            print(f"    Provision response: 0x{status:02X}, {res}")
            assert status == 0x00 and res.get("success") is True, f"Provisioning failed: {res}"

        # Step 2: Unlock Secure Guard if not unlocked
        if not st.get("unlocked"):
            print("\n[Step 2] Unlocking Secure Guard with PIN '2707'...")
            status, res = send_sg(0x3B, {"action": "unlock", "pin": b"2707"})
            print(f"    Unlock response: 0x{status:02X}, {res}")
            assert status == 0x00 and res.get("success") is True, f"Unlock failed: {res}"

        # Re-check status
        status, st = send_sg(0x3A, {})
        print(f"[+] Secure Guard unlocked: {st.get('unlocked')}")
        assert st.get("unlocked") is True, "Secure Guard must be unlocked!"

        # Step 3: Call authenticatorGetInfo (0x04)
        print("\n[Step 3] Sending CTAP2 authenticatorGetInfo (0x04)...")
        st_code, info_bytes = sess.ctap(CTAP_CMD_GET_INFO, "", op="get_info")
        print(f"    CTAP status code: 0x{st_code:02X}, payload len: {len(info_bytes)} bytes")
        assert st_code == 0x00, f"GetInfo returned error 0x{st_code:02X}"

        info_dict = cbor2.loads(info_bytes)
        print(f"    Info map keys: {list(info_dict.keys())}")
        versions = info_dict.get(1, [])
        options = info_dict.get(4, {})
        print(f"    FIDO Versions supported: {versions}")
        print(f"    CTAP Options: {options}")

        # WebAuthn on Android / Galaxy S24 checks these options:
        # clientPin: whether PIN is set / available
        # rk: resident key supported
        # up: user presence supported
        # uv: user verification supported
        client_pin = options.get("clientPin")
        print(f"    -> clientPin: {client_pin}")
        print(f"    -> rk: {options.get('rk')}")
        print(f"    -> up: {options.get('up')}")
        print(f"    -> uv: {options.get('uv')}")

        # Step 4: Arm User Presence via TEST_UP to simulate physical touch
        print("\n[Step 4] Latching User Presence (simulating touch window)...")
        sess.confirm_pairing()
        resp = sess.send_text_line("TEST_UP", timeout_s=2.0)
        print(f"    TEST_UP response: {resp.strip() if resp else 'None'}")

        # Step 5: Test authenticatorMakeCredential (0x01)
        print("\n[Step 5] Simulating WebAuthn Registration (authenticatorMakeCredential)...")
        client_data_hash = hashlib.sha256(b"{\"type\":\"webauthn.create\",\"challenge\":\"dGVzdGNoYWxsZW5nZQ\"}").digest()
        rp = {"id": "webauthn.io", "name": "WebAuthn Demo"}
        user = {"id": b"user-s24-test", "name": "s24@aegiskey.dev", "displayName": "Galaxy S24 Tester"}
        pub_key_cred_params = [{"type": "public-key", "alg": -7}] # ES256
        
        mc_map = {
            1: client_data_hash,
            2: rp,
            3: user,
            4: pub_key_cred_params,
            7: {"rk": True, "up": True}
        }
        mc_cbor = cbor2.dumps(mc_map)
        
        mc_status, mc_resp = sess.ctap(CTAP_CMD_MAKE_CREDENTIAL, mc_cbor.hex(), op="make_credential")
        print(f"    MakeCredential status: 0x{mc_status:02X}")
        if mc_status == 0x00:
            mc_data = cbor2.loads(mc_resp)
            fmt = mc_data.get(1)
            auth_data = mc_data.get(2)
            att_stmt = mc_data.get(3)
            print(f"[+] SUCCESS! Credential created successfully!")
            print(f"    Format: {fmt}")
            print(f"    AuthData len: {len(auth_data) if auth_data else 0} bytes")
            print(f"    AttStmt: {att_stmt}")

            # Extract Credential ID from auth_data
            # rpIdHash (32) + flags (1) + signCount (4) + aaguid (16) = 53
            cred_id_len = int.from_bytes(auth_data[53:55], "big")
            cred_id = auth_data[55:55 + cred_id_len]
            print(f"    Extracted Credential ID ({cred_id_len} bytes): {cred_id.hex()}")

            # Step 6: Test authenticatorGetAssertion (0x02) - WebAuthn Login
            print("\n[Step 6] Simulating WebAuthn Authentication (authenticatorGetAssertion)...")
            sess.send_text_line("TEST_UP", timeout_s=2.0)
            
            auth_client_data_hash = hashlib.sha256(b"{\"type\":\"webauthn.get\",\"challenge\":\"bG9naW5jaGFsbGVuZ2U\"}").digest()
            ga_map = {
                1: "webauthn.io",
                2: auth_client_data_hash,
                3: [{"type": "public-key", "id": cred_id}],
                5: {"up": True}
            }
            ga_cbor = cbor2.dumps(ga_map)
            ga_status, ga_resp = sess.ctap(0x02, ga_cbor.hex(), op="get_assertion")
            print(f"    GetAssertion status: 0x{ga_status:02X}")
            assert ga_status == 0x00, f"GetAssertion failed with status 0x{ga_status:02X}"
            ga_data = cbor2.loads(ga_resp)
            print(f"[+] SUCCESS! WebAuthn Assertion generated successfully!")
            print(f"    Assertion AuthData len: {len(ga_data.get(2, b''))} bytes")
            print(f"    Signature len: {len(ga_data.get(3, b''))} bytes")
        else:
            print(f"[-] MakeCredential error: 0x{mc_status:02X}")
            if mc_status == 0x27:
                print("    Error 0x27: CTAP2_ERR_OPERATION_DENIED (User Presence or PIN UV not satisfied)")
            elif mc_status == 0x2B:
                print("    Error 0x2B: CTAP2_ERR_UNSUPPORTED_OPTION")
            elif mc_status == 0x35:
                print("    Error 0x35: CTAP2_ERR_PIN_NOT_SET")
            assert False, f"MakeCredential failed with status 0x{mc_status:02X}"

        print("\n================================================================")
        print("  ALL WEBAUTHN / FIDO2 COMPATIBILITY CHECKS PASSED!")
        print("================================================================")

    finally:
        sess.close()

if __name__ == "__main__":
    run_test()
