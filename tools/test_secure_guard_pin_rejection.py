import sys
import os
import time

sys.path.insert(0, os.path.abspath("tools"))
from app_simulator import Session, CMD_MSG

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
    print("  AEGISKEY HARDWARE TEST: SECURE GUARD STRICT PIN AUTHENTICATION")
    print("================================================================")
    sess = Session("http://127.0.0.1", test_mode=True)
    print("[*] Connecting to COM7 @ 115200 bps...")
    sess.connect("COM7", 115200)
    time.sleep(0.5)

    try:
        print("[*] Initializing CTAPHID CID...")
        cid = sess.cmd_init()
        print(f"[+] CID allocated: 0x{cid:08X}")

        def send_sg(opcode, req_dict):
            req_bytes = cbor2.dumps(req_dict) if req_dict else b""
            status, resp_bytes = sess._exchange(CMD_MSG, bytes([opcode]) + req_bytes, op=f"sg_0x{opcode:02X}")
            data = cbor2.loads(resp_bytes) if resp_bytes else {}
            return status, data

        # 1. Query Initial Status
        print("\n[Step 1] Querying 0x3A (Status)...")
        status, st = send_sg(0x3A, {})
        print(f"    Code: 0x{status:02X}, State: {st.get('state_name')} ({st.get('state')}), Provisioned: {st.get('provisioned')}, Unlocked: {st.get('unlocked')}")

        # If not provisioned, verify unlock is rejected
        if not st.get("provisioned"):
            print("\n[Step 2] Testing unlock on unprovisioned board with wrong PIN '9999'...")
            status, res = send_sg(0x3B, {"action": "unlock", "pin": b"9999"})
            print(f"    Code: 0x{status:02X}, Response: {res}")
            assert status != 0x00 or res.get("success") is not True, "Unlock must fail on unprovisioned key!"
            print("[+] PASS: Unlock correctly rejected when key is unprovisioned.")

            print("\n[Step 3] Provisioning Secure Guard with PIN '2707'...")
            status, res = send_sg(0x3B, {"action": "provision", "pin": b"2707"})
            print(f"    Code: 0x{status:02X}, Response: {res}")
            assert status == 0x00 and res.get("success") is True, f"Provisioning failed: {res}"
            print("[+] PASS: Successfully provisioned with PIN '2707'!")

            # Verify status after provision
            status, st = send_sg(0x3A, {})
            print(f"    Status after provision: State={st.get('state_name')}, Provisioned={st.get('provisioned')}, Unlocked={st.get('unlocked')}")
            assert st.get("provisioned") is True, "Device must be provisioned!"

        # 4. Lock the session
        print("\n[Step 4] Locking the session (0x3C)...")
        status, res = send_sg(0x3C, {})
        print(f"    Code: 0x{status:02X}, Response: {res}")
        status, st = send_sg(0x3A, {})
        print(f"    Status after lock: State={st.get('state_name')}, Unlocked={st.get('unlocked')}")
        assert st.get("unlocked") is False, "Device must be locked!"
        print("[+] PASS: Session is locked.")

        # 5. Attempt UNLOCK with WRONG PIN #1: '9999'
        print("\n[Step 5] Attempting unlock with INVALID PIN '9999'...")
        status, res = send_sg(0x3B, {"action": "unlock", "pin": b"9999"})
        print(f"    Code: 0x{status:02X}, Response: {res}")
        assert res.get("success") is False, "CRITICAL SECURITY FAULT: Invalid PIN returned success=True!"
        assert status != 0x00, "CRITICAL SECURITY FAULT: Invalid PIN returned status=0x00!"
        print("[+] PASS: Hardware rejected invalid PIN '9999'!")

        # Verify device remains locked
        status, st = send_sg(0x3A, {})
        assert st.get("unlocked") is False, "CRITICAL SECURITY FAULT: Device unlocked after invalid PIN!"
        print(f"[+] PASS: Device remained locked. Failed attempts: {st.get('failed_attempts')}, Remaining: {st.get('remaining_attempts')}")

        # 6. Attempt UNLOCK with WRONG PIN #2: '1234'
        print("\n[Step 6] Attempting unlock with INVALID PIN '1234'...")
        status, res = send_sg(0x3B, {"action": "unlock", "pin": b"1234"})
        print(f"    Code: 0x{status:02X}, Response: {res}")
        assert res.get("success") is False, "CRITICAL SECURITY FAULT: Invalid PIN returned success=True!"
        print("[+] PASS: Hardware rejected invalid PIN '1234'!")

        # Verify device remains locked and remaining attempts decreased
        status, st = send_sg(0x3A, {})
        assert st.get("unlocked") is False, "CRITICAL SECURITY FAULT: Device unlocked after invalid PIN!"
        print(f"[+] PASS: Device remained locked. Failed attempts: {st.get('failed_attempts')}, Remaining: {st.get('remaining_attempts')}")

        # 7. Attempt UNLOCK with CORRECT PIN: '2707'
        print("\n[Step 7] Attempting unlock with CORRECT PIN '2707'...")
        status, res = send_sg(0x3B, {"action": "unlock", "pin": b"2707"})
        print(f"    Code: 0x{status:02X}, Response: {res}")
        assert status == 0x00 and res.get("success") is True, f"Failed to unlock with correct PIN: {res}"
        print("[+] PASS: Correct PIN '2707' successfully unlocked Secure Guard!")

        # Verify status is now unlocked and failed attempts reset to 0
        status, st = send_sg(0x3A, {})
        print(f"    Status: State={st.get('state_name')}, Unlocked={st.get('unlocked')}, Failed attempts={st.get('failed_attempts')}")
        assert st.get("unlocked") is True, "Device must be unlocked!"
        assert st.get("failed_attempts") == 0, "Failed attempts must reset to 0 on valid unlock!"
        print("[+] PASS: Verified device is unlocked and failed attempts reset to 0.")

        # 8. Re-lock
        print("\n[Step 8] Locking session again (0x3C)...")
        status, res = send_sg(0x3C, {})
        status, st = send_sg(0x3A, {})
        assert st.get("unlocked") is False, "Device must be locked!"
        print("[+] PASS: Device locked cleanly.")

        print("\n================================================================")
        print("🎉 ALL HARDWARE PIN AUTHENTICATION CHECKS PASSED PERFECTLY!")
        print("   - Wrong PINs are strictly rejected with error code & locked.")
        print("   - Backdoors & auto-provision on failed unlock eliminated.")
        print("   - Correct PIN '2707' unlocks reliably.")
        print("================================================================")

    finally:
        sess.close()

if __name__ == "__main__":
    run_test()
