"""Decision-logic tests for killswitch.py (no hardware, dry-run only).

Wave2 Step3: dedicated killswitch opcode (RESC 0x06) over transport 0x2E.
All tests are plan/fingerprint only — never touch hardware, never write files.
Mirrors tools/host/win/test_proximity_agent.py (unittest, no HW).
"""

import hashlib
import os
import subprocess
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import killswitch as ks

TOOL = os.path.join(os.path.dirname(os.path.abspath(__file__)), "killswitch.py")
RAW_TOKEN = b"AEGISKEY_KILLSWITCH_CONFIRM"


def run_tool(*argv):
    """Run killswitch.py as subprocess, capture (returncode, stdout, stderr)."""
    proc = subprocess.run(
        [sys.executable, TOOL, *argv],
        capture_output=True,
        text=True,
        timeout=30,
    )
    return proc.returncode, proc.stdout, proc.stderr


class TestKillswitchFrame(unittest.TestCase):
    def test_frame_wire_format_magic_ver_cmd_len(self):
        frame = ks.build_rescue_frame(ks.RESCUE_CMD_KILLSWITCH, RAW_TOKEN)
        self.assertTrue(frame.startswith(b"RESC"))
        self.assertEqual(frame[4], ks.RESCUE_VERSION)
        self.assertEqual(frame[5], 0x06)
        self.assertEqual(int.from_bytes(frame[6:8], "big"), len(RAW_TOKEN))
        self.assertEqual(frame[8:], RAW_TOKEN)

    def test_frame_rejects_bad_cmd(self):
        with self.assertRaises(ValueError):
            ks.build_rescue_frame(256, b"x")
        with self.assertRaises(ValueError):
            ks.build_rescue_frame(-1, b"x")

    def test_frame_rejects_oversized_payload(self):
        with self.assertRaises(ValueError):
            ks.build_rescue_frame(0x06, b"x" * 0x10000)

    def test_opcodes_match_firmware_rescue_rs(self):
        # Byte-identical contract with crates/aegis-fido-core/src/otp/rescue.rs.
        self.assertEqual(ks.RESCUE_CMD_KILLSWITCH, 0x06)
        self.assertEqual(ks.RESCUE_TRANSPORT_OP, 0x2E)
        self.assertEqual(ks.KILLSWITCH_TOKEN, RAW_TOKEN)
        self.assertEqual(ks.KILLSWITCH_ACK, bytes([0xDE, 0xAD]))
        self.assertEqual(ks.KILLSWITCH_HOLD_MS, 5000)
        self.assertEqual(ks.KILLSWITCH_ARM_WINDOW_MS, 60000)

    def test_valid_serial(self):
        self.assertTrue(ks.valid_serial("AEGIS-S3-00AF"))
        self.assertFalse(ks.valid_serial("NOPE-0000"))
        self.assertFalse(ks.valid_serial("AEGIS-S3-"))
        self.assertFalse(ks.valid_serial("AEGIS-S3-" + "X" * 30))


class TestKillswitchCli(unittest.TestCase):
    def test_dry_run_plans_without_hardware(self):
        code, out, _ = run_tool("--dry-run")
        self.assertEqual(code, 0)
        self.assertIn("[PLAN] mode=remote", out)
        self.assertIn("transport_op=0x2E cmd=0x06 ack=dead", out)
        self.assertIn("UP+PIN", out)
        self.assertIn("hold BOOT 5000ms", out)
        self.assertIn("[DRY-RUN] no hardware touched", out)

    def test_dry_run_never_leaks_raw_token(self):
        code, out, err = run_tool("--dry-run", "--emit-ps1", "--emit-pam", "--emit-udev")
        self.assertEqual(code, 0)
        blob = out + err
        self.assertNotIn(RAW_TOKEN.decode(), blob)
        # Only the sha256 fingerprint is printed.
        self.assertIn(hashlib.sha256(RAW_TOKEN).hexdigest(), out)

    def test_emit_templates_gated_content(self):
        _, out, _ = run_tool("--dry-run", "--emit-ps1", "--emit-pam", "--emit-udev")
        self.assertIn("PowerShell", out)
        self.assertIn("-Confirm", out)
        self.assertIn("pam_exec", out)
        self.assertIn("CONFIRM=1", out)
        self.assertIn("99-aegis-killswitch.rules", out)

    def test_real_kill_requires_confirm(self):
        code, _, err = run_tool("--port", "COM7")
        self.assertEqual(code, 3)
        self.assertIn("--confirm", err)

    def test_real_kill_requires_port(self):
        code, _, err = run_tool("--confirm")
        self.assertEqual(code, 3)
        self.assertIn("--port", err)

    def test_confirm_aborts_without_jig(self):
        # Audit wave: real path prints plan then aborts, never touches HW.
        code, _, err = run_tool("--confirm", "--port", "COM7")
        self.assertEqual(code, 4)
        self.assertIn("NOT IMPLEMENTED", err)

    def test_bad_serial_rejected(self):
        code, _, err = run_tool("--dry-run", "--serial", "NOPE-0000")
        self.assertEqual(code, 2)
        self.assertIn("AEGIS-S3-", err)

    def test_physical_mode_plan(self):
        code, out, _ = run_tool("--dry-run", "--mode", "physical")
        self.assertEqual(code, 0)
        self.assertIn("mode=physical", out)


if __name__ == "__main__":
    unittest.main()
