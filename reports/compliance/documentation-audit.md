Documentation audit -- AegisKey
==============================

Audit only. No files were removed. No files were renamed.
Scope: README.md, MASTER_EXECUTION_PLAN.md, AGENT_MAP.md, docs/project/PROJECT.md, docs/plans/PLANS.md,
docs/tasks/TASKS.md, docs/evaluation/EVALUATION.md, docs/test-hooks.md, app-tray/README.md.

README and PROJECT coherence
------------------------------
- Both files describe the same product: FIDO2 and WebAuthn hardware key on ESP32-S3, VID 0x303A and PID 0xAE61,
  4-layer architecture, GPLv3 license, dashboard at 127.0.0.1 port 5678. Status: coherent by inspection, no action.
- Minor drift, severity low, REVIEW: PROJECT.md section 1 lists a web RP interface at localhost port 8888 that
  README.md does not mention. Remediation: confirm whether port 8888 is current, then add it to README or
  remove it from PROJECT. No deletion performed in this audit.
- Minor drift, severity low, REVIEW: CTAP version strings vary (CTAP 2.1 in README badges and PROJECT section 1,
  CTAP 2.3 in web UI text and AGENT_MAP). Remediation: pick one canonical version string and apply it everywhere.
- License statements agree (GPLv3 badge and section 9 in README, GPL-3.0-only in Cargo.toml, full text in LICENSE).
  Status: coherent by inspection, no action.

Root document duplication
--------------------------
- AGENT_MAP.md restricts markdown to 4 canonical docs folders plus test-hooks, and routes root files by role.
- Root markdown present: README.md, AGENTS.md, AGENT_MAP.md, MASTER_EXECUTION_PLAN.md. Each has a distinct role
  (product overview, agent rules, routing map, master plan). No duplicate root documents were found.
- Action: none. No duplicate root docs removal was performed, as instructed.

ASD-STE100 language check
--------------------------
- PROJECT.md declares ASD-STE100 Simplified Technical English (short sentences, active voice, one instruction
  per sentence). README.md carries the same style badge.
- Method in this audit: heuristic inspection only (short-sentence style observed, no controlled-language tool run).
- Status: REVIEW, NOT certified. Remediation: run a controlled-language checker before claiming compliance.

Web dashboard duplication note
------------------------------
- Two dashboard trees exist: web/index.html with web/app.js and web/style.css, and tools/web_dashboard/index.html.
- Status: REVIEW, severity low. Remediation: confirm which tree is canonical and cross-link the other.
- No deletion performed in this audit.

Severity summary: coherence items coherent by inspection with evidence cited above, 3 low REVIEW items, 0 high rows.
