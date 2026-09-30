# Verification status

Three separate levels (a feature is not called "working end-to-end" on the strength of mocked tests):

* **CI** — automated tests with fakes/stand-ins (`tests/`), run by `.github/workflows/ci.yml` on Ubuntu and Windows.
* **Local integration** — tests or runs that used the real tool binaries on the development machine.
* **Real application** — driven through the agent against the real Windows GUI application.

Recorded on 2026-09-30, Windows 11 23H2 (10.0.22631), Python 3.12.2, Russian keyboard layout.

| Integration | CI | Local integration | Real application |
| --- | --- | --- | --- |
| core (hashing, screenshots, manual review) | ✓ | ✓ real Assignment 3 run | window screenshots ✓ |
| forensics — hashes, working copy, signatures, hex views, built-in carver, ZIP fragment repair, records | ✓ synthetic image | ✓ **real Assignment 3 materials**: SOURCE_UNCHANGED before/after, `system_log.txt` identified as PNG, real EOCD found at 0x0052C03A, valid `evidence_fixed.zip` | n/a (no GUI) |
| forensics — Foremost / Scalpel / Sleuth Kit | ✓ command construction (mocked runner) | tools not installed (native or WSL) → steps correctly BLOCKED with install instructions | — |
| autopsy (command-line ingest, case DB verification, export, GUI evidence) | ✓ fake Autopsy writing a real SQLite case DB | — | **not verified: Autopsy is not installed on this machine** |
| wireshark (tshark/capinfos analysis) | ✓ mocked runner | ✓ real TShark 4.4.2 (packet counts, filters, field export, filtered export) | — |
| wireshark (GUI) | ✓ fake driver | — | ✓ Wireshark 4.4.2: launch with `-r/-Y`, main window by class `WiresharkMainWindow`, window-only screenshot, filter shown in GUI, update pop-up selectors (`Remind me later`), display-filter entry selector, clean close |
| browser (Playwright session, scope guard) | ✓ (Chromium installed in CI) | ✓ real Chromium: navigate/type/select/click/wait/read/inspect/download; redirect and link to unauthorized host blocked | headless and headed supported; headed not exercised in tests |
| burp (proxy, intercept/forward measurement, response inspection) | ✓ local fake proxy with held requests | — | Burp Community 2026.8: discovery, launch, window detection ✓; the Swing start-up wizard is not visible to UI Automation without the Java Access Bridge → launch correctly BLOCKED until the student clicks *Start Burp*. Proxy/intercept against the real Burp **not yet verified**. |
| packet_tracer (topology model, IOS CLI, PC command prompt, ping parsing) | ✓ fake IOS console | — | Packet Tracer 8.2.2: discovery (8.2.2.400), launch, main window class `CAppWindow`, login wall `CNetspaceLogin` detected → BLOCKED, agent-launched processes terminated ✓. CLI configuration and ping on real devices **not verified** (requires the Cisco login). |
| overleaf (web) | — | ✓ full flow against a local stand-in with real Chromium | **not verified against overleaf.com** (needs credentials) |
| latex (local compile) | — | no TeX engine installed → BLOCKED | — |
| powershell allowlist | ✓ policy tests | ✓ real `Get-FileHash` cross-checked on Windows | — |
| ftk | ✓ log verification logic | FTK Imager 8.3.0.27 discovered | GUI not launched |
| desktop engine / computer-use loop | ✓ fake driver (pop-ups, stuck detection, AI decider limits) | — | UIA driver fixes found on real Wireshark (name vs. text matching, ambiguous matches, keyboard layout) |
| AI providers (OpenAI, Ollama) | ✓ mocked HTTP, schema validation, retries, fallback | — | **no real API call made** (no `OPENAI_API_KEY`, Ollama not running) |
| web dashboard | ✓ TestClient | ✓ live `lab-agent serve` on the real Assignment 3 workspace (status, SSE, report download, rendered page) | — |
| reports (DOCX/PDF) | ✓ content assertions | ✓ generated from the real Assignment 3 run and inspected page by page | — |
| CI workflow | written (ruff, mypy, pytest, CLI smoke test; Ubuntu + Windows) | ruff, mypy, pytest pass locally | **not yet executed on GitHub** (branch not pushed) |

## Assignment 3 reference run (real materials)

`lab-agent run Assignment_3_Student_Materials.zip --ai-provider deterministic` → status **BLOCKED**, 13/19 steps
completed and verified; BLOCKED: Foremost, Scalpel (not installed), Autopsy ingest + inspection (not installed),
analytical answers (require the student). Optional TSK step BLOCKED (not installed). To finish it on this machine:
install Autopsy and `sudo apt install foremost scalpel sleuthkit` in WSL Ubuntu, answer the analytical questions,
then `lab-agent resume <workspace>` and record the manual step with
`lab-agent complete-step <workspace> 19 --verification "answers written in section X of the report"`.
