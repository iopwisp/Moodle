# Verification status

Three separate levels (a feature is not called "working end-to-end" on the strength of mocked tests):

* **CI** — automated tests with fakes/stand-ins (`tests/`), run by `.github/workflows/ci.yml` on Ubuntu and Windows.
* **Local integration** — tests or runs that used the real tool binaries on the development machine.
* **Real application** — driven through the agent against the real Windows GUI application.

Recorded on 2026-09-30, updated 2026-10-01; Windows 11 23H2 (10.0.22631), Python 3.12.2, Russian keyboard layout.

| Integration | CI | Local integration | Real application |
| --- | --- | --- | --- |
| core (hashing, screenshots, manual review) | ✓ | ✓ real Assignment 3 run | window screenshots ✓ |
| forensics — hashes, working copy, signatures, hex views, built-in carver, ZIP fragment repair, records | ✓ synthetic image | ✓ **real Assignment 3 materials**: SOURCE_UNCHANGED before/after, `system_log.txt` identified as PNG, real EOCD found at 0x0052C03A, valid `evidence_fixed.zip` | n/a (no GUI) |
| forensics — Foremost / Scalpel / Sleuth Kit | ✓ command construction (mocked runner) | ✓ real Foremost 1.5.7, Scalpel 1.60 and TSK `fsstat` in WSL Ubuntu on the Assignment 3 image (FAT16 found) | n/a (no GUI) |
| autopsy (command-line ingest, case DB verification, export, GUI evidence) | ✓ fake Autopsy writing a real SQLite case DB | ✓ Autopsy 4.23.1 command-line ingest of the Assignment 3 image: case DB with 20 objects, ingest COMPLETED, Extension Mismatch Detected ×2 | `--generateReports` needs a report profile created once in the GUI → BLOCKED with instructions; GUI case screenshot not exercised |
| wireshark (tshark/capinfos analysis) | ✓ mocked runner | ✓ real TShark 4.4.2 (packet counts, filters, field export, filtered export) | — |
| wireshark (GUI) | ✓ fake driver | — | ✓ Wireshark 4.4.2: launch with `-r/-Y`, main window by class `WiresharkMainWindow`, window-only screenshot, filter shown in GUI, update pop-up selectors (`Remind me later`), display-filter entry selector, clean close |
| browser (Playwright session, scope guard) | ✓ (Chromium installed in CI) | ✓ real Chromium: navigate/type/select/click/wait/read/inspect/download; redirect and link to unauthorized host blocked | headless and headed supported; headed not exercised in tests |
| burp (proxy, intercept/forward measurement, response inspection) | ✓ fake proxy that behaves like Burp (Ctrl+T toggles, Forward releases the oldest held request, Intercept off releases all) | ✓ local test site on 127.0.0.1:8000 | ✓ Burp Community 2026.8: start-up wizard passed with Enter/Enter when needed, proxy verified via http://burp/, request through the proxy, Intercept on with the request held (measured), Send to Repeater, Forward until our request passed (5 forwards with a stale queue), Intercept switched off and verified, Chromium through Burp to localhost; clean window screenshots of Intercept and Repeater. Hotkeys need the Burp window in focus: do not touch mouse/keyboard during these steps. |
| packet_tracer (topology model, IOS CLI, PC command prompt, ping parsing) | ✓ fake IOS console | — | Packet Tracer 8.2.2: discovery (8.2.2.400), launch, main window class `CAppWindow`, login wall `CNetspaceLogin` detected → BLOCKED, agent-launched processes terminated ✓. CLI configuration and ping on real devices **not verified** (requires the Cisco login). |
| overleaf (web) | — | ✓ full flow against a local stand-in with real Chromium | **not verified against overleaf.com** (needs credentials) |
| latex (local compile) | — | no TeX engine installed → BLOCKED | — |
| powershell allowlist | ✓ policy tests | ✓ real `Get-FileHash` cross-checked on Windows | — |
| ftk | ✓ log verification logic | FTK Imager 8.3.0.27 discovered | GUI not launched |
| desktop engine / computer-use loop | ✓ fake driver (pop-ups, stuck detection, AI decider limits) | — | UIA driver fixes found on real Wireshark (name vs. text matching, ambiguous matches, keyboard layout) |
| AI providers (OpenAI, Ollama) | ✓ mocked HTTP, schema validation, retries, fallback | — | **no real API call made** (no `OPENAI_API_KEY`, Ollama not running) |
| web dashboard | ✓ TestClient | ✓ live `lab-agent serve` on the real Assignment 3 workspace (status, SSE, report download, rendered page) | — |
| reports (DOCX/PDF) | ✓ student report (structure, language, no jargon, honest about unfinished steps) and technical audit | ✓ student report from the real Assignment 3 run (18 pages, answers attached with `complete-step --attach`) rendered and inspected page by page | — |
| screenshots | ✓ requested window never replaced by a desktop grab; covered window uses its own pixels | ✓ PrintWindow capture of Burp while covered by a terminal | — |
| CI workflow | written (ruff, mypy, pytest, CLI smoke test; Ubuntu + Windows) | ruff, mypy, pytest pass locally | **not yet executed on GitHub** (branch not pushed) |

## Assignment 3 reference run (real materials)

2026-10-01, "Autopsy-ready" materials (image SHA-256 `6949a5f1…5669`):
`lab-agent run <materials> --ai-provider deterministic` → 18/18 automatic steps COMPLETED and verified, including Foremost,
Scalpel and TSK in WSL and the Autopsy 4.23.1 ingest; the remaining step (analytical answers) was closed with
`lab-agent complete-step <workspace> 19 --verification "..." --attach analytical_answers.md` and the reports regenerated:
`reports/Assignment_3_Report.pdf` (student report) and `reports/Assignment_3_Audit.pdf` (technical record).

The earlier materials in `~/Downloads/Assignment_3_Student_Materials.zip` (image `323e0664…0e0b`) contain no file system
that TSK recognises at offset 0: `fsstat` fails and the optional step is reported as such; everything else completes.
