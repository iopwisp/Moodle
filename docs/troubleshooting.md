# Troubleshooting

Always start with `lab-agent doctor` and `lab-agent status <workspace>`; every BLOCKED/FAILED step carries its reason,
and `logs/execution.jsonl`, `logs/commands.jsonl` and `state/agent.db` hold the details.

| Symptom | Cause and fix |
| --- | --- |
| `X is not installed or not configured` (BLOCKED) | Install it or set `LAB_AGENT_X_PATH` / `applications.x`, then `lab-agent resume`. |
| Foremost / Scalpel / Sleuth Kit BLOCKED | Not in Windows `PATH` or WSL. In WSL: `sudo apt install foremost scalpel sleuthkit`; the built-in carver result is recorded separately in the meantime. |
| Packet Tracer launch BLOCKED: "requires a Cisco account login" | Packet Tracer 8.x opens a login window (class `CNetspaceLogin`). Log in once in that window and resume. |
| Packet Tracer `Open the R1 window` (BLOCKED) | The logical workspace is a canvas without accessibility controls. Click the device once so its window opens; the agent then uses its CLI / Command Prompt tabs. |
| Placing devices / drawing cables BLOCKED | Canvas actions are not automatable through UI Automation; do them manually (or start from the lab's `.pkt`) and resume. |
| Burp launch BLOCKED: proxy not listening | Burp Community shows a Swing start-up wizard. Choose Temporary project → Next → Use Burp defaults → Start Burp and resume. Optional: enable the Java Access Bridge (`jabswitch -enable` from Burp's `jre\bin`) so UI Automation can see Swing controls. |
| `burp.intercept_request` fails "Intercept is off" | The request completed immediately; switch Proxy → Intercept on (or fix the `intercept_on` hotkey in `profiles/burp.yaml`). |
| Wireshark main window not found | Wireshark 4.x titles the window with the file name; the profile matches class `WiresharkMainWindow`. Update the profile if your version differs (`desktop.observe`). |
| Shortcuts type Cyrillic letters | Fixed: letter chords are sent as virtual-key codes and text through the UIA value pattern. If a custom profile types text with a non-Latin layout active and the value differs, the step fails instead of continuing. |
| Browser step BLOCKED "not authorized" | Add the host to `policy.network.authorized_targets` or pass `--allowed-target host` when planning. Redirects to other hosts are blocked by design. |
| Overleaf BLOCKED | Set `LAB_AGENT_OVERLEAF_EMAIL/PASSWORD`; complete captcha/SSO in the headed browser window; authorize `www.overleaf.com`. |
| Autopsy ingest FAILED although the command finished | Verification reads `autopsy.db`; ingest jobs not in state Completed or no data source recorded means the case is incomplete. See `logs/autopsy_ingest.json`. |
| Evidence step FAILED "Refusing to register" | The produced file is empty or not a valid image/PDF/DOCX/ZIP. Nothing fake is accepted. |
| `resume` re-runs a completed step | Its evidence was modified or deleted after completion (hash mismatch). |
| AI plan fell back to deterministic | See `metadata/planner.json` → `warnings`; the AI plan failed validation twice or the provider was unreachable. |
| Screenshots show the desktop | The target window was not found/visible; set `screenshots.target: window` and check the profile's `window` selector. |
| Playwright "Executable doesn't exist" | `py -3.12 -m playwright install chromium`. |
