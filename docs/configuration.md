# Configuration

Resolution order: defaults → YAML (`--config`, `$LAB_AGENT_CONFIG` or `./config.yaml`) → environment variables.
Start from [`config.example.yaml`](../config.example.yaml); `lab-agent config` prints the effective values.

## Sections

| Key | Meaning |
| --- | --- |
| `workspace_root` | where workspaces are created (default `workspace`) |
| `ai.provider` | `auto` (OpenAI if `OPENAI_API_KEY`, else Ollama if `OLLAMA_HOST`, else deterministic), `openai`, `ollama`, `codex`, `deterministic`. `codex` runs the Codex CLI (`codex exec`) with the ChatGPT plan Codex is signed in with: no API key; it is never picked by `auto`, because every call uses the plan's quota |
| `ai.model`, `ai.base_url`, `ai.timeout_seconds`, `ai.max_retries` | provider settings; retries also cover re-planning after validation errors |
| `ai.fallback` | `deterministic` (record the fallback) or `none` (fail) |
| `ai.recovery_advice` | ask the AI for corrected parameters after a failed verification (validated before use) |
| `execution.max_attempts` | attempts per step (first try included) |
| `execution.stop_on_failure` | stop the run at the first failed required step |
| `screenshots.mode` | `evidence` (steps that need one), `all` (before/after every step), `none` |
| `screenshots.target` | `window` (focus and capture the application window) or `desktop` |
| `browser.headless`, `browser.timeout_seconds` | Playwright session |
| `browser.allow_external_subresources` | allow passive GET sub-resources from other hosts; navigations, redirects and non-GET requests stay in scope |
| `report.*` | cover page (student, group, student ID, case ID, course, instructor), `language: en|ru` |
| `policy.tools.<tool>` | `allowed`, `require_confirmation` |
| `policy.powershell.arbitrary` | enables `powershell.run_script` (still needs approval per step) |
| `policy.network` | `localhost`, `authorized_targets_only`, `authorized_targets` (`host` or `*.domain`) |
| `policy.require_confirmation_for_risk` | risk levels that need approval (default `[unsafe]`) |
| `plugins.entry_points`, `plugins.directories` | external integrations |
| `logging.level`, `logging.json_logs` | structured logging (secrets are redacted) |
| `applications.<name>` | explicit executable paths (override discovery) |

## Environment variables

| Variable | Effect |
| --- | --- |
| `LAB_AGENT_CONFIG` | path of the YAML file |
| `LAB_AGENT_WORKSPACE_ROOT`, `LAB_AGENT_AI_PROVIDER`, `LAB_AGENT_AI_MODEL`, `LAB_AGENT_AI_TIMEOUT`, `LAB_AGENT_MAX_ATTEMPTS`, `LAB_AGENT_SCREENSHOT_MODE`, `LAB_AGENT_BROWSER_HEADLESS`, `LAB_AGENT_LOG_LEVEL`, `LAB_AGENT_JSON_LOGS` | override the matching setting |
| `LAB_AGENT_STUDENT_NAME`, `LAB_AGENT_STUDENT_GROUP`, `LAB_AGENT_STUDENT_ID`, `LAB_AGENT_CASE_ID` | report cover page |
| `LAB_AGENT_AUTHORIZED_TARGETS` | comma-separated hosts added to `policy.network.authorized_targets` |
| `LAB_AGENT_AUTOPSY_PATH`, `LAB_AGENT_BURP_PATH`, `LAB_AGENT_PACKET_TRACER_PATH`, `LAB_AGENT_WIRESHARK_PATH`, `LAB_AGENT_TSHARK_PATH`, `LAB_AGENT_FTK_PATH`, `LAB_AGENT_FOREMOST_PATH`, `LAB_AGENT_SCALPEL_PATH`, `LAB_AGENT_TSK_PATH`, `LAB_AGENT_TESTDISK_PATH`, `LAB_AGENT_PHOTOREC_PATH` | application executables (portable tools unpacked under `C:\Tools` are found automatically) |
| `LAB_AGENT_WSL_DISTRO` | WSL distribution used for Linux forensic tools (default `Ubuntu`) |
| `LAB_AGENT_AUTOPSY_TIMEOUT` | seconds allowed for Autopsy command-line ingest (default 21600) |
| `LAB_AGENT_PROFILES_DIR` | extra folder(s) with application profiles (searched first) |
| `OPENAI_API_KEY`, `OPENAI_BASE_URL`, `OLLAMA_HOST` | AI providers |
| `LAB_AGENT_CODEX_PATH` | `codex.exe` for `ai.provider: codex` (default: `PATH`, then the CLI inside the Codex desktop app) |
| `LAB_AGENT_REAL_APPS=1`, `LAB_AGENT_REAL_CODEX=1` | opt-in tests against the real TestDisk / a real Codex call (`pytest -k real`) |
| `LAB_AGENT_OVERLEAF_EMAIL`, `LAB_AGENT_OVERLEAF_PASSWORD` | Overleaf credentials (or store them in the OS keyring, service `doneasik-lab-agent`) |

Secrets are read only from the environment or the OS keyring and are masked in logs, SQLite events, reports and AI prompts.
