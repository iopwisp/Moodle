# Architecture

```text
            ┌──────────────┐
            │  Assignment  │  PDF / DOCX / TXT / MD / CSV / JSON / ZIP (+ evidence files)
            └──────┬───────┘
                   ▼
            analyzer.py        text of every document (also inside ZIPs), file roles, steps/parts,
                   │           questions, commands, deliverables, hashes, URLs, workspace paths
                   ▼
            ai.py / planning.py   AI (llm.py providers) or deterministic planner → ExecutionPlan
                   │              validated against the registry, parameters, DAG and policy
                   ▼
            workspace.py       input copies + input_manifest.json (MD5/SHA-1/SHA-256), ZIP extraction
                   ▼
            runner.py          DAG order · policy · confirmation · execute · evidence · verification
                   │           · recovery · pause/stop/resume · SQLite events · execution.jsonl
       ┌───────────┼──────────────────────────────┐
       ▼           ▼                              ▼
 integrations/  verification.py               evidence.py
 (capabilities) (check DSL, independent)      (real files only, hashes, manifest)
       │
       ├─ applications.py  lifecycle: discover → launch → wait ready → blockers/pop-ups → use → close
       ├─ desktop/         UIA driver · versioned profiles · profile engine · computer-use loop
       └─ sessions.py      shared Playwright session with scope guard
                   ▼
            reports.py (DOCX + PDF)   web.py (dashboard, SSE)   cli.py
```

## Key modules

| Module | Responsibility |
| --- | --- |
| `config.py` | `AgentConfig` from `config.yaml` + `LAB_AGENT_*` variables |
| `policy.py` | tool allow/deny, network scope, unsafe capabilities, confirmation |
| `credentials.py` | secrets from env/keyring; redaction for logs, SQLite, reports and prompts |
| `environment.py` | application discovery (config, env, PATH, install dirs, registry), WSL tools, `doctor` |
| `analyzer.py` | assignment understanding (deterministic) |
| `llm.py` | provider interface (OpenAI, Ollama, scripted) with schema validation, retries, timeouts |
| `ai.py` | capability-aware planning, deterministic fallback, AI recovery advice |
| `planning.py` | plan validation |
| `runner.py` | the execution engine; contains no application-specific code |
| `recovery.py` | failure classification and bounded strategies |
| `verification.py` | check DSL (`file_exists`, `hash_match`, `sqlite_query`, `window_exists`, ...) |
| `evidence.py` | evidence registry with content validation |
| `database.py` | SQLite: runs, tasks, events, evidence, verifications, errors, capabilities |
| `reports.py` | submission-style DOCX/PDF from recorded results only |
| `web.py` | FastAPI dashboard with background runs and live events |

## Step life cycle

1. Dependencies: `depends_on` must be COMPLETED, `run_after` only finished (used e.g. for the final hash check).
2. Policy check → BLOCKED (denied) or confirmation request (BLOCKED until approved).
3. `capability.started` → adapter executes with an `ExecutionContext` (workspace, config, discovered applications,
   screenshot function, event sink, cancel event).
4. Evidence files are registered; invalid ones are rejected and fail the step.
5. Verification: checks returned by the adapter + `verification_checks` from the plan + evidence requirements.
6. COMPLETED, or recovery (`retry` with the adapter's `recover` hook / AI-corrected parameters), or FAILED / BLOCKED.
7. Checkpoint (`state.json`), SQLite rows and `logs/execution.jsonl` are written after every transition.

## Resume

`execute_workspace` is also the resume operation: evidence of COMPLETED steps is re-hashed (changed evidence → step
runs again), RUNNING steps from a crash are reconciled through the adapter's `reconcile` hook or their plan checks,
and only unfinished steps are executed.

## Statuses

Task: `PENDING RUNNING COMPLETED FAILED BLOCKED SKIPPED`.
Run: `PLANNED IN_PROGRESS PAUSED STOPPED WAITING_CONFIRMATION BLOCKED FAILED COMPLETED`.
A run is COMPLETED only when every required step is COMPLETED (or explicitly SKIPPED by the user, which the report
states).
