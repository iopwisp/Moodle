# Lab Agent Operating Rules

Use this project only for authorized educational assignments. Read all supplied materials, inspect the generated
analysis and plan, and verify each step against an observed result before marking it complete. Keep originals
unchanged and operate on workspace copies. Register real evidence with its workspace-relative path and integrity hash.
Never claim a result or screenshot exists unless it was actually produced and validated. Record failures and
distinguish unverified work from completion. Use security tools only with local, intentionally vulnerable, or
explicitly authorized targets. Arbitrary PowerShell requires explicit opt-in in config.yaml and per-step approval.

How the code enforces these rules:

* **Capabilities only.** The planner can select only capabilities published by the integration registry; plans are
  validated (known capability, declared parameters, backward dependencies, known verification checks, authorized
  network targets) before anything runs.
* **Policy before execution.** `lab_agent.policy` denies disabled tools, unauthorized hosts and arbitrary PowerShell,
  and turns `risk="unsafe"` capabilities into confirmation requests. Plan parameters cannot switch these off.
* **Verified or not completed.** A step is COMPLETED only when the adapter reports success, every evidence file is
  valid for its type and every verification check (adapter- and plan-supplied) passes. Missing applications,
  credentials, logins and canvas-only actions become BLOCKED with instructions; errors become FAILED.
* **No fake evidence.** Evidence registration rejects missing, empty, unparsable or out-of-workspace files.
* **Chain of custody.** Inputs are copied and hashed (MD5/SHA-1/SHA-256); archives are extracted with traversal
  protection; images are re-hashed after examination; every external command is logged.
* **No application logic in the core.** New tools are integrations (`src/lab_agent/integrations/*.py`, entry points or
  plugin directories) plus optional versioned YAML profiles; runner, planner, database and reports stay unchanged.
