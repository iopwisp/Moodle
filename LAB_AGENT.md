# Lab Agent operating rules

Use this project only for authorized educational assignments. Read all supplied materials, inspect the generated analysis and plan, and verify each step against an observed result before marking it complete. Keep originals unchanged and operate on workspace copies. Register real evidence with its workspace-relative path and integrity hash. Never claim a result or screenshot exists unless it was actually produced and validated. Record failures and distinguish unverified work from completion. Use security tools only with local, intentionally vulnerable, or explicitly authorized targets. Arbitrary PowerShell requires explicit user opt-in and must be reviewed before execution.

The agent may use OpenAI or Ollama for structured planning. The planner can select only capabilities published by the integration registry. The runner executes capabilities through that registry, checks the returned verification state and required evidence, records every result and failure, and never treats an unverified result as completed.

Desktop automation is restricted to versioned, profile-declared UI actions. Browser automation is restricted to localhost or explicitly authorized lab targets. New application integrations must expose the same capability contract instead of adding application-specific conditionals to the central runner.
