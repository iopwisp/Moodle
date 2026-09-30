# Plugin development

A new application is added as an **integration**. Nothing in `runner.py`, `ai.py`, `database.py` or `reports.py`
changes: the planner sees the new capabilities in its catalog, the runner executes them through the registry, and the
report renders their evidence and report sections.

## Minimal integration

```python
# src/lab_agent/integrations/checksum_tool.py  (built-in: any module with create_adapters() is discovered)
from typing import Any

from lab_agent.integrations import BaseIntegration, Capability, ExecutionContext, IntegrationResult, Param
from lab_agent.integrations.base import evidence, param_str
from lab_agent.workspace import calculate_hashes


class ChecksumTool(BaseIntegration):
    name = "checksum"                                # capabilities must be named checksum.<action>
    CAPABILITIES = (
        Capability(
            "checksum.report", "checksum", "Write MD5/SHA-256 of a workspace file",
            parameters=(Param("path", "path", True, "workspace-relative file"),),
            evidence_types=("json",),
            verification="report file exists and matches the recomputed hash",
            keywords=("checksum", "контрольная сумма"),   # used by the deterministic planner
        ),
    )

    def report(self, parameters: dict[str, Any], context: ExecutionContext) -> IntegrationResult:
        target = context.resolve(param_str(parameters, "path"), base="input")   # refuses paths outside the workspace
        digests = calculate_hashes(target)
        output = context.save_result(f"{target.name}.checksum.json", digests)
        relative = target.relative_to(context.workspace.resolve()).as_posix()
        return IntegrationResult(
            verified=True,
            details={"file": relative, **digests},
            evidence=[evidence(output, f"Checksums of {relative}", "json")],
            # post-conditions evaluated by the runner, independently of this adapter:
            checks=[{"type": "hash_match", "path": relative, "expected": digests["sha256"]}],
        )


def create_adapters(services: Any) -> list[ChecksumTool]:
    return [ChecksumTool()]
```

`BaseIntegration.execute` dispatches `checksum.report` to the `report` method.

## Distribution options

| Where | How it is found |
| --- | --- |
| `src/lab_agent/integrations/<name>.py` | automatically (module defines `create_adapters`) |
| separate Python package | entry point group `doneasik_lab_agent.integrations` (see `pyproject.toml`) |
| a folder of `.py` files | `plugins.directories` in `config.yaml` |

Load failures are never silent: `lab-agent plugins` and `lab-agent doctor` list them.

## Contract

* **Capability**: `name`, `tool`, `description`, typed `Param`s (validated in plans; unknown parameters are rejected),
  `evidence_types`, `verification` text, `risk` (`safe`/`elevated`/`unsafe` → confirmation), `network=True` for
  capabilities whose URL/host parameters must pass the network policy, `keywords` for deterministic matching.
* **IntegrationResult**: `verified` (your claim), `details`, `evidence` (real files only), `checks` (verification DSL),
  `blocked` for "cannot run here" (missing app, credential, login), `report_sections` (title + paragraphs / table /
  code rendered into the report).
* Raise `CapabilityBlocked` for situations that need the user; any other exception is a failure that the recovery
  engine may retry.

## Optional hooks

| Hook | Purpose |
| --- | --- |
| `applications() -> list[AppSpec]` | environment discovery / `doctor` (env var, executables, install globs, registry name) |
| `plan_templates(analysis, registry)` | propose a complete workflow for matching assignments (deterministic planner) |
| `match_requirement(text, analysis)` | `(capability, parameters, score)` for a single requirement |
| `recover(capability, parameters, context, kind)` | restart the app / reopen the project before a retry |
| `reconcile(capability, parameters, context)` | after a crash: is the result already there? |
| `shutdown()` | close sessions and applications at the end of a run |

## Desktop applications

Use `lab_agent.applications.ManagedApplication` (launch/attach, wait for window, blockers, pop-ups, profile operations,
window screenshots, safe close) and describe the UI in `profiles/<name>.yaml`:

```yaml
name: myapp
executable_env: LAB_AGENT_MYAPP_PATH
window: {class_name: MyAppMainWindow}       # prefer class/automation ids verified with desktop.observe
blockers:                                   # windows that need the user -> step BLOCKED with this reason
  - window: {title_re: "(?i)log ?in"}
    reason: "Log in once, then resume."
dismiss:                                    # pop-ups closed automatically
  - window: {title: "Software Update"}
    control: {title: "Remind me later", control_type: Button}
operations:
  export:
    - {type: hotkey, keys: "^e"}            # letter chords are sent as virtual keys (work with any keyboard layout)
    - {type: wait_until, window: {title_re: "Export"}}
    - {type: type, window: {title_re: "Export"}, control: {control_type: Edit}, text: "{path}"}
    - {type: hotkey, keys: "{ENTER}"}
verification:
  export: [{type: file_exists, path: "results/export.csv"}]
goals:                                      # for desktop.computer_use (observe -> act -> verify)
  export_report:
    steps:
      - {name: open, action: click, targets: [{title: Export}], done_when: {window_exists: {title_re: Export}}}
versions:                                   # overrides by detected application version prefix
  "5": {window: {class_name: MyApp5Window}}
```

Selectors use accessibility properties only (`title`, `title_re`, `automation_id`, `control_type`, `class_name`,
`found_index`, `any: [...]`); coordinates are rejected. Run `desktop.observe` against the real application to record
its accessibility tree and confirm selectors before relying on them.

## Tests

Add unit tests with `tests/fakes.py` (`FakeDriver`, `FakeWindow`, `FakeControl`, `fake_screenshot`) and, when possible,
a test that runs the real tool and is skipped when it is not installed (see `tests/test_network_integrations.py`).
