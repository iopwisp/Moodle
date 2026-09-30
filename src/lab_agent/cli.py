"""Command-line interface for DoneAsik Lab Agent."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import __version__
from .analyzer import analyze, build_plan
from .config import get_config, load_config, set_config
from .evidence import list_evidence, register_evidence, validate_evidence
from .filesystem import copy_file, extract_zip, file_metadata, list_files, search_files
from .logging_setup import configure_logging
from .models import TaskStatus
from .reports import generate_reports
from .runner import (
    decide_confirmation,
    execute_workspace,
    plan_assignment,
    request_control,
    run_assignment,
)
from .tools.powershell import run_powershell
from .tools.process import launch_application
from .tools.screenshot import take_screenshot
from .workspace import (
    calculate_hashes,
    create_workspace,
    load_state,
    save_state,
    verify_inputs_unchanged,
)


def _write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if hasattr(value, "model_dump_json"):
        path.write_text(value.model_dump_json(indent=2), encoding="utf-8")
    else:
        path.write_text(json.dumps(value, indent=2, ensure_ascii=False, default=str), encoding="utf-8")


def _print(value: object) -> None:
    print(json.dumps(value, ensure_ascii=False, indent=2, default=str))


def _workspace_arg(value: str) -> Path:
    path = Path(value).expanduser().resolve()
    if not (path / "state" / "state.json").is_file():
        raise ValueError(f"Not a Lab Agent workspace (missing state/state.json): {path}")
    return path


def _registry():  # type: ignore[no-untyped-def]
    from .integrations.registry import build_registry

    return build_registry(config=get_config())


def make_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="lab-agent", description="Local evidence-oriented university lab agent")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    parser.add_argument("--config", type=Path, help="config.yaml (default: $LAB_AGENT_CONFIG or ./config.yaml)")
    parser.add_argument("--log-level", default=None)
    parser.add_argument("--json-logs", action="store_true")
    sub = parser.add_subparsers(dest="command", required=True)

    def targets(p: argparse.ArgumentParser) -> None:
        p.add_argument("--allowed-target", action="append", default=[], help="Authorized hostname (localhost is always allowed)")

    def provider(p: argparse.ArgumentParser) -> None:
        p.add_argument("--ai-provider", choices=("auto", "openai", "ollama", "deterministic"), default="auto")
        p.add_argument("--model")

    p = sub.add_parser("analyze", help="Extract assignment text and create analysis, checklist and workspace")
    p.add_argument("paths", nargs="+", type=Path)
    p.add_argument("--workspace-root", type=Path)
    p.add_argument("--no-copy-inputs", action="store_true")
    p.add_argument("--output", type=Path, help="Optional directory for analysis JSON and plan JSON")
    p = sub.add_parser("plan", help="Analyze and build a validated capability plan without executing")
    p.add_argument("paths", nargs="+", type=Path)
    p.add_argument("--workspace-root", type=Path)
    provider(p)
    targets(p)
    p = sub.add_parser("run", help="Analyze, plan, execute, verify, collect evidence and generate reports")
    p.add_argument("paths", nargs="+", type=Path)
    p.add_argument("--workspace-root", type=Path)
    provider(p)
    targets(p)
    p = sub.add_parser("status", help="Show saved workflow state and evidence validation")
    p.add_argument("workspace")
    p = sub.add_parser("resume", help="Re-validate evidence, reconcile interrupted steps and continue")
    p.add_argument("workspace")
    p.add_argument("--verify-only", action="store_true")
    targets(p)
    for name, text in (("pause", "Ask a running execution to pause after the current step"),
                       ("stop", "Stop a running execution (current waits are interrupted; progress is kept)")):
        p = sub.add_parser(name, help=text)
        p.add_argument("workspace")
    for name, text in (("approve", "Approve a step that waits for confirmation"), ("reject", "Reject a pending confirmation")):
        p = sub.add_parser(name, help=text)
        p.add_argument("workspace")
        p.add_argument("step_id", type=int)
        p.add_argument("--note", default="")
    p = sub.add_parser("complete-step", help="Mark a step complete after manual verification (evidence still required)")
    p.add_argument("workspace")
    p.add_argument("step_id", type=int)
    p.add_argument("--verification", required=True, help="Describe what was observed to verify completion")
    p = sub.add_parser("hash", help="Calculate MD5, SHA1, and SHA256 for a file")
    p.add_argument("file", type=Path)
    p = sub.add_parser("files", help="List files under a workspace-relative path")
    p.add_argument("workspace")
    p.add_argument("--path", default=".")
    p = sub.add_parser("search", help="Search workspace file names and small text files")
    p.add_argument("workspace")
    p.add_argument("query")
    p.add_argument("--path", default=".")
    p = sub.add_parser("metadata", help="Show size, modification time, and SHA-256 for a workspace file")
    p.add_argument("workspace")
    p.add_argument("path")
    p = sub.add_parser("copy", help="Copy a file within a workspace and compare SHA-256")
    p.add_argument("workspace")
    p.add_argument("source")
    p.add_argument("destination")
    p = sub.add_parser("extract-zip", help="Safely extract a ZIP within a workspace")
    p.add_argument("workspace")
    p.add_argument("archive")
    p.add_argument("destination")
    p = sub.add_parser("powershell", help="Run a logged PowerShell command (requires explicit unsafe opt-in)")
    p.add_argument("workspace")
    p.add_argument("ps_command")
    p.add_argument("--allow-unsafe", action="store_true")
    p.add_argument("--timeout", type=int, default=120)
    p = sub.add_parser("launch", help="Launch a desktop application without shell interpretation")
    p.add_argument("workspace")
    p.add_argument("executable")
    p.add_argument("args", nargs="*")
    p = sub.add_parser("screenshot", help="Capture and register a screenshot (a window when --window is given)")
    p.add_argument("workspace")
    p.add_argument("--name")
    p.add_argument("--window", help="Window title regex to focus and capture")
    p.add_argument("--description", required=True)
    p.add_argument("--step", type=int)
    p = sub.add_parser("evidence", help="Register a file already stored in the workspace, or list evidence")
    p.add_argument("workspace")
    p.add_argument("path", nargs="?")
    p.add_argument("--description")
    p.add_argument("--type", default="file")
    p.add_argument("--step", type=int)
    p = sub.add_parser("review", help="Validate evidence and produce execution summary JSON")
    p.add_argument("workspace")
    p = sub.add_parser("report", help="Generate DOCX and PDF reports from recorded state")
    p.add_argument("workspace")
    p = sub.add_parser("serve", help="Start the local web dashboard")
    p.add_argument("--workspace-root", type=Path)
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=8765)
    p = sub.add_parser("doctor", help="Check Python, dependencies, applications, AI providers and desktop session")
    p.add_argument("--json", action="store_true")
    p.add_argument("--no-wsl", action="store_true", help="Skip probing forensic tools inside WSL")
    p.add_argument("--save", type=Path, help="Also write environment.json to this path")
    p = sub.add_parser("capabilities", help="List every registered capability")
    p.add_argument("--tool")
    p.add_argument("--json", action="store_true")
    sub.add_parser("plugins", help="List integrations, their source and plugin load errors")
    p = sub.add_parser("environment", help="Discover installed applications and write environment.json")
    p.add_argument("--output", type=Path, default=Path("environment.json"))
    p.add_argument("--wsl", action="store_true")
    sub.add_parser("config", help="Print the effective configuration")
    return parser


def _targets(args: argparse.Namespace) -> set[str]:
    return {t.strip() for t in getattr(args, "allowed_target", []) if t.strip()}


def _root(args: argparse.Namespace) -> Path:
    return args.workspace_root or Path(get_config().workspace_root)


def main(argv: list[str] | None = None) -> int:
    args = make_parser().parse_args(argv)
    try:
        config = load_config(args.config)
        set_config(config)
        configure_logging(args.log_level or config.logging.level, args.json_logs or config.logging.json_logs)
        command = args.command
        if command == "analyze":
            result = analyze(args.paths)
            plan = build_plan(result)
            workspace = create_workspace(result, plan, _root(args), not args.no_copy_inputs)
            if args.output:
                _write_json(args.output / "assignment_analysis.json", result)
                _write_json(args.output / "checklist.json", [{"id": t.id, "title": t.title, "status": t.status.value} for t in plan.steps])
                _write_json(args.output / "execution_plan.json", plan)
            _print({"assignment": result.assignment, "workspace": str(workspace), "tools": result.tools,
                    "files": [{"file": f.workspace_path or f.path, "role": f.role} for f in result.files],
                    "steps": len(plan.steps), "questions": len(result.questions), "deliverables": result.deliverables[:30],
                    "limitations": result.limitations})
        elif command == "plan":
            workspace, planner = plan_assignment(args.paths, _root(args), args.ai_provider, args.model, _targets(args))
            state = load_state(workspace)
            _print({"workspace": str(workspace), "planner": planner, "planner_detail": state.plan.planner,
                    "warnings": state.plan.warnings,
                    "steps": [{"id": t.id, "title": t.title, "capability": t.action, "parameters": t.parameters,
                               "depends_on": t.depends_on, "required": t.required} for t in state.plan.steps]})
        elif command == "run":
            workspace, state, planner = run_assignment(args.paths, _root(args), args.ai_provider, args.model, _targets(args))
            _print({"assignment": state.assignment, "workspace": str(workspace), "planner": planner, "status": state.status,
                    "reason": state.status_reason, "completed": state.completed_steps,
                    "steps": {t.id: t.status.value for t in state.plan.steps},
                    "reports": {"docx": str(workspace / "reports" / f"{state.assignment}_Report.docx"),
                                "pdf": str(workspace / "reports" / f"{state.assignment}_Report.pdf")}})
            return 0 if state.status == "COMPLETED" else 3
        elif command == "status":
            workspace = _workspace_arg(args.workspace)
            state = load_state(workspace)
            _print({"assignment": state.assignment, "status": state.status, "reason": state.status_reason,
                    "workspace": str(workspace), "steps": [{"id": t.id, "title": t.title, "capability": t.action,
                                                            "status": t.status.value, "reason": t.status_reason} for t in state.plan.steps],
                    "pending_confirmations": [c.model_dump(mode="json") for c in state.confirmations if c.status == "PENDING"],
                    "evidence": validate_evidence(workspace)})
        elif command == "resume":
            workspace = _workspace_arg(args.workspace)
            state = load_state(workspace)
            _write_json(workspace / "state" / "recovery_check.json", {
                "loaded": True, "status": state.status, "completed_steps": state.completed_steps,
                "evidence_validation": validate_evidence(workspace), "inputs": verify_inputs_unchanged(workspace)})
            if args.verify_only:
                print(f"Checkpoint validated: {state.assignment}; {len(state.completed_steps)}/{len(state.plan.steps)} steps marked complete.")
            else:
                state = execute_workspace(workspace, _targets(args))
                print(f"Checkpoint resumed: {state.assignment}; {len(state.completed_steps)}/{len(state.plan.steps)} steps completed; "
                      f"status {state.status}.")
        elif command in {"pause", "stop"}:
            state = request_control(_workspace_arg(args.workspace), "PAUSE_REQUESTED" if command == "pause" else "STOP_REQUESTED")
            print(f"{command.title()} requested for {state.assignment}.")
        elif command in {"approve", "reject"}:
            decide_confirmation(_workspace_arg(args.workspace), args.step_id, command == "approve", args.note)
            print(f"Step {args.step_id} {'approved' if command == 'approve' else 'rejected'}; run `lab-agent resume` to continue.")
        elif command == "complete-step":
            workspace = _workspace_arg(args.workspace)
            state = load_state(workspace)
            task = next((t for t in state.plan.steps if t.id == args.step_id), None)
            if task is None:
                raise ValueError(f"Unknown step id: {args.step_id}")
            if task.evidence_required:
                checks = {c["id"]: c for c in validate_evidence(workspace)}
                ok = [item for item in list_evidence(workspace) if item.step_id == task.id and checks.get(item.id, {}).get("verified")
                      and (task.evidence_type_required is None or item.type == task.evidence_type_required)]
                if not ok:
                    raise ValueError(f"Step {task.id} requires registered, intact evidence before completion.")
            task.status, task.status_reason = TaskStatus.COMPLETED, f"manually verified: {args.verification}"
            state.current_step = args.step_id
            if args.step_id not in state.completed_steps:
                state.completed_steps.append(args.step_id)
            state.status = "IN_PROGRESS" if len(state.completed_steps) < len(state.plan.steps) else "COMPLETED"
            state.errors = [e for e in state.errors if e.get("step_id") != args.step_id]
            save_state(workspace, state)
            with (workspace / "logs" / "verification.jsonl").open("a", encoding="utf-8") as stream:
                stream.write(json.dumps({"step_id": args.step_id, "verification": args.verification}, ensure_ascii=False) + "\n")
            print(f"Step {args.step_id} marked complete based on recorded manual verification.")
        elif command == "hash":
            _print(calculate_hashes(args.file.resolve()))
        elif command == "files":
            workspace = _workspace_arg(args.workspace)
            print("\n".join(str(p.relative_to(workspace)) for p in list_files(workspace, args.path)))
        elif command == "search":
            _print(search_files(_workspace_arg(args.workspace), args.query, args.path))
        elif command == "metadata":
            _print(file_metadata(_workspace_arg(args.workspace), args.path))
        elif command == "copy":
            _print(copy_file(_workspace_arg(args.workspace), args.source, args.destination))
        elif command == "extract-zip":
            _print(extract_zip(_workspace_arg(args.workspace), args.archive, args.destination))
        elif command == "powershell":
            record = run_powershell(_workspace_arg(args.workspace), args.ps_command, allow_unsafe=args.allow_unsafe, timeout=args.timeout)
            print(record.model_dump_json(indent=2))
            return record.exit_code or 0
        elif command == "launch":
            workspace = _workspace_arg(args.workspace)
            process = launch_application(args.executable, args.args, cwd=workspace)
            launch_log = workspace / "logs" / "applications.jsonl"
            launch_log.parent.mkdir(parents=True, exist_ok=True)
            with launch_log.open("a", encoding="utf-8") as stream:
                stream.write(json.dumps({"executable": args.executable, "args": args.args, "pid": process.pid}, ensure_ascii=False) + "\n")
            print(json.dumps({"pid": process.pid, "executable": args.executable}, ensure_ascii=False))
        elif command == "screenshot":
            workspace = _workspace_arg(args.workspace)
            path = take_screenshot(workspace, name=args.name, window_title_re=args.window)
            print(register_evidence(workspace, path, args.description, "screenshot", args.step).model_dump_json(indent=2))
        elif command == "evidence":
            workspace = _workspace_arg(args.workspace)
            if not args.path:
                _print([item.model_dump(mode="json") for item in list_evidence(workspace)])
            else:
                if not args.description:
                    raise ValueError("--description is required when registering evidence")
                print(register_evidence(workspace, workspace / args.path, args.description, args.type, args.step).model_dump_json(indent=2))
        elif command == "review":
            workspace = _workspace_arg(args.workspace)
            state = load_state(workspace)
            integrity = validate_evidence(workspace)
            evidence = list_evidence(workspace)
            required = [t for t in state.plan.steps if t.required]
            summary: dict[str, object] = {
                "assignment": state.assignment, "status": state.status, "reason": state.status_reason,
                "required_steps": len(required), "completed_steps": len([t for t in required if t.status == TaskStatus.COMPLETED]),
                "failed_steps": [t.id for t in state.plan.steps if t.status == TaskStatus.FAILED],
                "blocked_steps": [t.id for t in state.plan.steps if t.status == TaskStatus.BLOCKED],
                "evidence_count": len(evidence), "invalid_evidence": [c for c in integrity if not c["verified"]],
                "screenshot_count": sum(item.type == "screenshot" for item in evidence),
                "missing_required_evidence_steps": [
                    t.id for t in state.plan.steps if t.evidence_required and not any(
                        item.step_id == t.id and (t.evidence_type_required is None or item.type == t.evidence_type_required)
                        for item in evidence)],
                "inputs_unchanged": verify_inputs_unchanged(workspace), "ready": False, "report_path": None,
            }
            summary["ready"] = (summary["completed_steps"] == summary["required_steps"] and not summary["failed_steps"]
                                and not summary["invalid_evidence"] and not summary["missing_required_evidence_steps"])
            report = workspace / "reports" / f"{state.assignment}_Report.docx"
            summary["report_path"] = str(report) if report.exists() else None
            _write_json(workspace / "execution_summary.json", summary)
            _print(summary)
        elif command == "report":
            _print(generate_reports(_workspace_arg(args.workspace)))
        elif command == "serve":
            try:
                import uvicorn
            except ImportError as exc:
                raise RuntimeError("Web dashboard requires the web extra: pip install -e .[web]") from exc
            from .web import create_app

            uvicorn.run(create_app(_root(args)), host=args.host, port=args.port)
        elif command == "doctor":
            from .environment import format_doctor, run_doctor, save_environment

            doctor = run_doctor(_registry(), config, Path(config.workspace_root), include_wsl=not args.no_wsl)
            if args.save:
                save_environment(doctor["environment"], args.save)
            if args.json:
                _print(doctor)
            else:
                print(format_doctor(doctor))
            return 0 if doctor["result"] != "NOT_READY" else 1
        elif command == "capabilities":
            registry = _registry()
            rows = [c.to_dict() for c in registry.capabilities() if not args.tool or c.tool == args.tool]
            if args.json:
                _print(rows)
            else:
                for row in rows:
                    params = ", ".join(p["name"] + ("" if p["required"] else "?") for p in row["parameters"])
                    print(f"{row['name']:<34} {row['description']}" + (f"  [{params}]" if params else ""))
        elif command == "plugins":
            registry = _registry()
            _print({"integrations": [{"name": a.name, "source": registry.sources.get(a.name), "capabilities": len(a.capabilities())}
                                     for a in registry.adapters()],
                    "load_errors": registry.load_errors,
                    "entry_point_group": "doneasik_lab_agent.integrations",
                    "plugin_directories": config.plugins.directories})
        elif command == "environment":
            from .environment import discover_environment, save_environment

            environment = discover_environment(_registry(), config, include_wsl=args.wsl)
            save_environment(environment, args.output)
            _print({name: {k: app[k] for k in ("available", "version", "path")} for name, app in environment["applications"].items()})
        elif command == "config":
            print(config.model_dump_json(indent=2))
        return 0
    except (ValueError, FileNotFoundError, PermissionError, RuntimeError, OSError) as exc:
        print(f"lab-agent: error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
