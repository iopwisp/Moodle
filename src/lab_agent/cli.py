"""Command-line interface for the local lab workflow MVP."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .analyzer import analyze, build_plan
from .evidence import list_evidence, register_evidence, validate_evidence
from .filesystem import copy_file, extract_zip, file_metadata, list_files, search_files
from .models import TaskStatus
from .reports import generate_reports
from .runner import execute_workspace, run_assignment
from .tools.powershell import run_powershell
from .tools.process import launch_application
from .tools.screenshot import take_screenshot
from .workspace import calculate_hashes, create_workspace, load_state, save_state


def _write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if hasattr(value, "model_dump_json"):
        path.write_text(value.model_dump_json(indent=2), encoding="utf-8")
    else:
        path.write_text(json.dumps(value, indent=2, ensure_ascii=False, default=str), encoding="utf-8")


def _workspace_arg(value: str) -> Path:
    path = Path(value).expanduser().resolve()
    if not (path / "state" / "state.json").is_file():
        raise ValueError(f"Not a Lab Agent workspace (missing state/state.json): {path}")
    return path


def make_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="lab-agent", description="Local evidence-oriented university lab assistant")
    sub = parser.add_subparsers(dest="command", required=True)
    p = sub.add_parser("analyze", help="Extract assignment text and create analysis, plan, and workspace")
    p.add_argument("paths", nargs="+", type=Path)
    p.add_argument("--workspace-root", type=Path, default=Path("workspace"))
    p.add_argument("--no-copy-inputs", action="store_true")
    p.add_argument("--output", type=Path, help="Optional directory for analysis JSON and plan JSON")
    p = sub.add_parser("run", help="Analyze, plan with AI when configured, execute, capture evidence, and generate reports")
    p.add_argument("paths", nargs="+", type=Path)
    p.add_argument("--workspace-root", type=Path, default=Path("workspace"))
    p.add_argument("--ai-provider", choices=("auto", "openai", "ollama", "deterministic"), default="auto")
    p.add_argument("--model")
    p.add_argument("--allowed-target", action="append", default=[], help="Authorized browser hostname; localhost is always allowed")
    p = sub.add_parser("status", help="Show saved workflow state and evidence validation")
    p.add_argument("workspace")
    p = sub.add_parser("resume", help="Validate evidence and execute unfinished or failed steps")
    p.add_argument("workspace")
    p.add_argument("--verify-only", action="store_true")
    p.add_argument("--allowed-target", action="append", default=[])
    p = sub.add_parser("complete-step", help="Mark a step complete after manual verification")
    p.add_argument("workspace"); p.add_argument("step_id", type=int)
    p.add_argument("--verification", required=True, help="Describe what was observed to verify completion")
    p = sub.add_parser("hash", help="Calculate MD5, SHA1, and SHA256 for a file")
    p.add_argument("file", type=Path)
    p = sub.add_parser("files", help="List files under a workspace-relative path")
    p.add_argument("workspace"); p.add_argument("--path", default=".")
    p = sub.add_parser("search", help="Search workspace file names and small text files")
    p.add_argument("workspace"); p.add_argument("query"); p.add_argument("--path", default=".")
    p = sub.add_parser("metadata", help="Show size, modification time, and SHA-256 for a workspace file")
    p.add_argument("workspace"); p.add_argument("path")
    p = sub.add_parser("copy", help="Copy a file within a workspace and compare SHA-256")
    p.add_argument("workspace"); p.add_argument("source"); p.add_argument("destination")
    p = sub.add_parser("extract-zip", help="Safely extract a ZIP within a workspace")
    p.add_argument("workspace"); p.add_argument("archive"); p.add_argument("destination")
    p = sub.add_parser("powershell", help="Run a logged PowerShell command (requires explicit unsafe opt-in)")
    p.add_argument("workspace"); p.add_argument("ps_command")
    p.add_argument("--allow-unsafe", action="store_true"); p.add_argument("--timeout", type=int, default=120)
    p = sub.add_parser("launch", help="Launch a desktop application without shell interpretation")
    p.add_argument("workspace"); p.add_argument("executable"); p.add_argument("args", nargs="*")
    p = sub.add_parser("screenshot", help="Capture and register a desktop screenshot")
    p.add_argument("workspace"); p.add_argument("--name"); p.add_argument("--description", required=True); p.add_argument("--step", type=int)
    p = sub.add_parser("evidence", help="Register a file already stored in the workspace")
    p.add_argument("workspace"); p.add_argument("path"); p.add_argument("--description", required=True); p.add_argument("--type", default="file"); p.add_argument("--step", type=int)
    p = sub.add_parser("review", help="Validate evidence and produce execution summary JSON")
    p.add_argument("workspace")
    p = sub.add_parser("report", help="Generate DOCX and PDF reports from recorded state")
    p.add_argument("workspace")
    p = sub.add_parser("serve", help="Start the local web dashboard")
    p.add_argument("--workspace-root", type=Path, default=Path("workspace"))
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=8765)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = make_parser().parse_args(argv)
    try:
        if args.command == "analyze":
            result = analyze(args.paths)
            plan = build_plan(result)
            workspace = create_workspace(result, plan, args.workspace_root, not args.no_copy_inputs)
            if args.output:
                _write_json(args.output / "assignment_analysis.json", result)
                _write_json(args.output / "checklist.json", [{"id": t.id, "title": t.title, "status": t.status.value} for t in plan.steps])
                _write_json(args.output / "execution_plan.json", plan)
            print(json.dumps({"assignment": result.assignment, "workspace": str(workspace), "tools": result.tools,
                              "steps": len(plan.steps), "limitations": result.limitations}, ensure_ascii=False, indent=2))
        elif args.command == "run":
            workspace, state, planner = run_assignment(args.paths, args.workspace_root, args.ai_provider, args.model, set(args.allowed_target))
            print(json.dumps({"assignment": state.assignment, "workspace": str(workspace), "planner": planner,
                              "status": state.status, "completed": state.completed_steps,
                              "reports": {"docx": str(workspace / "reports" / f"{state.assignment}_Report.docx"),
                                          "pdf": str(workspace / "reports" / f"{state.assignment}_Report.pdf")}}, ensure_ascii=False, indent=2))
        elif args.command == "status":
            workspace = _workspace_arg(args.workspace); state = load_state(workspace)
            print(json.dumps({"assignment": state.assignment, "status": state.status, "workspace": str(workspace),
                              "steps": len(state.plan.steps), "completed": state.completed_steps,
                              "evidence": validate_evidence(workspace)}, ensure_ascii=False, indent=2))
        elif args.command == "resume":
            workspace = _workspace_arg(args.workspace); state = load_state(workspace)
            _write_json(workspace / "state" / "recovery_check.json", {"loaded": True, "status": state.status,
                                                                       "completed_steps": state.completed_steps,
                                                                       "evidence_validation": validate_evidence(workspace)})
            if args.verify_only:
                print(f"Checkpoint validated: {state.assignment}; {len(state.completed_steps)}/{len(state.plan.steps)} steps marked complete.")
            else:
                state = execute_workspace(workspace, set(args.allowed_target))
                print(f"Checkpoint resumed: {state.assignment}; {len(state.completed_steps)}/{len(state.plan.steps)} steps completed.")
        elif args.command == "complete-step":
            workspace = _workspace_arg(args.workspace); state = load_state(workspace)
            task = next((t for t in state.plan.steps if t.id == args.step_id), None)
            if task is None: raise ValueError(f"Unknown step id: {args.step_id}")
            if task.evidence_required:
                verified_for_step = [item for item in list_evidence(workspace)
                                     if item.step_id == task.id and item.verified
                                     and (task.evidence_type_required is None or item.type == task.evidence_type_required)]
                if not any(check["id"] == item.id and check["verified"]
                           for item in verified_for_step for check in validate_evidence(workspace)):
                    raise ValueError(f"Step {task.id} requires registered, intact evidence before completion.")
            task.status = TaskStatus.COMPLETED; state.current_step = args.step_id
            if args.step_id not in state.completed_steps: state.completed_steps.append(args.step_id)
            state.status = "IN_PROGRESS" if len(state.completed_steps) < len(state.plan.steps) else "COMPLETED"
            state.errors = [e for e in state.errors if e.get("step_id") != args.step_id]
            save_state(workspace, state)
            with (workspace / "logs" / "verification.jsonl").open("a", encoding="utf-8") as stream:
                stream.write(json.dumps({"step_id": args.step_id, "verification": args.verification}, ensure_ascii=False) + "\n")
            print(f"Step {args.step_id} marked complete based on recorded manual verification.")
        elif args.command == "hash":
            path = args.file.resolve()
            print(json.dumps(calculate_hashes(path), indent=2))
        elif args.command == "files":
            print("\n".join(str(p.relative_to(_workspace_arg(args.workspace))) for p in list_files(_workspace_arg(args.workspace), args.path)))
        elif args.command == "search":
            print(json.dumps(search_files(_workspace_arg(args.workspace), args.query, args.path), indent=2))
        elif args.command == "metadata":
            print(json.dumps(file_metadata(_workspace_arg(args.workspace), args.path), indent=2))
        elif args.command == "copy":
            print(json.dumps(copy_file(_workspace_arg(args.workspace), args.source, args.destination), indent=2))
        elif args.command == "extract-zip":
            print(json.dumps(extract_zip(_workspace_arg(args.workspace), args.archive, args.destination), indent=2))
        elif args.command == "powershell":
            record = run_powershell(_workspace_arg(args.workspace), args.ps_command, allow_unsafe=args.allow_unsafe, timeout=args.timeout)
            print(record.model_dump_json(indent=2))
            return record.exit_code or 0
        elif args.command == "launch":
            workspace = _workspace_arg(args.workspace)
            process = launch_application(args.executable, args.args, cwd=workspace)
            launch_log = workspace / "logs" / "applications.jsonl"
            launch_log.parent.mkdir(parents=True, exist_ok=True)
            with launch_log.open("a", encoding="utf-8") as stream:
                stream.write(json.dumps({"executable": args.executable, "args": args.args, "pid": process.pid}, ensure_ascii=False) + "\n")
            print(json.dumps({"pid": process.pid, "executable": args.executable}, ensure_ascii=False))
        elif args.command == "screenshot":
            workspace = _workspace_arg(args.workspace); path = take_screenshot(workspace, name=args.name)
            item = register_evidence(workspace, path, args.description, "screenshot", args.step)
            print(item.model_dump_json(indent=2))
        elif args.command == "evidence":
            workspace = _workspace_arg(args.workspace)
            print(register_evidence(workspace, workspace / args.path, args.description, args.type, args.step).model_dump_json(indent=2))
        elif args.command == "review":
            workspace = _workspace_arg(args.workspace); state = load_state(workspace)
            checks = validate_evidence(workspace)
            summary = {"assignment": state.assignment, "status": state.status,
                       "required_steps": sum(t.required for t in state.plan.steps),
                       "completed_steps": len(state.completed_steps), "failed_steps": [t.id for t in state.plan.steps if t.status == TaskStatus.FAILED],
                       "evidence_count": len(list_evidence(workspace)), "invalid_evidence": [c for c in checks if not c["verified"]],
                       "screenshot_count": sum(item.type == "screenshot" for item in list_evidence(workspace)),
                       "missing_required_evidence_steps": [task.id for task in state.plan.steps if task.evidence_required and not any(item.step_id == task.id and item.verified and (task.evidence_type_required is None or item.type == task.evidence_type_required) and any(check["id"] == item.id and check["verified"] for check in checks) for item in list_evidence(workspace))],
                       "ready": False,
                       "report_path": None}
            summary["ready"] = (summary["completed_steps"] == summary["required_steps"]
                                 and not summary["failed_steps"] and not summary["invalid_evidence"]
                                 and not summary["missing_required_evidence_steps"])
            report = workspace / "reports" / f"{state.assignment}_Report.docx"
            summary["report_path"] = str(report) if report.exists() else None
            _write_json(workspace / "execution_summary.json", summary)
            print(json.dumps(summary, ensure_ascii=False, indent=2))
        elif args.command == "report":
            print(json.dumps(generate_reports(_workspace_arg(args.workspace)), ensure_ascii=False, indent=2))
        elif args.command == "serve":
            try:
                import uvicorn
            except ImportError as exc:
                raise RuntimeError("Web dashboard requires the web extra: pip install -e .[web]") from exc
            from .web import create_app
            uvicorn.run(create_app(args.workspace_root), host=args.host, port=args.port)
        return 0
    except (ValueError, FileNotFoundError, PermissionError, RuntimeError, OSError) as exc:
        print(f"lab-agent: error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
