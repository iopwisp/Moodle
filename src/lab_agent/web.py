"""A small local FastAPI dashboard for assignment upload, execution, and reports."""

from __future__ import annotations

import shutil
import uuid
from pathlib import Path

from .database import RunDatabase
from .models import TaskStatus
from .reports import generate_reports
from .runner import execute_workspace, run_assignment
from .workspace import load_state, save_state


def _workspace(root: Path, assignment_id: str) -> Path:
    candidate = (root.resolve() / assignment_id).resolve()
    if not candidate.is_relative_to(root.resolve()) or not (candidate / "state" / "state.json").is_file():
        raise FileNotFoundError("Unknown assignment")
    return candidate


def _assignments(root: Path) -> list[dict[str, object]]:
    root.mkdir(parents=True, exist_ok=True)
    rows: list[dict[str, object]] = []
    for state_file in root.glob("*/state/state.json"):
        state = load_state(state_file.parents[1])
        rows.append({"id": state_file.parents[1].name, "name": state.assignment, "status": state.status,
                     "completed": len(state.completed_steps), "total": len(state.plan.steps)})
    return sorted(rows, key=lambda value: str(value["id"]), reverse=True)


def create_app(workspace_root: Path):
    try:
        from fastapi import FastAPI, File, Form, HTTPException, UploadFile
        from fastapi.responses import FileResponse, HTMLResponse, RedirectResponse
    except ImportError as exc:
        raise RuntimeError("Web dashboard requires the web extra: pip install -e .[web]") from exc

    root = workspace_root.expanduser().resolve(); root.mkdir(parents=True, exist_ok=True)
    app = FastAPI(title="Lab Agent", version="0.2.0")

    def get_workspace(assignment_id: str) -> Path:
        try: return _workspace(root, assignment_id)
        except FileNotFoundError as exc: raise HTTPException(status_code=404, detail=str(exc)) from exc

    @app.get("/", response_class=HTMLResponse)
    def dashboard() -> str:
        cards = "".join(f"<li><a href='/assignments/{row['id']}'>{row['name']}</a> - {row['status']} ({row['completed']}/{row['total']})</li>" for row in _assignments(root)) or "<li>No assignments yet.</li>"
        return f"""<!doctype html><html><head><meta charset='utf-8'><title>Lab Agent</title><style>body{{font:16px system-ui;margin:2rem;max-width:860px}}input,button{{margin:.4rem 0;padding:.45rem}}pre{{background:#f4f4f4;padding:1rem;white-space:pre-wrap}}a{{color:#0645ad}}</style></head><body><h1>Lab Agent</h1><p>Upload an assignment. The agent creates a workspace, executes its constrained plan, captures evidence, and generates DOCX/PDF reports.</p><form action='/assignments/run-upload' method='post' enctype='multipart/form-data'><label>Assignment and evidence files<br><input type='file' name='files' multiple required></label><br><label>AI provider <select name='provider'><option value='auto'>Auto</option><option value='openai'>OpenAI</option><option value='ollama'>Ollama</option><option value='deterministic'>Deterministic fallback</option></select></label><br><label>Model (optional) <input name='model'></label><br><label>Authorized browser hostnames, comma-separated <input name='allowed_targets'></label><br><button type='submit'>Run assignment</button></form><h2>Assignments</h2><ul>{cards}</ul></body></html>"""

    @app.post("/assignments/analyze")
    async def analyze_upload(files: list[UploadFile] = File(...), provider: str = Form("auto"), model: str = Form("")) -> dict[str, object]:  # noqa: B008
        upload = root / "uploads" / uuid.uuid4().hex; upload.mkdir(parents=True)
        paths: list[Path] = []
        for file in files:
            filename = Path(file.filename or "upload.bin").name
            target = upload / filename
            with target.open("wb") as destination: shutil.copyfileobj(file.file, destination)
            paths.append(target)
        workspace, state, planner = run_assignment(paths, root, provider, model or None)
        return {"id": workspace.name, "status": state.status, "planner": planner, "reports": {"docx": f"/reports/{workspace.name}/docx", "pdf": f"/reports/{workspace.name}/pdf"}}

    @app.post("/assignments/run-upload")
    async def run_upload(files: list[UploadFile] = File(...), provider: str = Form("auto"), model: str = Form(""), allowed_targets: str = Form("")):  # noqa: B008
        upload = root / "uploads" / uuid.uuid4().hex; upload.mkdir(parents=True)
        paths: list[Path] = []
        for file in files:
            target = upload / Path(file.filename or "upload.bin").name
            with target.open("wb") as destination: shutil.copyfileobj(file.file, destination)
            paths.append(target)
        targets = {host.strip() for host in allowed_targets.split(",") if host.strip()}
        workspace, _, _ = run_assignment(paths, root, provider, model or None, targets)
        return RedirectResponse(f"/assignments/{workspace.name}", status_code=303)

    @app.get("/assignments")
    def assignments() -> list[dict[str, object]]: return _assignments(root)

    @app.get("/assignments/{assignment_id}", response_class=HTMLResponse)
    def assignment_page(assignment_id: str) -> str:
        workspace = get_workspace(assignment_id); state = load_state(workspace); db = RunDatabase(workspace)
        steps = "".join(f"<li>{step.id}. {step.title} - <b>{step.status.value}</b> ({step.action})</li>" for step in state.plan.steps)
        report_links = f"<a href='/reports/{assignment_id}/docx'>DOCX report</a> | <a href='/reports/{assignment_id}/pdf'>PDF report</a>"
        return f"<!doctype html><html><head><meta charset='utf-8'><title>{state.assignment}</title></head><body style='font:16px system-ui;margin:2rem;max-width:860px'><p><a href='/'>Back</a></p><h1>{state.assignment}</h1><p>Status: <b>{state.status}</b></p><form action='/assignments/{assignment_id}/resume' method='post'><button>Resume unfinished steps</button></form><p>{report_links}</p><h2>Tasks</h2><ol>{steps}</ol><h2>Recent events</h2><pre>{db.events(state.run_id or state.assignment, 20)}</pre></body></html>"

    @app.post("/assignments/{assignment_id}/run")
    def run_existing(assignment_id: str) -> dict[str, object]:
        workspace = get_workspace(assignment_id); state = execute_workspace(workspace)
        return {"id": assignment_id, "status": state.status}

    @app.post("/assignments/{assignment_id}/resume")
    def resume_existing(assignment_id: str):
        workspace = get_workspace(assignment_id); execute_workspace(workspace)
        return RedirectResponse(f"/assignments/{assignment_id}", status_code=303)

    @app.post("/assignments/{assignment_id}/stop")
    def stop(assignment_id: str) -> dict[str, str]:
        workspace = get_workspace(assignment_id); state = load_state(workspace); state.status = "STOPPED"; save_state(workspace, state)
        RunDatabase(workspace).event(state.run_id or state.assignment, "agent.stopped")
        return {"status": "STOPPED"}

    @app.get("/assignments/{assignment_id}/tasks")
    def tasks(assignment_id: str) -> list[dict[str, object]]:
        return [task.model_dump(mode="json") for task in load_state(get_workspace(assignment_id)).plan.steps]

    @app.get("/assignments/{assignment_id}/evidence")
    def evidence(assignment_id: str) -> list[dict[str, object]]:
        from .evidence import list_evidence
        return [item.model_dump(mode="json") for item in list_evidence(get_workspace(assignment_id))]

    @app.get("/assignments/{assignment_id}/logs")
    def logs(assignment_id: str) -> list[dict[str, object]]:
        workspace = get_workspace(assignment_id); state = load_state(workspace)
        return RunDatabase(workspace).events(state.run_id or state.assignment)

    @app.get("/assignments/{assignment_id}/screenshots")
    def screenshots(assignment_id: str) -> list[str]:
        workspace = get_workspace(assignment_id)
        return [path.relative_to(workspace).as_posix() for path in sorted((workspace / "screenshots").glob("*.png"))]

    @app.post("/assignments/{assignment_id}/tasks/{step_id}/retry")
    def retry_task(assignment_id: str, step_id: int) -> dict[str, object]:
        workspace = get_workspace(assignment_id); state = load_state(workspace)
        task = next((item for item in state.plan.steps if item.id == step_id), None)
        if task is None: raise HTTPException(status_code=404, detail="Unknown task")
        task.status = TaskStatus.PENDING
        state.errors = [error for error in state.errors if error.get("step_id") != step_id]
        save_state(workspace, state)
        executed = execute_workspace(workspace)
        return {"id": assignment_id, "step_id": step_id, "status": executed.status}

    @app.post("/assignments/{assignment_id}/tasks/{step_id}/skip")
    def skip_task(assignment_id: str, step_id: int) -> dict[str, object]:
        workspace = get_workspace(assignment_id); state = load_state(workspace)
        task = next((item for item in state.plan.steps if item.id == step_id), None)
        if task is None: raise HTTPException(status_code=404, detail="Unknown task")
        task.status = TaskStatus.SKIPPED
        save_state(workspace, state); RunDatabase(workspace).event(state.run_id or state.assignment, "task.skipped", {"step_id": step_id})
        return {"id": assignment_id, "step_id": step_id, "status": task.status.value}

    @app.post("/reports/{assignment_id}/generate")
    def generate(assignment_id: str) -> dict[str, str]:
        return generate_reports(get_workspace(assignment_id))

    @app.get("/reports/{assignment_id}/{kind}")
    def report(assignment_id: str, kind: str):
        workspace = get_workspace(assignment_id); state = load_state(workspace)
        suffix = ".docx" if kind == "docx" else ".pdf" if kind == "pdf" else ""
        if not suffix: raise HTTPException(status_code=404, detail="Unknown report type")
        path = workspace / "reports" / f"{state.assignment}_Report{suffix}"
        if not path.is_file(): raise HTTPException(status_code=404, detail="Report has not been generated")
        return FileResponse(path, filename=path.name)

    return app
