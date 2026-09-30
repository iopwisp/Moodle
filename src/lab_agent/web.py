"""Local FastAPI dashboard: upload, live progress (SSE), controls and reports.

(No ``from __future__ import annotations`` here: FastAPI must resolve the
endpoint annotations, which reference names imported inside ``create_app``.)

Runs execute in background threads (one per workspace), so the page stays
responsive; Pause/Stop are cooperative requests stored in the checkpoint.
"""

import asyncio
import html
import json
import mimetypes
import shutil
import threading
import uuid
from pathlib import Path
from typing import Any

from .database import RunDatabase
from .evidence import list_evidence
from .models import TaskStatus
from .reports import generate_reports
from .runner import decide_confirmation, execute_workspace, plan_assignment, request_control
from .workspace import load_state, save_state

SERVABLE = ("screenshots", "results", "reports")


def _workspace(root: Path, assignment_id: str) -> Path:
    candidate = (root.resolve() / assignment_id).resolve()
    if not candidate.is_relative_to(root.resolve()) or not (candidate / "state" / "state.json").is_file():
        raise FileNotFoundError("Unknown assignment")
    return candidate


def _assignments(root: Path) -> list[dict[str, object]]:
    root.mkdir(parents=True, exist_ok=True)
    rows: list[dict[str, object]] = []
    for state_file in root.glob("*/state/state.json"):
        try:
            state = load_state(state_file.parents[1])
        except (OSError, ValueError):
            continue
        rows.append({"id": state_file.parents[1].name, "name": state.assignment, "status": str(state.status),
                     "completed": len(state.completed_steps), "total": len(state.plan.steps)})
    return sorted(rows, key=lambda value: str(value["id"]), reverse=True)


def status_payload(workspace: Path) -> dict[str, Any]:
    state = load_state(workspace)
    steps = state.plan.steps
    done = sum(step.status in {TaskStatus.COMPLETED, TaskStatus.SKIPPED} for step in steps)
    current = state.step(state.current_step) if state.current_step else None
    evidence = list_evidence(workspace)
    reports = {kind: (workspace / "reports" / f"{state.assignment}_Report.{kind}").is_file() for kind in ("docx", "pdf")}
    return {
        "id": workspace.name, "assignment": state.assignment, "status": str(state.status), "reason": state.status_reason,
        "progress": round(100 * done / len(steps)) if steps else 0, "completed": done, "total": len(steps),
        "current": {"id": current.id, "title": current.title, "capability": current.action} if current else None,
        "application": state.current_application, "planner": state.plan.planner,
        "steps": [{"id": s.id, "title": s.title, "capability": s.action, "status": s.status.value, "reason": s.status_reason,
                   "summary": s.result_summary, "attempts": len(s.attempts), "depends_on": s.depends_on,
                   "checks": [{"type": c.get("type"), "passed": c.get("passed")} for c in s.verification_results]} for s in steps],
        "confirmations": [c.model_dump(mode="json") for c in state.confirmations if c.status == "PENDING"],
        "evidence": [{"id": e.id, "type": e.type, "step_id": e.step_id, "path": e.path, "sha256": e.sha256,
                      "description": e.description} for e in evidence],
        "errors": state.errors, "reports": reports,
    }


class RunManager:
    """Background execution threads keyed by workspace."""

    def __init__(self, options: dict[str, Any] | None = None) -> None:
        self.options = options or {}
        self._threads: dict[str, threading.Thread] = {}
        self._lock = threading.Lock()

    def running(self, workspace: Path) -> bool:
        thread = self._threads.get(str(workspace))
        return bool(thread and thread.is_alive())

    def start(self, workspace: Path, allowed_targets: set[str] | None = None) -> bool:
        with self._lock:
            if self.running(workspace):
                return False
            thread = threading.Thread(target=self._run, args=(workspace, allowed_targets), daemon=True,
                                      name=f"lab-agent-{workspace.name}")
            self._threads[str(workspace)] = thread
            thread.start()
            return True

    def _run(self, workspace: Path, allowed_targets: set[str] | None) -> None:
        try:
            allowed = {"config", "registry", "screenshot_fn", "environment", "advisor"}
            execute_workspace(workspace, allowed_targets, **{k: v for k, v in self.options.items() if k in allowed})
        except Exception as exc:  # noqa: BLE001 - surface in the dashboard instead of killing the thread silently
            state = load_state(workspace)
            state.status, state.status_reason = "FAILED", f"runner crashed: {type(exc).__name__}: {exc}"
            save_state(workspace, state)
            RunDatabase(workspace).event(state.run_id or state.assignment, "agent.failed", {"error": str(exc)})

    def wait(self, workspace: Path, timeout: float = 60) -> None:
        thread = self._threads.get(str(workspace))
        if thread:
            thread.join(timeout)


PAGE = """<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Lab Agent</title><style>
:root{--bg:#f6f7f9;--card:#fff;--ink:#1d2330;--muted:#5b6475;--line:#e3e6eb;--ok:#1e7d45;--bad:#b3261e;--warn:#9a6200;--run:#1f5fbf}
@media (prefers-color-scheme:dark){:root{--bg:#14161a;--card:#1c1f25;--ink:#e8eaee;--muted:#9aa3b2;--line:#2b3038}}
body{font:15px/1.45 system-ui,sans-serif;margin:0;background:var(--bg);color:var(--ink)}main{max-width:1100px;margin:auto;padding:16px}
.card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:16px;margin:12px 0}
h1{font-size:22px;margin:4px 0}h2{font-size:17px;margin:0 0 8px}.muted{color:var(--muted)}a{color:var(--run)}
.bar{height:10px;background:var(--line);border-radius:6px;overflow:hidden}.bar>div{height:100%;background:var(--run)}
table{width:100%;border-collapse:collapse;font-size:14px;table-layout:fixed}td,th{border-bottom:1px solid var(--line);padding:6px;text-align:left;vertical-align:top;overflow-wrap:anywhere}.scroll{overflow-x:auto}#steps th:nth-child(1){width:36px}#steps th:nth-child(2){width:20%}#steps th:nth-child(3){width:17%}#steps th:nth-child(4){width:95px}#steps th:nth-child(6){width:9%}#steps th:nth-child(7){width:70px}#evidence th:nth-child(1),#evidence th:nth-child(3){width:70px}
.COMPLETED{color:var(--ok)}.FAILED{color:var(--bad)}.BLOCKED{color:var(--warn)}.RUNNING{color:var(--run)}
button{padding:7px 12px;border-radius:7px;border:1px solid var(--line);background:var(--card);color:var(--ink);cursor:pointer;margin:2px}
.shots{display:flex;flex-wrap:wrap;gap:8px}.shots img{max-width:220px;border:1px solid var(--line);border-radius:6px}
pre{white-space:pre-wrap;font-size:12px;max-height:260px;overflow:auto}input,select{padding:6px;margin:4px 0;max-width:100%}
</style></head><body><main>__BODY__</main></body></html>"""


def _index_body(rows: list[dict[str, object]]) -> str:
    items = "".join(f"<tr><td><a href='/assignments/{html.escape(str(r['id']))}'>{html.escape(str(r['name']))}</a></td>"
                    f"<td class='{html.escape(str(r['status']))}'>{html.escape(str(r['status']))}</td><td>{r['completed']}/{r['total']}</td></tr>"
                    for r in rows) or "<tr><td colspan=3 class=muted>No assignments yet.</td></tr>"
    return f"""<h1>Lab Agent</h1><p class=muted>Upload the assignment, materials and evidence. The agent analyses every file, plans with
registered capabilities, executes, verifies, collects evidence and writes DOCX/PDF reports.</p>
<div class=card><h2>New assignment</h2><form action='/assignments/run-upload' method='post' enctype='multipart/form-data'>
<label>Assignment and evidence files<br><input type='file' name='files' multiple required></label><br>
<label>AI provider <select name='provider'><option value='auto'>Auto</option><option value='openai'>OpenAI</option>
<option value='ollama'>Ollama</option><option value='deterministic'>Deterministic</option></select></label>
<label>Model <input name='model' placeholder='optional'></label><br>
<label>Authorized hostnames (comma-separated) <input name='allowed_targets' placeholder='lab.example.edu'></label><br>
<button type='submit'>Analyse, plan and run</button></form></div>
<div class=card><h2>Assignments</h2><table><tr><th>Assignment</th><th>Status</th><th>Steps</th></tr>{items}</table></div>"""


def _assignment_body(assignment_id: str) -> str:
    safe = html.escape(assignment_id)
    return f"""<p><a href='/'>&larr; All assignments</a></p><h1 id=title>{safe}</h1>
<div class=card><div id=status class=muted>Loading...</div><div class=bar><div id=bar style='width:0%'></div></div>
<p id=current class=muted></p>
<button onclick="act('run')">Start / Resume</button><button onclick="act('pause')">Pause</button>
<button onclick="act('stop')">Stop</button><button onclick="act('report')">Regenerate report</button>
<span id=reports></span></div>
<div class=card id=confirm hidden><h2>Waiting for you</h2><div id=confirmations></div></div>
<div class=card><h2>Plan and execution</h2><div class=scroll><table id=steps></table></div></div>
<div class=card><h2>Screenshots</h2><div class=shots id=shots></div></div>
<div class=card><h2>Evidence</h2><table id=evidence></table></div>
<div class=card><h2>Live events</h2><pre id=events></pre></div>
<script>
const id={json.dumps(assignment_id)};const el=(t,c)=>{{const e=document.createElement(t);if(c!==undefined)e.textContent=c;return e}};
async function act(what,step){{const url=step?`/assignments/${{id}}/tasks/${{step}}/${{what}}`:(what==='report'?`/reports/${{id}}/generate`:`/assignments/${{id}}/${{what}}`);
await fetch(url,{{method:'POST'}});refresh()}}
async function refresh(){{const s=await (await fetch(`/assignments/${{id}}/status`)).json();
document.getElementById('title').textContent=s.assignment;
document.getElementById('status').textContent=`${{s.status}} - ${{s.completed}}/${{s.total}} steps (${{s.progress}}%) ${{s.reason||''}}`;
document.getElementById('bar').style.width=s.progress+'%';
document.getElementById('current').textContent=s.current?`Current: ${{s.application||''}} -> ${{s.current.title}} (${{s.current.capability}})`:`Planner: ${{s.planner||''}}`;
const r=document.getElementById('reports');r.replaceChildren();for(const k of ['docx','pdf'])if(s.reports[k]){{const a=el('a',' '+k.toUpperCase()+' ');a.href=`/reports/${{id}}/${{k}}`;r.append(a)}}
const t=document.getElementById('steps');t.replaceChildren();const h=el('tr');['#','Step','Capability','Status','Result','Checks',''].forEach(x=>h.append(el('th',x)));t.append(h);
for(const st of s.steps){{const tr=el('tr');tr.append(el('td',st.id),el('td',st.title),el('td',st.capability));const c=el('td',st.status);c.className=st.status;tr.append(c);
tr.append(el('td',st.summary||st.reason||''));const ok=st.checks.filter(x=>x.passed).length,bad=st.checks.filter(x=>!x.passed).map(x=>x.type);tr.append(el('td',st.checks.length?`${{ok}}/${{st.checks.length}} ✓`+(bad.length?' ✗ '+bad.join(', '):''):''));
const b=el('td');if(['FAILED','BLOCKED'].includes(st.status)){{const x=el('button','Retry');x.onclick=()=>act('retry',st.id);b.append(x)}}tr.append(b);t.append(tr)}}
const cf=document.getElementById('confirmations');cf.replaceChildren();document.getElementById('confirm').hidden=!s.confirmations.length;
for(const c of s.confirmations){{const d=el('div',`Step ${{c.step_id}}: ${{c.reason}} `);const a=el('button','Approve');a.onclick=()=>act('approve',c.step_id);
const n=el('button','Reject');n.onclick=()=>act('reject',c.step_id);d.append(a,n);cf.append(d)}}
const sh=document.getElementById('shots');sh.replaceChildren();for(const e of s.evidence.filter(e=>['screenshot','figure'].includes(e.type))){{
const a=el('a');a.href=`/assignments/${{id}}/files/${{e.path}}`;const i=el('img');i.src=a.href;i.title=e.description;a.append(i);sh.append(a)}}
const ev=document.getElementById('evidence');ev.replaceChildren();const eh=el('tr');['ID','Type','Step','File','SHA-256'].forEach(x=>eh.append(el('th',x)));ev.append(eh);
for(const e of s.evidence){{const tr=el('tr');tr.append(el('td',e.id),el('td',e.type),el('td',e.step_id??''),el('td',e.path),el('td',(e.sha256||'').slice(0,16)+'...'));ev.append(tr)}}}}
const log=document.getElementById('events');const src=new EventSource(`/assignments/${{id}}/events/stream`);
src.onmessage=m=>{{const e=JSON.parse(m.data);log.textContent=`${{e.created_at.slice(11,19)}} ${{e.event_type}} ${{JSON.stringify(e.payload)}}\\n`+log.textContent;refresh()}};
refresh();setInterval(refresh,5000);
</script>"""


def create_app(workspace_root: Path, *, run_options: dict[str, Any] | None = None) -> Any:
    try:
        from fastapi import FastAPI, File, Form, HTTPException, UploadFile
        from fastapi.responses import (
            FileResponse,
            HTMLResponse,
            RedirectResponse,
            StreamingResponse,
        )
    except ImportError as exc:
        raise RuntimeError("Web dashboard requires the web extra: pip install -e .[web]") from exc

    root = workspace_root.expanduser().resolve()
    root.mkdir(parents=True, exist_ok=True)
    options = dict(run_options or {})
    manager = RunManager(options)
    app = FastAPI(title="Lab Agent", version="0.3.0")
    app.state.manager = manager

    def get_workspace(assignment_id: str) -> Path:
        try:
            return _workspace(root, assignment_id)
        except FileNotFoundError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc

    def save_uploads(files: list[UploadFile]) -> list[Path]:
        upload = root / "uploads" / uuid.uuid4().hex
        upload.mkdir(parents=True)
        paths: list[Path] = []
        for file in files:
            target = upload / Path(file.filename or "upload.bin").name
            with target.open("wb") as destination:
                shutil.copyfileobj(file.file, destination)
            paths.append(target)
        return paths

    def plan(paths: list[Path], provider: str, model: str, targets: set[str]) -> Path:
        workspace, _ = plan_assignment(paths, root, provider, model or None, targets,
                                       **{k: v for k, v in options.items() if k in {"config", "registry", "environment", "llm",
                                                                                     "screenshot_fn"}})
        return workspace

    @app.get("/", response_class=HTMLResponse)
    def dashboard() -> str:
        return PAGE.replace("__BODY__", _index_body(_assignments(root)))

    @app.post("/assignments/analyze")
    async def analyze_upload(files: list[UploadFile] = File(...), provider: str = Form("auto"), model: str = Form(""),  # noqa: B008
                             allowed_targets: str = Form("")) -> dict[str, object]:
        targets = {host.strip() for host in allowed_targets.split(",") if host.strip()}
        workspace = plan(save_uploads(files), provider, model, targets)
        manager.start(workspace, targets)
        return {"id": workspace.name, "status": "STARTED", "planner": load_state(workspace).plan.planner,
                "reports": {"docx": f"/reports/{workspace.name}/docx", "pdf": f"/reports/{workspace.name}/pdf"}}

    @app.post("/assignments/plan-upload")
    async def plan_upload(files: list[UploadFile] = File(...), provider: str = Form("auto"), model: str = Form(""),  # noqa: B008
                          allowed_targets: str = Form("")) -> dict[str, object]:
        targets = {host.strip() for host in allowed_targets.split(",") if host.strip()}
        workspace = plan(save_uploads(files), provider, model, targets)
        return {"id": workspace.name, "status": "PLANNED"}

    @app.post("/assignments/run-upload")
    async def run_upload(files: list[UploadFile] = File(...), provider: str = Form("auto"), model: str = Form(""),  # noqa: B008
                         allowed_targets: str = Form("")) -> Any:
        targets = {host.strip() for host in allowed_targets.split(",") if host.strip()}
        workspace = plan(save_uploads(files), provider, model, targets)
        manager.start(workspace, targets)
        return RedirectResponse(f"/assignments/{workspace.name}", status_code=303)

    @app.get("/assignments")
    def assignments() -> list[dict[str, object]]:
        return _assignments(root)

    @app.get("/assignments/{assignment_id}", response_class=HTMLResponse)
    def assignment_page(assignment_id: str) -> str:
        get_workspace(assignment_id)
        return PAGE.replace("__BODY__", _assignment_body(assignment_id))

    @app.get("/assignments/{assignment_id}/status")
    def status(assignment_id: str) -> dict[str, Any]:
        workspace = get_workspace(assignment_id)
        payload = status_payload(workspace)
        payload["running"] = manager.running(workspace)
        return payload

    @app.post("/assignments/{assignment_id}/run")
    def run_existing(assignment_id: str) -> dict[str, object]:
        workspace = get_workspace(assignment_id)
        return {"id": assignment_id, "started": manager.start(workspace)}

    @app.post("/assignments/{assignment_id}/resume")
    def resume_existing(assignment_id: str) -> Any:
        workspace = get_workspace(assignment_id)
        manager.start(workspace)
        return RedirectResponse(f"/assignments/{assignment_id}", status_code=303)

    @app.post("/assignments/{assignment_id}/pause")
    def pause(assignment_id: str) -> dict[str, str]:
        request_control(get_workspace(assignment_id), "PAUSE_REQUESTED")
        return {"status": "PAUSE_REQUESTED"}

    @app.post("/assignments/{assignment_id}/stop")
    def stop(assignment_id: str) -> dict[str, str]:
        workspace = get_workspace(assignment_id)
        request_control(workspace, "STOP_REQUESTED")
        return {"status": "STOPPED" if not manager.running(workspace) else "STOP_REQUESTED"}

    @app.get("/assignments/{assignment_id}/tasks")
    def tasks(assignment_id: str) -> list[dict[str, object]]:
        return [task.model_dump(mode="json") for task in load_state(get_workspace(assignment_id)).plan.steps]

    @app.get("/assignments/{assignment_id}/evidence")
    def evidence(assignment_id: str) -> list[dict[str, object]]:
        return [item.model_dump(mode="json") for item in list_evidence(get_workspace(assignment_id))]

    @app.get("/assignments/{assignment_id}/logs")
    def logs(assignment_id: str) -> list[dict[str, object]]:
        workspace = get_workspace(assignment_id)
        state = load_state(workspace)
        return RunDatabase(workspace).events(state.run_id or state.assignment)

    @app.get("/assignments/{assignment_id}/events/stream")
    async def stream(assignment_id: str, once: bool = False, since: int = 0) -> Any:
        workspace = get_workspace(assignment_id)
        state = load_state(workspace)
        db = RunDatabase(workspace)
        key = state.run_id or state.assignment

        async def generator() -> Any:
            last = since
            idle = 0
            while True:
                batch = db.events(key, 200, since_id=last) if last else list(reversed(db.events(key, 50)))
                for item in batch:
                    last = max(last, int(item["id"]))
                    yield f"id: {item['id']}\ndata: {json.dumps(item, ensure_ascii=False, default=str)}\n\n"
                if once:
                    return
                idle = 0 if batch else idle + 1
                if idle and idle % 15 == 0:
                    yield ": keep-alive\n\n"
                await asyncio.sleep(1)

        return StreamingResponse(generator(), media_type="text/event-stream")

    @app.get("/assignments/{assignment_id}/screenshots")
    def screenshots(assignment_id: str) -> list[str]:
        workspace = get_workspace(assignment_id)
        return [path.relative_to(workspace).as_posix() for path in sorted((workspace / "screenshots").glob("*.png"))]

    @app.get("/assignments/{assignment_id}/files/{relative:path}")
    def file(assignment_id: str, relative: str) -> Any:
        workspace = get_workspace(assignment_id)
        target = (workspace / relative).resolve()
        if not any(target.is_relative_to((workspace / folder).resolve()) for folder in SERVABLE) or not target.is_file():
            raise HTTPException(status_code=404, detail="Not found")
        media = mimetypes.guess_type(target.name)[0] or "application/octet-stream"
        return FileResponse(target, media_type=media)

    @app.post("/assignments/{assignment_id}/tasks/{step_id}/retry")
    def retry_task(assignment_id: str, step_id: int) -> dict[str, object]:
        workspace = get_workspace(assignment_id)
        state = load_state(workspace)
        task = state.step(step_id)
        if task is None:
            raise HTTPException(status_code=404, detail="Unknown task")
        task.status, task.status_reason = TaskStatus.PENDING, "retry requested"
        state.errors = [error for error in state.errors if error.get("step_id") != step_id]
        save_state(workspace, state)
        started = manager.start(workspace)
        return {"id": assignment_id, "step_id": step_id, "started": started}

    @app.post("/assignments/{assignment_id}/tasks/{step_id}/skip")
    def skip_task(assignment_id: str, step_id: int) -> dict[str, object]:
        workspace = get_workspace(assignment_id)
        state = load_state(workspace)
        task = state.step(step_id)
        if task is None:
            raise HTTPException(status_code=404, detail="Unknown task")
        task.status, task.status_reason = TaskStatus.SKIPPED, "skipped by the user (reported as not done)"
        save_state(workspace, state)
        RunDatabase(workspace).event(state.run_id or state.assignment, "task.skipped", {"step_id": step_id})
        return {"id": assignment_id, "step_id": step_id, "status": task.status.value}

    @app.post("/assignments/{assignment_id}/tasks/{step_id}/approve")
    def approve(assignment_id: str, step_id: int) -> dict[str, object]:
        workspace = get_workspace(assignment_id)
        try:
            decide_confirmation(workspace, step_id, True)
        except ValueError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        return {"approved": True, "started": manager.start(workspace)}

    @app.post("/assignments/{assignment_id}/tasks/{step_id}/reject")
    def reject(assignment_id: str, step_id: int) -> dict[str, object]:
        try:
            decide_confirmation(get_workspace(assignment_id), step_id, False)
        except ValueError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        return {"approved": False}

    @app.post("/reports/{assignment_id}/generate")
    def generate(assignment_id: str) -> dict[str, str]:
        return generate_reports(get_workspace(assignment_id))

    @app.get("/reports/{assignment_id}/{kind}")
    def report(assignment_id: str, kind: str) -> Any:
        workspace = get_workspace(assignment_id)
        state = load_state(workspace)
        suffix = ".docx" if kind == "docx" else ".pdf" if kind == "pdf" else ""
        if not suffix:
            raise HTTPException(status_code=404, detail="Unknown report type")
        path = workspace / "reports" / f"{state.assignment}_Report{suffix}"
        if not path.is_file():
            raise HTTPException(status_code=404, detail="Report has not been generated")
        return FileResponse(path, filename=path.name)

    @app.get("/api/capabilities")
    def capabilities() -> list[dict[str, Any]]:
        from .config import get_config
        from .integrations.registry import build_registry

        return [c.to_dict() for c in build_registry(config=options.get("config") or get_config()).capabilities()]

    return app
