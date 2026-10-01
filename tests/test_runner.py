from __future__ import annotations

from pathlib import Path
from typing import Any

from conftest import EMPTY_ENVIRONMENT
from fakes import fake_screenshot

from lab_agent.database import RunDatabase
from lab_agent.integrations.base import (
    BaseIntegration,
    Capability,
    ExecutionContext,
    IntegrationResult,
    Param,
    evidence,
)
from lab_agent.integrations.registry import build_registry
from lab_agent.llm import ScriptedProvider
from lab_agent.models import AssignmentAnalysis, ExecutionPlan, PlannedTask, RunStatus, TaskStatus
from lab_agent.runner import Runner, decide_confirmation, execute_workspace, request_control
from lab_agent.workspace import create_workspace, load_state, save_state


class LabDevice(BaseIntegration):
    """Scripted integration: behaviour controlled by parameters, results written as real files."""

    name = "lab"
    CAPABILITIES = (
        Capability("lab.write", "lab", "write a result file", (Param("text", "str", True), Param("name", "str")), ("file",)),
        Capability("lab.flaky", "lab", "fails until the recover hook ran", (), ("file",)),
        Capability("lab.claims", "lab", "claims success without producing its file", (), ("file",)),
        Capability("lab.ping", "lab", "succeeds only with the right peer", (Param("peer", "str", True),), ("file",)),
        Capability("lab.dangerous", "lab", "needs approval", (), ("file",), risk="unsafe"),
        Capability("lab.slow", "lab", "requests pause while running", (), ("file",)),
    )

    def __init__(self) -> None:
        self.recovered = False
        self.calls: list[str] = []

    def write(self, parameters: dict[str, Any], context: ExecutionContext) -> IntegrationResult:
        self.calls.append("write")
        path = context.save_result(parameters.get("name") or f"out_{context.step_id}.txt", parameters["text"])
        return IntegrationResult(True, {"chars": len(parameters["text"])}, [evidence(path, "written", "file")],
                                 checks=[{"type": "text_contains", "path": f"results/{path.name}", "value": parameters["text"]}])

    def flaky(self, parameters: dict[str, Any], context: ExecutionContext) -> IntegrationResult:
        self.calls.append("flaky")
        if not self.recovered:
            raise TimeoutError("application did not answer")
        path = context.save_result("flaky.txt", "ok")
        return IntegrationResult(True, {}, [evidence(path, "flaky", "file")])

    def recover(self, capability: str, parameters: dict[str, Any], context: ExecutionContext, kind: str) -> str:
        self.recovered = True
        return f"restarted application after {kind}"

    def claims(self, parameters: dict[str, Any], context: ExecutionContext) -> IntegrationResult:
        return IntegrationResult(True, {}, [], checks=[{"type": "file_exists", "path": "results/never.txt"}])

    def ping(self, parameters: dict[str, Any], context: ExecutionContext) -> IntegrationResult:
        ok = parameters["peer"] == "10.0.0.2"
        path = context.save_result("ping.txt", f"Received = {4 if ok else 0}")
        return IntegrationResult(ok, {"received": 4 if ok else 0, **({} if ok else {"reason": "0 replies"})},
                                 [evidence(path, "ping", "file")])

    def dangerous(self, parameters: dict[str, Any], context: ExecutionContext) -> IntegrationResult:
        path = context.save_result("dangerous.txt", "done")
        return IntegrationResult(True, {}, [evidence(path, "dangerous", "file")])

    def slow(self, parameters: dict[str, Any], context: ExecutionContext) -> IntegrationResult:
        request_control(context.workspace, "PAUSE_REQUESTED")
        path = context.save_result("slow.txt", "done")
        return IntegrationResult(True, {}, [evidence(path, "slow", "file")])


def _setup(tmp_path: Path, config, steps: list[PlannedTask]) -> tuple[Path, Any, LabDevice]:
    source = tmp_path / "lab.txt"
    source.write_text("1. do things\n", encoding="utf-8")
    analysis = AssignmentAnalysis(assignment="lab", source_files=[str(source)], objective="do things", tools=[], requirements=[],
                                  screenshot_requirements=[], expected_outputs=[], limitations=[], extracted_text_files={})
    workspace = create_workspace(analysis, ExecutionPlan(assignment="lab", objective="x", steps=steps, source_files=[str(source)]),
                                 tmp_path / "ws")
    registry = build_registry(fake_screenshot, config)
    device = LabDevice()
    registry.register(device)
    return workspace, registry, device


def _run(workspace: Path, registry, config, **kwargs):
    return execute_workspace(workspace, config=config, registry=registry, screenshot_fn=fake_screenshot,
                             environment=EMPTY_ENVIRONMENT, generate_report=False, **kwargs)


def test_dag_blocks_dependents_and_run_after_still_runs(tmp_path: Path, config) -> None:
    steps = [PlannedTask(id=1, title="fails", description="", action="lab.ping", parameters={"peer": "10.9.9.9"}),
             PlannedTask(id=2, title="needs 1", description="", action="lab.write", parameters={"text": "a"}, depends_on=[1]),
             PlannedTask(id=3, title="after all", description="", action="lab.write", parameters={"text": "b", "name": "b.txt"},
                         run_after=[1, 2])]
    workspace, registry, _ = _setup(tmp_path, config, steps)
    state = _run(workspace, registry, config)
    assert [t.status for t in state.plan.steps] == [TaskStatus.FAILED, TaskStatus.BLOCKED, TaskStatus.COMPLETED]
    assert "dependency step 1" in state.plan.steps[1].status_reason
    assert state.status == RunStatus.FAILED
    events = [e["event_type"] for e in RunDatabase(workspace).events(state.run_id)]
    for name in ("agent.started", "task.started", "capability.started", "verification.started", "verification.failed",
                 "verification.passed", "evidence.created", "task.completed", "task.failed", "task.blocked"):
        assert name in events, name
    log = (workspace / "logs" / "execution.jsonl").read_text(encoding="utf-8")
    assert '"capability": "lab.ping"' in log and '"duration_seconds"' in log


def test_claimed_success_without_proof_is_never_completed(tmp_path: Path, config) -> None:
    workspace, registry, _ = _setup(tmp_path, config, [PlannedTask(id=1, title="claims", description="", action="lab.claims")])
    state = _run(workspace, registry, config)
    task = state.plan.steps[0]
    assert task.status == TaskStatus.FAILED
    assert any(not r["passed"] for r in task.verification_results)


def test_required_evidence_type_is_enforced(tmp_path: Path, config) -> None:
    step = PlannedTask(id=1, title="x", description="", action="lab.write", parameters={"text": "x"},
                       evidence_required=True, evidence_type_required="screenshot")
    workspace, registry, _ = _setup(tmp_path, config, [step])
    state = _run(workspace, registry, config)
    assert state.plan.steps[0].status == TaskStatus.FAILED
    assert "required screenshot" in state.plan.steps[0].status_reason


def test_screenshot_required_step_captures_and_binds_screenshot(tmp_path: Path, config) -> None:
    step = PlannedTask(id=1, title="configure", description="", action="lab.write", parameters={"text": "x"},
                       screenshot_required=True, requirement_refs=["Attach screenshot of step 1"])
    workspace, registry, _ = _setup(tmp_path, config, [step])
    state = _run(workspace, registry, config)
    assert state.plan.steps[0].status == TaskStatus.COMPLETED
    from lab_agent.evidence import list_evidence

    shots = [e for e in list_evidence(workspace) if e.type == "screenshot"]
    assert shots and shots[0].step_id == 1 and shots[0].requirement_refs == ["Attach screenshot of step 1"]


def test_recovery_hook_and_retry(tmp_path: Path, config) -> None:
    workspace, registry, device = _setup(tmp_path, config, [PlannedTask(id=1, title="flaky", description="", action="lab.flaky")])
    state = _run(workspace, registry, config)
    assert state.plan.steps[0].status == TaskStatus.COMPLETED
    assert device.calls == ["flaky", "flaky"] and len(state.plan.steps[0].attempts) == 2
    assert state.recoveries and "restarted application" in state.recoveries[0]["notes"][0]


def test_ai_self_correction_changes_parameters(tmp_path: Path, config) -> None:
    config.execution.max_attempts = 3
    workspace, registry, _ = _setup(tmp_path, config, [PlannedTask(id=1, title="ping", description="", action="lab.ping",
                                                                  parameters={"peer": "10.0.0.9"})])
    advisor = ScriptedProvider([{"decision": "replace_parameters", "reason": "wrong interface IP; peer is 10.0.0.2",
                                 "parameters": [{"name": "peer", "value": "10.0.0.2"}], "step_action": "lab.ping"}])
    state = _run(workspace, registry, config, advisor=advisor)
    task = state.plan.steps[0]
    assert task.status == TaskStatus.COMPLETED and task.parameters["peer"] == "10.0.0.2"
    assert state.recoveries[0]["parameters"] == {"peer": "10.0.0.2"}


def test_ai_advice_with_unknown_parameters_is_rejected(tmp_path: Path, config) -> None:
    config.execution.max_attempts = 3
    workspace, registry, _ = _setup(tmp_path, config, [PlannedTask(id=1, title="ping", description="", action="lab.ping",
                                                                  parameters={"peer": "10.0.0.9"})])
    advisor = ScriptedProvider([{"decision": "replace_parameters", "reason": "try shell",
                                 "parameters": [{"name": "shell", "value": "rm -rf /"}], "step_action": "lab.ping"}])
    state = _run(workspace, registry, config, advisor=advisor)
    assert state.plan.steps[0].status in {TaskStatus.FAILED, TaskStatus.BLOCKED}
    assert state.plan.steps[0].parameters == {"peer": "10.0.0.9"}


def test_human_confirmation_flow(tmp_path: Path, config) -> None:
    workspace, registry, _ = _setup(tmp_path, config, [PlannedTask(id=1, title="danger", description="", action="lab.dangerous")])
    state = _run(workspace, registry, config)
    assert state.status == RunStatus.WAITING_CONFIRMATION and state.plan.steps[0].status == TaskStatus.BLOCKED
    assert not (workspace / "results" / "dangerous.txt").exists()
    decide_confirmation(workspace, 1, approve=True)
    state = _run(workspace, registry, config)
    assert state.plan.steps[0].status == TaskStatus.COMPLETED and state.status == RunStatus.COMPLETED


def test_rejected_confirmation_never_runs(tmp_path: Path, config) -> None:
    workspace, registry, _ = _setup(tmp_path, config, [PlannedTask(id=1, title="danger", description="", action="lab.dangerous")])
    _run(workspace, registry, config)
    decide_confirmation(workspace, 1, approve=False, note="not in this lab")
    state = _run(workspace, registry, config)
    assert state.plan.steps[0].status == TaskStatus.BLOCKED and not (workspace / "results" / "dangerous.txt").exists()


def test_policy_denies_disabled_tool(tmp_path: Path, config) -> None:
    from lab_agent.config import ToolPolicy

    config.policy.tools["lab"] = ToolPolicy(allowed=False)
    workspace, registry, _ = _setup(tmp_path, config, [PlannedTask(id=1, title="w", description="", action="lab.write",
                                                                  parameters={"text": "x"})])
    state = _run(workspace, registry, config)
    assert state.plan.steps[0].status == TaskStatus.BLOCKED and "disabled by policy" in state.plan.steps[0].status_reason


def test_pause_and_resume(tmp_path: Path, config) -> None:
    steps = [PlannedTask(id=1, title="slow", description="", action="lab.slow"),
             PlannedTask(id=2, title="next", description="", action="lab.write", parameters={"text": "n"})]
    workspace, registry, _ = _setup(tmp_path, config, steps)
    state = _run(workspace, registry, config)
    assert state.status == RunStatus.PAUSED
    assert [t.status for t in state.plan.steps] == [TaskStatus.COMPLETED, TaskStatus.PENDING]
    state = _run(workspace, registry, config)
    assert state.status == RunStatus.COMPLETED


def test_stop_request_before_start(tmp_path: Path, config) -> None:
    workspace, registry, _ = _setup(tmp_path, config, [PlannedTask(id=1, title="w", description="", action="lab.write",
                                                                  parameters={"text": "x"})])
    runner = Runner(workspace, config=config, registry=registry, screenshot_fn=fake_screenshot, environment=EMPTY_ENVIRONMENT)
    runner.prepare()
    request_control(workspace, "STOP_REQUESTED")
    state = load_state(workspace)
    assert state.status == RunStatus.STOPPED and state.plan.steps[0].status == TaskStatus.PENDING


def test_resume_reconciles_interrupted_step_and_detects_tampering(tmp_path: Path, config) -> None:
    steps = [PlannedTask(id=1, title="a", description="", action="lab.write", parameters={"text": "alpha", "name": "a.txt"}),
             PlannedTask(id=2, title="b", description="", action="lab.write", parameters={"text": "beta", "name": "b.txt"},
                         verification_checks=[{"type": "text_contains", "path": "results/b.txt", "value": "beta"}])]
    workspace, registry, device = _setup(tmp_path, config, steps)
    _run(workspace, registry, config)
    # simulate: crash while step 2 was running (result already on disk) and step 1 evidence was altered
    state = load_state(workspace)
    state.plan.steps[1].status = TaskStatus.RUNNING
    save_state(workspace, state)
    (workspace / "results" / "a.txt").write_text("tampered", encoding="utf-8")
    device.calls.clear()
    state = _run(workspace, registry, config)
    assert state.plan.steps[1].status == TaskStatus.COMPLETED and "verified on resume" in state.plan.steps[1].status_reason
    assert device.calls == ["write"]  # only the tampered step 1 was executed again
    assert (workspace / "results" / "a.txt").read_text(encoding="utf-8") == "alpha"
    assert state.status == RunStatus.COMPLETED


def test_step_completed_on_resume_reruns_steps_that_summarised_it(tmp_path: Path, config) -> None:
    steps = [PlannedTask(id=1, title="tool", description="", action="lab.ping", parameters={"peer": "10.9.9.9"}, required=False),
             PlannedTask(id=2, title="summary", description="", action="lab.write", parameters={"text": "s", "name": "s.txt"},
                         run_after=[1]),
             PlannedTask(id=3, title="student", description="", action="lab.write", parameters={"text": "m", "name": "m.txt"},
                         run_after=[1])]
    workspace, registry, device = _setup(tmp_path, config, steps)
    state = _run(workspace, registry, config)
    assert [t.status for t in state.plan.steps] == [TaskStatus.FAILED, TaskStatus.COMPLETED, TaskStatus.COMPLETED]
    # the tool becomes usable (e.g. installed) and the student confirmed step 3 by hand in the meantime
    state.plan.steps[0].parameters["peer"] = "10.0.0.2"
    state.plan.steps[2].status_reason = "manually verified: written by the student"
    save_state(workspace, state)
    device.calls.clear()
    state = _run(workspace, registry, config)
    assert [t.status for t in state.plan.steps] == [TaskStatus.COMPLETED] * 3
    assert device.calls == ["write"]  # the summary ran again, the student's step did not
    assert state.plan.steps[2].status_reason.startswith("manually verified")
    events = [e["event_type"] for e in RunDatabase(workspace).events(state.run_id)]
    assert "task.invalidated" in events


def test_unknown_capability_fails(tmp_path: Path, config) -> None:
    workspace, registry, _ = _setup(tmp_path, config, [PlannedTask(id=1, title="x", description="", action="nope.nothing")])
    state = _run(workspace, registry, config)
    assert state.plan.steps[0].status == TaskStatus.FAILED


def test_unauthorized_network_target_is_blocked_by_policy(tmp_path: Path, config) -> None:
    class Net(BaseIntegration):
        name = "net"
        CAPABILITIES = (Capability("net.get", "net", "fetch", (Param("url", "url", True),), ("file",), network=True),)

        def get(self, parameters: dict[str, Any], context: ExecutionContext) -> IntegrationResult:
            raise AssertionError("must never execute")

    workspace, registry, _ = _setup(tmp_path, config, [PlannedTask(id=1, title="x", description="", action="net.get",
                                                                  parameters={"url": "https://example.com/admin"})])
    registry.register(Net())
    state = _run(workspace, registry, config)
    assert state.plan.steps[0].status == TaskStatus.BLOCKED
    assert "not authorized" in state.plan.steps[0].status_reason
