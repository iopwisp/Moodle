from __future__ import annotations

from pathlib import Path

import pytest
from fakes import FakeControl, FakeDriver, FakeWindow, fake_screenshot

from lab_agent.desktop.computer_use import ComputerUseLoop, Goal, LLMDecider
from lab_agent.desktop.engine import ProfileEngine, render
from lab_agent.desktop.profiles import load_profile, select_version
from lab_agent.desktop.uia import ElementNotFound, validate_selector
from lab_agent.integrations.base import ExecutionContext
from lab_agent.llm import ScriptedProvider


def _wizard(driver: FakeDriver) -> FakeWindow:
    """A fake 'New Case' wizard: Next enables Finish only after a name is typed."""
    name = FakeControl("Case Name", "Edit", automation_id="caseName")
    finish = FakeControl("Finish", "Button", enabled=False)
    window = FakeWindow("New Case Information")

    def typed(text: str) -> None:
        name.text = text
        finish.enabled = bool(text)

    def finished() -> None:
        window.closed = True
        main.controls.append(FakeControl(f"Case {name.text}", "Text"))

    name.on_type = typed
    finish.on_click = finished
    window.controls = [name, FakeControl("Cancel"), finish]
    main = driver.add_window(FakeWindow("Autopsy 4.21.0", [FakeControl("New Case", "Button", on_click=lambda: driver.add_window(window))]))
    return main


def test_selectors_reject_coordinates() -> None:
    with pytest.raises(ValueError):
        validate_selector({"x": 10, "y": 20})
    assert validate_selector({"any": [{"title": "OK"}, {"automation_id": "ok"}]})


def test_profile_engine_runs_operations_and_reads_values() -> None:
    driver = FakeDriver()
    _wizard(driver)
    profile = {"name": "autopsy", "window": {"title_re": "^Autopsy"}, "operations": {"create_case": [
        {"type": "click", "control": {"title": "New Case", "control_type": "Button"}},
        {"type": "wait_until", "window": {"title": "New Case Information"}},
        {"type": "type", "window": {"title": "New Case Information"}, "control": {"automation_id": "caseName"}, "text": "{case}"},
        {"type": "click", "window": {"title": "New Case Information"}, "control": {"title": "Finish"}},
        {"type": "read_text", "control": {"title_re": "^Case "}, "into": "created"},
    ]}}
    engine = ProfileEngine(driver, profile, sleep=lambda s: None)
    result = engine.run("create_case", {"case": "lab3"})
    assert result.values["created"] == "Case lab3"
    with pytest.raises(KeyError):
        render("{missing}", {})
    with pytest.raises(ValueError):
        engine.run("unknown", {})


def test_profile_engine_fails_when_control_missing() -> None:
    driver = FakeDriver()
    driver.add_window(FakeWindow("Autopsy 4.21.0"))
    engine = ProfileEngine(driver, {"name": "a", "window": {"title_re": "Autopsy"},
                                    "operations": {"op": [{"type": "click", "control": {"title": "Nope"}, "timeout": 0}]}},
                           sleep=lambda s: None)
    with pytest.raises(ElementNotFound):
        engine.run("op", {})


def test_computer_use_adapts_dismisses_popups_and_verifies() -> None:
    driver = FakeDriver()
    main = _wizard(driver)
    popup = FakeWindow("Update available", [FakeControl("Later", on_click=lambda: setattr(popup, "closed", True))])
    driver.add_window(popup)
    goal = Goal.from_dict({
        "description": "create a case",
        "window": {"title_re": "Autopsy|New Case"},
        "steps": [
            {"name": "open wizard", "action": "click", "targets": [{"title": "Create New Case"}, {"title": "New Case"}],
             "done_when": {"window_exists": {"title": "New Case Information"}}},
            {"name": "name", "action": "type", "text": "lab3", "targets": [{"automation_id": "caseName"}],
             "done_when": {"control_enabled": {"title": "Finish"}}},
            {"name": "finish", "action": "click", "targets": [{"title": "Finish"}],
             "done_when": {"window_absent": {"title": "New Case Information"}}},
        ],
    }, dismiss=[{"window": {"title": "Update available"}, "control": {"title": "Later"}}])
    goal.window = {"any": [{"title": "New Case Information"}, {"title_re": "^Autopsy"}]}
    result = ComputerUseLoop(driver, sleep=lambda s: None).run(goal)
    assert result.success, result.reason
    assert popup.closed
    assert any(c.name == "Case lab3" for c in main.controls)


def test_computer_use_detects_stuck_ui() -> None:
    driver = FakeDriver()
    driver.add_window(FakeWindow("App", [FakeControl("Go")]))  # clicking changes nothing
    goal = Goal.from_dict({"window": {"title": "App"}, "steps": [
        {"name": "go", "action": "click", "targets": [{"title": "Go"}], "done_when": {"control_exists": {"title": "Done"}}}]})
    result = ComputerUseLoop(driver, sleep=lambda s: None, max_stuck=2, max_iterations=20).run(goal)
    assert not result.success
    assert "did not change" in result.reason or "budget" in result.reason


def test_llm_decider_cannot_invent_controls() -> None:
    driver = FakeDriver()
    driver.add_window(FakeWindow("App", [FakeControl("Go")]))
    goal = Goal.from_dict({"window": {"title": "App"}, "steps": [
        {"name": "go", "action": "click", "targets": [{"title": "Go"}], "done_when": {"control_exists": {"title": "Done"}}}]})
    provider = ScriptedProvider(lambda s, u, schema: {"action": "click", "element_index": 99, "text": "", "keys": "",
                                                      "reason": "made up"})
    decider = LLMDecider(provider)
    observation = ComputerUseLoop(driver, decider, sleep=lambda s: None).observe(goal)
    decision = decider.decide(goal, goal.steps[0], observation, [])
    assert decision.action == "wait" and "unknown element" in decision.reason


def test_versioned_profiles(tmp_path: Path, monkeypatch) -> None:
    (tmp_path / "demo.yaml").write_text(
        "name: demo\nwindow: {title_re: Demo}\noperations: {launch: []}\n"
        "versions:\n  '4': {operations: {launch: [{type: wait, seconds: 1}]}}\n  '4.21': {window: {title_re: 'Demo 4.21'}}\n",
        encoding="utf-8")
    monkeypatch.setenv("LAB_AGENT_PROFILES_DIR", str(tmp_path))
    assert load_profile("demo", "4.21.0")["window"]["title_re"] == "Demo 4.21"
    assert load_profile("demo", "4.10")["operations"]["launch"] == [{"type": "wait", "seconds": 1}]
    assert load_profile("demo", "5.0")["profile_version"] == "base"
    assert select_version(["1.0", "2.0"], "2.0.1") == "2.0"
    assert load_profile("packet_tracer", "8.2.2")["window"]


def test_desktop_profile_capability(tmp_path: Path, registry, monkeypatch) -> None:
    driver = FakeDriver()
    _wizard(driver)
    monkeypatch.setattr("lab_agent.applications.default_driver", lambda: driver)
    context = ExecutionContext(tmp_path, "A", step_id=1, screenshot_fn=fake_screenshot)
    result = registry.execute("desktop.observe", {"profile": "autopsy"}, context)
    assert result.verified and result.details["elements"] == 1
    closed = registry.execute("desktop.close", {"profile": "autopsy"}, context)
    assert closed.verified


def test_hotkey_chords_are_layout_independent() -> None:
    from lab_agent.desktop.uia import parse_chord

    assert parse_chord("^s") == ([0x11], ord("S"))
    assert parse_chord("^+r") == ([0x11, 0x10], ord("R"))
    assert parse_chord("{ENTER}") is None and parse_chord("^/") is None


def test_lifecycle_dismisses_declared_popups(tmp_path: Path, monkeypatch) -> None:
    from lab_agent.applications import ManagedApplication

    driver = FakeDriver()
    driver.add_window(FakeWindow("lab.pcap", class_name="WiresharkMainWindow"))
    update = FakeWindow("Software Update", class_name="#32770")
    update.controls = [FakeControl("Remind me later", on_click=lambda: setattr(update, "closed", True))]
    driver.add_window(update)
    monkeypatch.setattr(ExecutionContext, "sleep", lambda self, seconds: None)
    app = ManagedApplication("wireshark", ExecutionContext(tmp_path, "a"), driver_factory=lambda: driver)
    assert app.wait_ready(timeout=2) is not None and update.closed
