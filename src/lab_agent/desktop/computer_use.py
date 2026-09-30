"""Observe -> Reason -> Act -> Verify loop for desktop applications.

Unlike a fixed profile operation, the loop re-observes the UI after every
action and adapts:

* the **observation** is the accessibility tree of the target window (plus the
  list of top-level windows, so unexpected dialogs are noticed);
* a **decider** picks the next action.  :class:`GoalDecider` is deterministic
  (ordered goal steps with alternative selectors and ``done_when``
  conditions); :class:`LLMDecider` asks a configured AI provider to choose
  among *visible, enumerated controls* - it can never invent coordinates or
  controls that are not on screen;
* the loop **verifies** progress through ``done_when`` conditions, detects
  when the UI stops changing (stuck detection), dismisses known pop-ups,
  retries a bounded number of times and gives up with a precise reason.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from typing import Any, ClassVar, Protocol

from .uia import UIDriver, alternatives, element_matches, fingerprint, validate_selector

ALLOWED_ACTIONS = {"click", "double_click", "type", "hotkey", "select", "wait", "done", "give_up"}


@dataclass
class Observation:
    window_title: str
    windows: list[dict[str, Any]]
    elements: list[dict[str, Any]]
    fingerprint: str

    def find(self, selector: dict[str, Any]) -> dict[str, Any] | None:
        for option in alternatives(selector):
            for element in self.elements:
                if element.get("visible", True) and element_matches(element, option):
                    return element
        return None

    def window_visible(self, selector: dict[str, Any]) -> bool:
        return any(element_matches(window, option) for window in self.windows for option in alternatives(selector))

    def summary(self, limit: int = 60) -> list[dict[str, Any]]:
        return [
            {k: e.get(k) for k in ("index", "control_type", "name", "automation_id", "enabled")}
            for e in self.elements if e.get("visible", True)
        ][:limit]


@dataclass
class Decision:
    action: str
    element: dict[str, Any] | None = None
    text: str = ""
    keys: str = ""
    reason: str = ""


@dataclass
class GoalStep:
    name: str
    action: str
    targets: list[dict[str, Any]] = field(default_factory=list)
    text: str = ""
    keys: str = ""
    done_when: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> GoalStep:
        action = str(data["action"])
        if action not in ALLOWED_ACTIONS - {"done", "give_up"}:
            raise ValueError(f"Goal step action {action!r} is not allowed")
        targets = [validate_selector(t) for t in data.get("targets", [])]
        return cls(str(data.get("name", action)), action, targets, str(data.get("text", "")),
                   str(data.get("keys", "")), dict(data.get("done_when", {})))


@dataclass
class Goal:
    description: str
    window: dict[str, Any]
    steps: list[GoalStep]
    dismiss: list[dict[str, Any]] = field(default_factory=list)

    @classmethod
    def from_dict(cls, data: dict[str, Any], dismiss: list[dict[str, Any]] | None = None) -> Goal:
        return cls(str(data.get("description", "")), validate_selector(data["window"]),
                   [GoalStep.from_dict(step) for step in data["steps"]], list(dismiss or data.get("dismiss", [])))


def condition_met(condition: dict[str, Any], observation: Observation) -> bool:
    if not condition:
        return False
    if "control_exists" in condition:
        return observation.find(condition["control_exists"]) is not None
    if "control_enabled" in condition:
        element = observation.find(condition["control_enabled"])
        return element is not None and bool(element.get("enabled", True))
    if "control_absent" in condition:
        return observation.find(condition["control_absent"]) is None
    if "window_exists" in condition:
        return observation.window_visible(condition["window_exists"])
    if "window_absent" in condition:
        return not observation.window_visible(condition["window_absent"])
    if "title_contains" in condition:
        return str(condition["title_contains"]) in observation.window_title
    if "all" in condition:
        return all(condition_met(item, observation) for item in condition["all"])
    raise ValueError(f"Unknown done_when condition {condition}")


class Decider(Protocol):
    def decide(self, goal: Goal, step: GoalStep, observation: Observation, history: list[dict[str, Any]]) -> Decision: ...


class GoalDecider:
    """Deterministic decider: first visible alternative target of the current step."""

    def decide(self, goal: Goal, step: GoalStep, observation: Observation, history: list[dict[str, Any]]) -> Decision:
        if step.action == "hotkey":
            return Decision("hotkey", keys=step.keys, reason=f"{step.name}: send {step.keys}")
        if step.action == "wait":
            return Decision("wait", reason=f"{step.name}: waiting for UI")
        for target in step.targets:
            element = observation.find(target)
            if element is not None and element.get("enabled", True):
                return Decision(step.action, element=element, text=step.text, reason=f"{step.name}: matched {target}")
        return Decision("wait", reason=f"{step.name}: no target visible yet")


class LLMDecider:
    """AI decider constrained to enumerated, visible controls."""

    def __init__(self, provider: Any, fallback: Decider | None = None) -> None:
        self.provider = provider
        self.fallback = fallback or GoalDecider()

    SCHEMA: ClassVar[dict[str, Any]] = {
        "type": "object", "additionalProperties": False,
        "properties": {
            "action": {"type": "string", "enum": sorted(ALLOWED_ACTIONS - {"select"})},
            "element_index": {"type": "integer"},
            "text": {"type": "string"},
            "keys": {"type": "string"},
            "reason": {"type": "string"},
        },
        "required": ["action", "element_index", "text", "keys", "reason"],
    }

    def decide(self, goal: Goal, step: GoalStep, observation: Observation, history: list[dict[str, Any]]) -> Decision:
        prompt = json.dumps({
            "goal": goal.description, "current_step": step.name, "step_action": step.action,
            "step_text": step.text, "window": observation.window_title,
            "visible_controls": observation.summary(), "recent_history": history[-6:],
            "rules": "Choose one visible control by element_index (or -1 for none). Never use coordinates. "
                     "Use give_up when the goal cannot be reached safely.",
        }, ensure_ascii=False)
        try:
            answer = self.provider.complete_json(
                "You operate a desktop application through accessibility controls only.", prompt, self.SCHEMA)
        except Exception:  # noqa: BLE001 - provider failure falls back to deterministic logic
            return self.fallback.decide(goal, step, observation, history)
        action = str(answer.get("action", "wait"))
        if action not in ALLOWED_ACTIONS:
            return Decision("wait", reason=f"AI proposed disallowed action {action!r}")
        index = int(answer.get("element_index", -1))
        element = next((e for e in observation.elements if e.get("index") == index), None)
        if action in {"click", "double_click", "type", "select"} and element is None:
            return Decision("wait", reason=f"AI referenced unknown element {index}")
        if action == "type" and step.text and answer.get("text") != step.text:
            return Decision("wait", reason="AI tried to type text that is not part of the goal")
        return Decision(action, element=element, text=str(answer.get("text", "")), keys=str(answer.get("keys", "")),
                        reason="AI: " + str(answer.get("reason", ""))[:300])


@dataclass
class LoopResult:
    success: bool
    reason: str
    steps_completed: list[str]
    history: list[dict[str, Any]]
    final_title: str = ""


class ComputerUseLoop:
    def __init__(
        self,
        driver: UIDriver,
        decider: Decider | None = None,
        *,
        max_iterations: int = 40,
        max_stuck: int = 4,
        settle_seconds: float = 0.5,
        step_timeout: float = 60.0,
        sleep: Any = time.sleep,
        on_event: Any = None,
    ) -> None:
        self.driver = driver
        self.decider = decider or GoalDecider()
        self.max_iterations = max_iterations
        self.max_stuck = max_stuck
        self.settle_seconds = settle_seconds
        self.step_timeout = step_timeout
        self.sleep = sleep
        self.on_event = on_event

    def observe(self, goal: Goal) -> Observation | None:
        window = self.driver.find_window(goal.window, timeout=2)
        windows = self.driver.list_windows()
        if window is None:
            return Observation("", windows, [], fingerprint([], "<no window>"))
        elements = self.driver.snapshot(window)
        title = self.driver.window_title(window)
        # Top-level dialogs belong to the observation so pop-ups can be handled.
        for dialog_rule in goal.dismiss:
            dialog = self.driver.find_window(dialog_rule["window"], timeout=0)
            if dialog is not None:
                base = len(elements)
                for item in self.driver.snapshot(dialog, max_depth=4, limit=80):
                    elements.append({**item, "index": base + int(item.get("index", 0)), "dialog": True})
        return Observation(title, windows, elements, fingerprint(elements, title))

    def _element_handle(self, goal: Goal, element: dict[str, Any]) -> Any:
        window = self.driver.find_window(goal.window, timeout=2)
        selector = {k: element[k] for k in ("automation_id", "control_type") if element.get(k)}
        if element.get("name"):
            selector["title"] = element["name"]
        if element.get("dialog"):
            for rule in goal.dismiss:
                dialog = self.driver.find_window(rule["window"], timeout=0)
                if dialog is not None:
                    found = self.driver.find_control(dialog, selector, timeout=2)
                    if found is not None:
                        return found
        if window is None:
            raise LookupError("target window disappeared")
        control = self.driver.find_control(window, selector, timeout=3)
        if control is None:
            raise LookupError(f"element {selector} vanished before it could be used")
        return control

    def _act(self, goal: Goal, decision: Decision) -> None:
        if decision.action == "wait":
            self.sleep(self.settle_seconds)
            return
        if decision.action == "hotkey":
            window = self.driver.find_window(goal.window, timeout=2)
            if window is not None:
                self.driver.focus(window)
            self.driver.hotkey(decision.keys)
            return
        if decision.element is None:
            raise LookupError("decision without an element")
        control = self._element_handle(goal, decision.element)
        if decision.action in {"click", "double_click"}:
            self.driver.click(control, double=decision.action == "double_click")
        elif decision.action == "type":
            self.driver.type_text(control, decision.text)
        elif decision.action == "select":
            self.driver.select(control, decision.text)

    def _dismiss(self, goal: Goal, observation: Observation) -> bool:
        for rule in goal.dismiss:
            if observation.window_visible(rule["window"]) or self.driver.find_window(rule["window"], timeout=0) is not None:
                dialog = self.driver.find_window(rule["window"], timeout=0)
                control = self.driver.find_control(dialog, rule["control"], timeout=1) if dialog is not None else None
                if control is not None:
                    self.driver.click(control)
                    return True
        return False

    def run(self, goal: Goal) -> LoopResult:
        history: list[dict[str, Any]] = []
        completed: list[str] = []
        step_index = 0
        stuck = 0
        step_started = time.monotonic()
        last_fp = ""
        for iteration in range(self.max_iterations):
            observation = self.observe(goal)
            if observation is None or (not observation.elements and not observation.window_title):
                history.append({"iteration": iteration, "event": "window_missing"})
                stuck += 1
                if stuck > self.max_stuck:
                    return LoopResult(False, f"target window {goal.window} not available", completed, history)
                self.sleep(self.settle_seconds)
                continue
            if step_index >= len(goal.steps):
                return LoopResult(True, "goal reached", completed, history, observation.window_title)
            step = goal.steps[step_index]
            if step.done_when and condition_met(step.done_when, observation):
                completed.append(step.name)
                history.append({"iteration": iteration, "event": "step_done", "step": step.name})
                step_index += 1
                stuck = 0
                step_started = time.monotonic()
                continue
            if self._dismiss(goal, observation):
                history.append({"iteration": iteration, "event": "dismissed_popup"})
                self.sleep(self.settle_seconds)
                continue
            if time.monotonic() - step_started > self.step_timeout:
                return LoopResult(False, f"step '{step.name}' timed out after {self.step_timeout}s", completed, history,
                                  observation.window_title)
            decision = self.decider.decide(goal, step, observation, history)
            record = {"iteration": iteration, "step": step.name, "action": decision.action, "reason": decision.reason,
                      "element": {k: (decision.element or {}).get(k) for k in ("name", "automation_id", "control_type")}}
            if self.on_event:
                self.on_event("computer_use.action", record)
            if decision.action == "give_up":
                history.append(record)
                return LoopResult(False, decision.reason or "decider gave up", completed, history, observation.window_title)
            if decision.action == "done":
                history.append(record)
                if step.done_when and not condition_met(step.done_when, self.observe(goal) or observation):
                    return LoopResult(False, f"decider claimed '{step.name}' done but its condition is not met",
                                      completed, history, observation.window_title)
                completed.append(step.name)
                step_index += 1
                continue
            try:
                self._act(goal, decision)
                record["result"] = "ok"
            except Exception as exc:  # noqa: BLE001 - UI races are retried by the loop
                record["result"] = f"error: {exc}"
            history.append(record)
            self.sleep(self.settle_seconds)
            after = self.observe(goal)
            changed = after is not None and after.fingerprint != observation.fingerprint
            if not step.done_when and decision.action != "wait" and record["result"] == "ok":
                completed.append(step.name)
                step_index += 1
                stuck = 0
                step_started = time.monotonic()
                continue
            stuck = 0 if changed else stuck + 1
            if stuck > self.max_stuck and last_fp == (after.fingerprint if after else ""):
                return LoopResult(False, f"UI did not change after {stuck} attempts at step '{step.name}'",
                                  completed, history, observation.window_title)
            last_fp = after.fingerprint if after else ""
        return LoopResult(False, f"iteration budget ({self.max_iterations}) exhausted", completed, history)
