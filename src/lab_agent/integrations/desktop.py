"""Generic desktop integration: any application described by a YAML profile.

* ``desktop.profile`` - run a declared profile operation (legacy name kept);
* ``desktop.launch`` / ``desktop.close`` - application lifecycle;
* ``desktop.observe`` - accessibility tree + window screenshot of the app;
* ``desktop.computer_use`` - observe -> reason -> act -> verify loop towards a
  goal declared in the profile (``goals:``), with the AI decider when an AI
  provider is configured and the deterministic decider otherwise;
* ``desktop.capture_window`` - window-targeted screenshot.
"""

from __future__ import annotations

from typing import Any

from .base import (
    BaseIntegration,
    Capability,
    ExecutionContext,
    IntegrationResult,
    Param,
    evidence,
    param_dict,
    param_str,
)

PROFILE = Param("profile", "str", True, "profile name in profiles/, e.g. autopsy, burp, ftk")


class DesktopAdapter(BaseIntegration):
    name = "desktop"
    INTERACTIVE = frozenset({"desktop.profile", "desktop.computer_use"})
    CAPABILITIES = (
        Capability("desktop.profile", "desktop", "Run a declared Windows UI Automation operation from an application profile",
                   (PROFILE, Param("operation", "str", False, "operation name in the profile (default launch)"),
                    Param("variables", "dict", False, "template variables for the operation")),
                   ("screenshot",), "operation completed, profile verification checks pass, window captured"),
        Capability("desktop.launch", "desktop", "Start (or attach to) a profiled application and wait for its window",
                   (PROFILE,), ("screenshot",), "main window visible"),
        Capability("desktop.observe", "desktop", "Record the application's accessibility tree and a window screenshot",
                   (PROFILE,), ("json", "screenshot"), "tree captured"),
        Capability("desktop.computer_use", "desktop", "Reach a profile goal with the observe-reason-act-verify loop",
                   (PROFILE, Param("goal", "str", True, "goal name from the profile's goals section"),
                    Param("variables", "dict")), ("json", "screenshot"), "every goal step's done_when condition observed"),
        Capability("desktop.capture_window", "desktop", "Screenshot of the profiled application's window", (PROFILE,),
                   ("screenshot",), "valid window screenshot"),
        Capability("desktop.close", "desktop", "Close the profiled application window", (PROFILE,), (), "window gone"),
    )

    def __init__(self, provider_factory: Any = None) -> None:
        self.provider_factory = provider_factory

    def _app(self, parameters: dict[str, Any], context: ExecutionContext) -> Any:
        from ..applications import ManagedApplication

        return ManagedApplication(param_str(parameters, "profile"), context)

    def profile(self, parameters: dict[str, Any], context: ExecutionContext) -> IntegrationResult:
        app = self._app(parameters, context)
        operation = param_str(parameters, "operation", "launch") or "launch"
        if not app.has_operation(operation) and operation != "launch":
            available = ", ".join(sorted(app.profile.get("operations", {}))) or "none"
            raise ValueError(f"Operation {operation!r} is not in the {app.name} profile. Available operations: {available}.")
        app.launch()
        result = app.run_operation(operation, param_dict(parameters, "variables")) if app.has_operation(operation) else None
        picture = app.screenshot(f"{app.name}_{operation}_{context.stamp()}.png")
        checks = [dict(check) for check in (app.profile.get("verification") or {}).get(operation, [])]
        checks.append({"type": "image_valid", "path": str(picture)})
        details = {"profile": app.name, "operation": operation, "profile_version": app.profile.get("profile_version"),
                   **(result.to_dict() if result else {})}
        return IntegrationResult(True, details, [evidence(picture, f"{app.name} {operation}", "screenshot")], checks=checks)

    def launch(self, parameters: dict[str, Any], context: ExecutionContext) -> IntegrationResult:
        return self.profile({**parameters, "operation": "launch"}, context)

    def observe(self, parameters: dict[str, Any], context: ExecutionContext) -> IntegrationResult:
        app = self._app(parameters, context)
        window = app.running_window()
        if window is None:
            return IntegrationResult.failed(f"{app.name} window is not open")
        tree = app.driver.snapshot(window)
        output = context.save_result(f"{app.name}_ui_tree_{context.stamp()}.json", {"title": app.driver.window_title(window),
                                                                                    "elements": tree})
        picture = app.screenshot(f"{app.name}_observe_{context.stamp()}.png")
        return IntegrationResult(bool(tree), {"elements": len(tree)},
                                 [evidence(output, f"{app.name} accessibility tree", "json"),
                                  evidence(picture, f"{app.name} window", "screenshot")])

    def computer_use(self, parameters: dict[str, Any], context: ExecutionContext) -> IntegrationResult:
        from ..desktop.computer_use import ComputerUseLoop, Goal, GoalDecider, LLMDecider
        from ..desktop.engine import render_tree

        app = self._app(parameters, context)
        goal_name = param_str(parameters, "goal")
        goals = app.profile.get("goals") or {}
        if goal_name not in goals:
            raise ValueError(f"Goal {goal_name!r} is not declared in the {app.name} profile ({sorted(goals)})")
        variables = {"assignment": context.assignment, **param_dict(parameters, "variables")}
        raw = render_tree(goals[goal_name], variables)
        raw.setdefault("window", app.window_selector)
        goal = Goal.from_dict(raw, dismiss=app.profile.get("dismiss"))
        app.launch()
        decider: Any = GoalDecider()
        if self.provider_factory is not None:
            provider = self.provider_factory()
            if provider is not None:
                decider = LLMDecider(provider)
        loop = ComputerUseLoop(app.driver, decider, sleep=context.sleep, on_event=context.log,
                               max_iterations=int(goals[goal_name].get("max_iterations", 40)))
        outcome = loop.run(goal)
        log = context.save_result(f"{app.name}_{goal_name}_computer_use.json",
                                  {"success": outcome.success, "reason": outcome.reason, "steps": outcome.steps_completed,
                                   "history": outcome.history})
        items = [evidence(log, f"Computer-use trace for {goal_name}", "json")]
        try:
            items.append(evidence(app.screenshot(f"{app.name}_{goal_name}_{context.stamp()}.png"), f"{app.name} after {goal_name}",
                                  "screenshot"))
        except Exception:  # noqa: BLE001, S110
            pass
        return IntegrationResult(outcome.success, {"goal": goal_name, "reason": outcome.reason, "steps": outcome.steps_completed},
                                 items)

    def capture_window(self, parameters: dict[str, Any], context: ExecutionContext) -> IntegrationResult:
        app = self._app(parameters, context)
        if app.running_window() is None:
            return IntegrationResult.failed(f"{app.name} window is not open")
        picture = app.screenshot(f"{app.name}_{context.stamp()}.png")
        return IntegrationResult(True, {}, [evidence(picture, f"{app.name} window", "screenshot")],
                                 checks=[{"type": "image_valid", "path": str(picture)}])

    def close(self, parameters: dict[str, Any], context: ExecutionContext) -> IntegrationResult:
        app = self._app(parameters, context)
        app.close()
        gone = app.driver.find_window(app.window_selector, timeout=5) is None
        return IntegrationResult(gone, {"closed": gone, **({} if gone else {"reason": "window still open"})})


def create_adapters(services: Any) -> list[DesktopAdapter]:
    def provider_factory() -> Any:
        from ..ai import provider_from_config

        return provider_from_config(services.config, purpose="computer_use")

    return [DesktopAdapter(provider_factory)]
