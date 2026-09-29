"""Concrete desktop and browser adapters used by the constrained workflow runner."""

from __future__ import annotations

import json
import os
import re
import subprocess
import time
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from .tools.process import launch_application
from .tools.screenshot import take_screenshot

ROOT = Path(__file__).resolve().parents[2]


def _profile(name: str) -> dict[str, Any]:
    if name not in {"autopsy", "burp"}:
        raise ValueError("Desktop profile must be autopsy or burp.")
    try:
        import yaml
    except ImportError as exc:
        raise RuntimeError("Desktop automation requires the gui extra: pip install -e .[gui]") from exc
    path = ROOT / "profiles" / f"{name}.yaml"
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def _application_path(profile: dict[str, Any]) -> str:
    configured = os.environ.get(profile["executable_env"], "")
    if not configured:
        raise RuntimeError(f"Set {profile['executable_env']} to the installed application executable.")
    if not Path(configured).is_file():
        raise FileNotFoundError(configured)
    return configured


def desktop_operation(
    workspace: Path, profile_name: str, operation: str, assignment: str
) -> dict[str, Any]:
    """Launch a configured app and execute its versioned UIA/keyboard profile operation."""
    profile = _profile(profile_name)
    operations = profile.get("operations", {})
    if operation not in operations:
        raise ValueError(f"Operation {operation!r} is not in the {profile_name} profile.")
    executable = _application_path(profile)
    process = launch_application(executable, cwd=workspace)
    time.sleep(float(profile.get("launch_wait_seconds", 3)))
    try:
        from pywinauto import Desktop, keyboard
    except ImportError as exc:
        raise RuntimeError("Desktop automation requires pywinauto in the gui extra.") from exc
    window = Desktop(backend="uia").window(title_re=profile["window_title_re"])
    window.wait("visible", timeout=int(profile.get("window_timeout_seconds", 20)))
    actions_done: list[str] = []
    for action in operations[operation]:
        kind = action["type"]
        if kind == "hotkey":
            keyboard.send_keys(action["keys"].format(assignment=assignment))
        elif kind == "click":
            control = window.child_window(
                **{key: value.format(assignment=assignment) for key, value in action["selector"].items()}
            )
            control.wait("enabled", timeout=10)
            control.click_input()
        elif kind == "type":
            control = window.child_window(
                **{key: value.format(assignment=assignment) for key, value in action["selector"].items()}
            )
            control.wait("enabled", timeout=10)
            control.set_edit_text(action["text"].format(assignment=assignment))
        elif kind == "wait":
            time.sleep(float(action.get("seconds", 1)))
        else:
            raise ValueError(f"Unsupported profile action: {kind}")
        actions_done.append(kind)
    screenshot = take_screenshot(
        workspace, name=f"{profile_name}_{operation}_{int(time.time())}.png"
    )
    return {
        "pid": process.pid,
        "profile": profile_name,
        "operation": operation,
        "actions": actions_done,
        "screenshot": str(screenshot),
        "verified": True,
    }


def _find_data_source(workspace: Path) -> Path:
    candidates = sorted(
        p for p in (workspace / "input").rglob("*")
        if p.is_file() and p.suffix.lower() in {".dd", ".raw", ".img", ".001", ".e01", ".vmdk", ".vhd"}
    )
    if not candidates:
        raise FileNotFoundError(
            "No supported forensic image found in workspace/input. "
            "Expected .dd, .raw, .img, .001, .e01, .vmdk or .vhd."
        )
    return candidates[0]


def _discover_case(cases_dir: Path, case_name: str) -> Path:
    candidates = sorted(
        p for p in cases_dir.iterdir()
        if p.is_dir() and p.name.lower().startswith(case_name.lower())
    ) if cases_dir.exists() else []
    if not candidates:
        raise RuntimeError(f"Autopsy did not create a case under {cases_dir}.")
    return candidates[-1]


def autopsy_e2e_operation(workspace: Path, assignment: str) -> dict[str, Any]:
    """Create an Autopsy case, add a disk image, run ingest, open the case GUI, and capture proof.

    The forensic image is never modified. Autopsy receives the immutable workspace copy.
    Command-line ingest is used for the deterministic heavy operation; the GUI is then
    opened for a human-readable, screenshot-able result.
    """
    profile = _profile("autopsy")
    executable = _application_path(profile)
    source = _find_data_source(workspace)
    cases_dir = workspace / "working" / "autopsy_cases"
    cases_dir.mkdir(parents=True, exist_ok=True)
    safe_name = re.sub(r"[^A-Za-z0-9_-]+", "_", assignment)[:60] or "assignment"
    case_name = f"{safe_name}_agent"
    timeout = int(os.environ.get("LAB_AGENT_AUTOPSY_TIMEOUT", "21600"))

    command = [
        executable,
        "--createCase",
        f"--caseName={case_name}",
        f"--caseBaseDir={cases_dir}",
        "--addDataSource",
        f"--dataSourcePath={source}",
        "--runIngest",
    ]
    log_dir = workspace / "logs"
    log_dir.mkdir(parents=True, exist_ok=True)
    command_log = log_dir / "autopsy_ingest.json"
    started = time.time()
    try:
        completed = subprocess.run(
            command,
            cwd=workspace,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        command_log.write_text(
            json.dumps(
                {
                    "command": command,
                    "timeout_seconds": timeout,
                    "duration_seconds": time.time() - started,
                    "stdout": exc.stdout or "",
                    "stderr": exc.stderr or "",
                    "verified": False,
                },
                ensure_ascii=False,
                indent=2,
            ),
            encoding="utf-8",
        )
        raise RuntimeError(
            f"Autopsy ingest exceeded {timeout}s. Check {command_log} and resume after inspection."
        ) from exc

    command_log.write_text(
        json.dumps(
            {
                "command": command,
                "return_code": completed.returncode,
                "duration_seconds": time.time() - started,
                "stdout": completed.stdout,
                "stderr": completed.stderr,
                "verified": completed.returncode == 0,
            },
            ensure_ascii=False,
            indent=2,
        ),
        encoding="utf-8",
    )
    if completed.returncode != 0:
        raise RuntimeError(
            f"Autopsy command-line ingest failed with exit code {completed.returncode}. "
            f"See {command_log}."
        )

    case_dir = _discover_case(cases_dir, case_name)
    if not case_dir.is_dir():
        raise RuntimeError("Autopsy case directory was not created.")

    gui_process = launch_application(
        executable, ["--caseDir=" + str(case_dir)], cwd=workspace
    )
    time.sleep(float(profile.get("launch_wait_seconds", 4)))

    screenshot = take_screenshot(
        workspace, name=f"autopsy_e2e_result_{int(time.time())}.png"
    )
    result = {
        "pid": gui_process.pid,
        "profile": "autopsy",
        "operation": "e2e",
        "data_source": str(source),
        "case_dir": str(case_dir),
        "command_log": str(command_log),
        "screenshot": str(screenshot),
        "verified": True,
        "return_code": completed.returncode,
    }
    (workspace / "results" / "autopsy.json").write_text(
        json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    return result


def _allowed_url(url: str, allowed_targets: set[str]) -> bool:
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        return False
    hostname = parsed.hostname.casefold()
    return hostname in {"localhost", "127.0.0.1", "::1"} or hostname in allowed_targets


def browser_operation(workspace: Path, url: str, allowed_targets: set[str]) -> dict[str, Any]:
    """Visit an explicitly scoped page, collect page metadata, and save a screenshot."""
    if not _allowed_url(url, allowed_targets):
        raise PermissionError("Browser target must be localhost or declared in allowed_targets.")
    try:
        from playwright.sync_api import sync_playwright
    except ImportError as exc:
        raise RuntimeError(
            "Browser automation requires the browser extra: pip install -e .[browser], "
            "then playwright install chromium"
        ) from exc
    folder = workspace / "screenshots"
    folder.mkdir(parents=True, exist_ok=True)
    output = folder / f"browser_{int(time.time())}.png"
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(headless=True)
        page = browser.new_page(viewport={"width": 1440, "height": 1000})
        response = page.goto(url, wait_until="networkidle", timeout=45_000)
        page.screenshot(path=str(output), full_page=True)
        status = response.status if response else None
        result = {
            "url": page.url,
            "title": page.title(),
            "status": status,
            "screenshot": str(output),
            "verified": status is not None and 200 <= status < 400,
        }
        browser.close()
    (workspace / "results" / "browser.json").write_text(
        json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    if not result["verified"]:
        raise RuntimeError(f"Browser target returned HTTP status {status}.")
    return result


def urls_from_text(text: str) -> list[str]:
    return re.findall(r"https?://[^\s<>()\[\]{}]+", text)
