"""Environment discovery, preflight checks and ``lab-agent doctor``.

Applications are described by :class:`~lab_agent.integrations.base.AppSpec`
objects: a few core ones here, the rest contributed by integrations through
their ``applications()`` hook, so a new integration is discovered without
editing this module.

Lookup order per application: ``config.applications`` > ``LAB_AGENT_*_PATH``
environment variable > ``PATH`` > known install directories > Windows
uninstall registry.  GUI applications are never started to read a version;
versions come from the registry, file version resources or folder names.
"""

from __future__ import annotations

import glob
import importlib.util
import json
import os
import platform
import re
import shutil
import subprocess
import sys
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .integrations.base import AppSpec

CORE_APPS: tuple[AppSpec, ...] = (
    AppSpec("python", "Python", executables=("python.exe", "python3", "python"), version_args=("--version",)),
    AppSpec("powershell", "PowerShell", executables=("pwsh.exe", "powershell.exe", "pwsh"),
            version_args=("-NoProfile", "-Command", "$PSVersionTable.PSVersion.ToString()")),
    AppSpec("java", "Java", executables=("java.exe", "java"), version_args=("-version",)),
    AppSpec("git", "Git", executables=("git.exe", "git"), version_args=("--version",)),
    AppSpec("wsl", "Windows Subsystem for Linux", executables=("wsl.exe",)),
    AppSpec("docker", "Docker", executables=("docker.exe", "docker"), version_args=("--version",)),
)


@dataclass
class AppInfo:
    name: str
    display_name: str
    available: bool
    path: str | None = None
    version: str | None = None
    source: str | None = None
    capabilities: list[str] = field(default_factory=list)
    note: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _roots() -> list[Path]:
    roots = []
    for variable in ("ProgramFiles", "ProgramFiles(x86)", "ProgramW6432", "LOCALAPPDATA", "ProgramData"):
        value = os.environ.get(variable)
        if value:
            roots.append(Path(value))
    local = os.environ.get("LOCALAPPDATA")
    if local:
        roots.append(Path(local) / "Programs")
    if os.name == "nt":  # portable tools (TestDisk, HxD, ...) are usually unpacked to C:\Tools
        roots.append(Path(os.environ.get("SystemDrive", "C:") + "\\") / "Tools")
    roots.extend([Path("/usr/bin"), Path("/usr/local/bin"), Path("/opt"), Path("/Applications")])
    unique: list[Path] = []
    for root in roots:
        if root not in unique and root.is_dir():
            unique.append(root)
    return unique


def _registry_entries() -> list[dict[str, str]]:
    if os.name != "nt":
        return []
    try:
        import winreg
    except ImportError:
        return []
    entries: list[dict[str, str]] = []
    keys = [
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"),
        (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
    ]
    for hive, path in keys:
        try:
            root = winreg.OpenKey(hive, path)
        except OSError:
            continue
        for index in range(winreg.QueryInfoKey(root)[0]):
            try:
                sub = winreg.OpenKey(root, winreg.EnumKey(root, index))
            except OSError:
                continue
            entry: dict[str, str] = {}
            for value_name in ("DisplayName", "DisplayVersion", "InstallLocation", "DisplayIcon"):
                try:
                    entry[value_name] = str(winreg.QueryValueEx(sub, value_name)[0])
                except OSError:
                    continue
            if entry.get("DisplayName"):
                entries.append(entry)
    return entries


def _file_version(path: Path) -> str | None:
    if os.name != "nt":
        return None
    try:
        import win32api  # type: ignore[import-untyped]

        info = win32api.GetFileVersionInfo(str(path), "\\")
        ms, ls = info["FileVersionMS"], info["FileVersionLS"]
        return f"{ms >> 16}.{ms & 0xFFFF}.{ls >> 16}.{ls & 0xFFFF}"
    except Exception:  # noqa: BLE001 - pywin32 optional / no version resource
        return None


def _version_from_command(path: str, spec: AppSpec) -> str | None:
    if not spec.version_args:
        return None
    try:
        completed = subprocess.run([path, *spec.version_args], capture_output=True, text=True, timeout=20, check=False,
                                   errors="replace")
    except (OSError, subprocess.SubprocessError):
        return None
    match = re.search(spec.version_re, (completed.stdout or "") + (completed.stderr or ""))
    return match.group(1) if match else None


def _version_from_path(path: Path) -> str | None:
    for part in reversed(path.parts):
        match = re.search(r"(\d+\.\d+(?:\.\d+){0,2})", part)
        if match:
            return match.group(1)
    return None


def discover_app(spec: AppSpec, config: Any = None, registry_entries: list[dict[str, str]] | None = None) -> AppInfo:
    info = AppInfo(spec.name, spec.display_name, False, capabilities=list(spec.capabilities))
    candidates: list[tuple[str, str]] = []
    configured = getattr(config, "applications", {}) or {}
    if spec.name in configured:
        candidates.append((str(configured[spec.name]), "config"))
    if spec.env_var and os.environ.get(spec.env_var):
        candidates.append((os.environ[spec.env_var], f"env:{spec.env_var}"))
    for executable in spec.executables:
        found = shutil.which(executable)
        if found:
            candidates.append((found, "PATH"))
    for root in _roots():
        for pattern in spec.install_globs:
            for match in sorted(glob.glob(str(root / pattern)), reverse=True):
                candidates.append((match, f"install_dir:{root}"))
    registry_version: str | None = None
    if spec.registry_name_re:
        for entry in registry_entries if registry_entries is not None else _registry_entries():
            if re.search(spec.registry_name_re, entry.get("DisplayName", ""), re.IGNORECASE):
                registry_version = entry.get("DisplayVersion") or registry_version
                location = entry.get("InstallLocation", "").strip('"')
                for executable in spec.executables:
                    for candidate in (Path(location) / executable, Path(location) / "bin" / executable) if location else ():
                        candidates.append((str(candidate), "registry"))
                icon = entry.get("DisplayIcon", "").split(",")[0].strip('"')
                if icon.lower().endswith(".exe") and Path(icon).name.lower() in {e.lower() for e in spec.executables}:
                    candidates.append((icon, "registry"))
    for path_text, source in candidates:
        path = Path(path_text)
        if path.is_file():
            info.available, info.path, info.source = True, str(path), source
            info.version = registry_version or _file_version(path) or _version_from_command(str(path), spec) or _version_from_path(path)
            return info
        if source.startswith(("config", "env")):
            info.note = f"{source} points to a missing file: {path_text}"
    if not info.note:
        info.note = "not found; set " + (spec.env_var or f"applications.{spec.name} in config.yaml")
    return info


def wsl_tools(tools: tuple[str, ...] = ("foremost", "scalpel", "fls", "fsstat", "mmls", "icat"), distro: str | None = None,
              timeout: float = 90) -> dict[str, Any]:
    """Which Linux forensic tools are installed inside WSL (empty when WSL is absent)."""
    if not shutil.which("wsl.exe") and not shutil.which("wsl"):
        return {"available": False, "reason": "wsl.exe not found", "tools": {}}
    distro = distro or os.environ.get("LAB_AGENT_WSL_DISTRO") or "Ubuntu"
    script = "; ".join(f'printf "%s=%s\\n" {tool} "$(command -v {tool} || true)"' for tool in tools)
    try:
        completed = subprocess.run(["wsl.exe", "-d", distro, "-e", "sh", "-c", script], capture_output=True,
                                   timeout=timeout, check=False)
    except (OSError, subprocess.SubprocessError) as exc:
        return {"available": False, "reason": str(exc), "tools": {}}
    output = completed.stdout.decode("utf-8", errors="replace")
    found = {}
    for line in output.splitlines():
        if "=" in line:
            name, _, location = line.partition("=")
            found[name.strip()] = location.strip() or None
    if completed.returncode != 0 and not found:
        return {"available": False, "distro": distro, "reason": completed.stderr.decode("utf-16-le", errors="replace")[:300],
                "tools": {}}
    return {"available": True, "distro": distro, "tools": found}


def all_app_specs(registry: Any = None) -> list[AppSpec]:
    specs = list(CORE_APPS)
    if registry is not None:
        seen = {spec.name for spec in specs}
        for spec in registry.applications():
            if spec.name not in seen:
                specs.append(spec)
                seen.add(spec.name)
    return specs


def discover_environment(registry: Any = None, config: Any = None, *, include_wsl: bool = False) -> dict[str, Any]:
    entries = _registry_entries()
    apps = {spec.name: discover_app(spec, config, entries).to_dict() for spec in all_app_specs(registry)}
    if not apps.get("python", {}).get("available"):
        apps["python"] = AppInfo("python", "Python", True, sys.executable, sys.version.split()[0], "running interpreter",
                                 []).to_dict()
    apps["chromium"] = _playwright_browser()
    result: dict[str, Any] = {
        "generated_at": datetime.now(UTC).isoformat(),
        "os": f"{platform.system()} {platform.release()} ({platform.version()})",
        "machine": platform.machine(),
        "python": sys.version.split()[0],
        "applications": apps,
    }
    if include_wsl:
        result["wsl"] = wsl_tools()
    return result


def _playwright_browser() -> dict[str, Any]:
    info = {"name": "chromium", "display_name": "Chromium (Playwright)", "available": False, "path": None,
            "version": None, "source": None, "capabilities": ["browser.*"], "note": ""}
    if importlib.util.find_spec("playwright") is None:
        info["note"] = "playwright not installed (pip install -e .[browser])"
        return info
    base = Path(os.environ.get("PLAYWRIGHT_BROWSERS_PATH") or
                (Path(os.environ.get("LOCALAPPDATA", "")) / "ms-playwright" if os.name == "nt" else Path.home() / ".cache" / "ms-playwright"))
    patterns = ["chromium-*/chrome-win*/chrome.exe", "chromium-*/chrome-win/chrome.exe", "chromium-*/chrome-linux*/chrome"]
    for pattern in patterns:
        matches = sorted(glob.glob(str(base / pattern)), reverse=True)
        if matches:
            revision = re.search(r"chromium-(\d+)", matches[0])
            info.update(available=True, path=matches[0], source="playwright",
                        version=f"playwright revision {revision.group(1)}" if revision else None)
            return info
    info["note"] = "run: python -m playwright install chromium"
    return info


def save_environment(environment: dict[str, Any], path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(environment, ensure_ascii=False, indent=2), encoding="utf-8")
    return path


def app_index(environment: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return dict(environment.get("applications", {}))


# ---------------------------------------------------------------------------- doctor
DEPENDENCIES = (
    ("pydantic", "pydantic", True), ("PyYAML", "yaml", False), ("python-docx", "docx", False),
    ("reportlab", "reportlab", False), ("pypdf", "pypdf", False), ("Pillow", "PIL", False),
    ("PyAutoGUI", "pyautogui", False), ("pywinauto", "pywinauto", False), ("Playwright", "playwright", False),
    ("FastAPI", "fastapi", False), ("uvicorn", "uvicorn", False),
)


def _desktop_session() -> tuple[bool, str]:
    try:
        from PIL import ImageGrab

        image = ImageGrab.grab(bbox=(0, 0, 64, 64))
        return image.size == (64, 64), f"capture {image.size[0]}x{image.size[1]} ok"
    except Exception as exc:  # noqa: BLE001
        return False, str(exc)[:200]


def _ai_status(config: Any) -> list[tuple[str, str, str]]:
    rows = []
    rows.append(("OpenAI", "ok" if os.environ.get("OPENAI_API_KEY") else "-", "OPENAI_API_KEY set" if os.environ.get("OPENAI_API_KEY") else "OPENAI_API_KEY not set"))
    host = os.environ.get("OLLAMA_HOST", "http://127.0.0.1:11434").rstrip("/")
    try:
        import urllib.request

        with urllib.request.urlopen(host + "/api/tags", timeout=2) as response:
            models = [m.get("name") for m in json.loads(response.read()).get("models", [])]
        rows.append(("Ollama", "ok", f"{host} ({len(models)} model(s))"))
    except Exception:  # noqa: BLE001
        rows.append(("Ollama", "-", f"{host} unreachable"))
    return rows


def run_doctor(registry: Any = None, config: Any = None, workspace_root: Path | None = None,
               *, include_wsl: bool = True) -> dict[str, Any]:
    checks: list[dict[str, str]] = []

    def add(group: str, name: str, status: str, detail: str = "") -> None:
        checks.append({"group": group, "name": name, "status": status, "detail": detail})

    add("runtime", "Python", "ok" if sys.version_info >= (3, 12) else "fail", sys.version.split()[0])
    for label, module, required in DEPENDENCIES:
        present = importlib.util.find_spec(module) is not None
        add("dependencies", label, "ok" if present else ("fail" if required else "warn"), "installed" if present else "missing")
    environment = discover_environment(registry, config, include_wsl=include_wsl)
    for name, app in environment["applications"].items():
        detail = f"{app.get('path')} ({app.get('version') or 'version unknown'})" if app["available"] else app.get("note", "")
        add("applications", app.get("display_name") or name, "ok" if app["available"] else "-", detail)
    if include_wsl:
        wsl = environment.get("wsl", {})
        for tool, location in (wsl.get("tools") or {}).items():
            add("wsl", tool, "ok" if location else "-", location or f"sudo apt install {'sleuthkit' if tool in {'fls', 'fsstat', 'mmls', 'icat'} else tool}")
        if not wsl.get("available"):
            add("wsl", "WSL", "-", str(wsl.get("reason", "")))
    for name, status, detail in _ai_status(config):
        add("ai", name, status, detail)
    ok, detail = _desktop_session()
    add("desktop", "Screenshot", "ok" if ok else "warn", detail)
    root = (workspace_root or Path(getattr(config, "workspace_root", "workspace"))).expanduser().resolve()
    try:
        root.mkdir(parents=True, exist_ok=True)
        probe = root / ".doctor_probe"
        probe.write_text("ok", encoding="utf-8")
        probe.unlink()
        add("workspace", "Workspace permissions", "ok", str(root))
    except OSError as exc:
        add("workspace", "Workspace permissions", "fail", str(exc))
    if registry is not None:
        add("plugins", "Capabilities", "ok", f"{len(registry.capabilities())} registered")
        for error in getattr(registry, "load_errors", []):
            add("plugins", error.get("source", "plugin"), "warn", error.get("error", ""))
    failed = [c for c in checks if c["status"] == "fail"]
    warnings = [c for c in checks if c["status"] == "warn"]
    verdict = "NOT_READY" if failed else "READY" if not warnings else "READY_WITH_WARNINGS"
    return {"result": verdict, "checks": checks, "environment": environment}


def format_doctor(report: dict[str, Any]) -> str:
    symbols = {"ok": "✓", "fail": "✗", "warn": "!", "-": "-"}
    lines = ["DoneAsik Lab Agent Doctor", ""]
    group = None
    for check in report["checks"]:
        if check["group"] != group:
            group = check["group"]
            lines.append(f"[{group}]")
        lines.append(f"  {check['name']:<34} {symbols.get(check['status'], '?')}  {check['detail']}")
    lines += ["", f"Result: {report['result']}"]
    return "\n".join(lines)
