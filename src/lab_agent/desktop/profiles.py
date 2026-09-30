"""Versioned application profiles (``profiles/<app>.yaml`` or ``profiles/<app>/<version>.yaml``).

A profile describes, for one application:

* ``executable_env`` / ``window`` detection;
* ``operations``: lists of UIA actions (see :mod:`lab_agent.desktop.engine`);
* ``verification``: post-condition checks per operation;
* ``dismiss``: known pop-ups the computer-use loop may close;
* ``versions``: per-version overrides keyed by version prefix (``"4.21"``, ``"4"``).

The profile version is selected from the application version found by
environment discovery; the longest matching prefix wins.
"""

from __future__ import annotations

import copy
import os
import re
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[3]
PROFILE_NAME_RE = re.compile(r"^[A-Za-z0-9_-]+$")


def profile_dirs() -> list[Path]:
    dirs: list[Path] = []
    if os.environ.get("LAB_AGENT_PROFILES_DIR"):
        dirs.extend(Path(p) for p in os.environ["LAB_AGENT_PROFILES_DIR"].split(os.pathsep) if p)
    dirs.append(ROOT / "profiles")
    return dirs


def _yaml() -> Any:
    try:
        import yaml
    except ImportError as exc:
        raise RuntimeError("Profiles require PyYAML: pip install -e .[gui]") from exc
    return yaml


def _merge(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    merged = copy.deepcopy(base)
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(merged.get(key), dict):
            merged[key] = _merge(merged[key], value)
        else:
            merged[key] = copy.deepcopy(value)
    return merged


def _version_key(text: str) -> tuple[int, ...]:
    return tuple(int(part) for part in re.findall(r"\d+", text))


def select_version(keys: list[str], app_version: str | None) -> str | None:
    """Longest version prefix of ``app_version`` among ``keys`` (e.g. "4.21" for "4.21.0")."""
    if not keys:
        return None
    if app_version:
        wanted = _version_key(app_version)
        best: tuple[int, str] | None = None
        for key in keys:
            parts = _version_key(key.rstrip(".x"))
            if parts and wanted[: len(parts)] == parts and (best is None or len(parts) > best[0]):
                best = (len(parts), key)
        if best:
            return best[1]
    if "default" in keys:
        return "default"
    return None


def available_profiles() -> dict[str, list[str]]:
    found: dict[str, list[str]] = {}
    for base in profile_dirs():
        if not base.is_dir():
            continue
        for item in sorted(base.iterdir()):
            if item.is_dir() and PROFILE_NAME_RE.fullmatch(item.name):
                found.setdefault(item.name, []).extend(sorted(p.stem for p in item.glob("*.y*ml")))
            elif item.suffix in {".yaml", ".yml"} and PROFILE_NAME_RE.fullmatch(item.stem):
                data = _yaml().safe_load(item.read_text(encoding="utf-8")) or {}
                versions = sorted((data.get("versions") or {}).keys()) if isinstance(data, dict) else []
                found.setdefault(item.stem, []).extend(["base", *versions])
    return found


def load_profile(name: str, version: str | None = None) -> dict[str, Any]:
    """Load and version-resolve a profile. Raises ``FileNotFoundError`` when missing."""
    if not PROFILE_NAME_RE.fullmatch(name):
        raise ValueError(f"Invalid desktop profile name: {name!r}")
    yaml = _yaml()
    for base in profile_dirs():
        folder = base / name
        if folder.is_dir():
            files = {p.stem: p for p in folder.glob("*.y*ml")}
            chosen = select_version(sorted(files), version) or max(files, key=_version_key, default=None)
            if chosen:
                data = yaml.safe_load(files[chosen].read_text(encoding="utf-8")) or {}
                return _finalize(name, data, chosen)
        flat = base / f"{name}.yaml"
        if flat.is_file():
            data = yaml.safe_load(flat.read_text(encoding="utf-8")) or {}
            if not isinstance(data, dict):
                raise TypeError(f"Desktop profile must be a YAML object: {flat}")
            versions = data.pop("versions", None) or {}
            chosen = select_version(sorted(versions), version)
            if chosen:
                data = _merge(data, versions[chosen])
            return _finalize(name, data, chosen or "base")
    raise FileNotFoundError(f"Desktop profile not found: {name} (searched {[str(d) for d in profile_dirs()]})")


def _finalize(name: str, data: dict[str, Any], version: str) -> dict[str, Any]:
    data.setdefault("name", name)
    data["profile_version"] = version
    if "window" not in data and data.get("window_title_re"):
        data["window"] = {"title_re": data["window_title_re"]}
    data.setdefault("operations", {})
    return data
