"""Workspace-confined file helpers."""

from __future__ import annotations

import shutil
import zipfile
from datetime import UTC, datetime
from pathlib import Path

from .workspace import sha256_file


def _inside(root: Path, target: Path) -> Path:
    base = root.resolve()
    result = (base / target).resolve() if not target.is_absolute() else target.resolve()
    if not result.is_relative_to(base):
        raise ValueError(f"Path escapes workspace: {target}")
    return result


def list_files(root: Path, relative: str = ".") -> list[Path]:
    target = _inside(root, Path(relative))
    return sorted(path for path in target.rglob("*") if path.is_file())


def search_files(root: Path, query: str, relative: str = ".") -> list[str]:
    """Search workspace file names and bounded UTF-8 text contents."""
    needle = query.casefold()
    found: list[str] = []
    for path in list_files(root, relative):
        matched = needle in path.name.casefold()
        if not matched and path.stat().st_size <= 1_000_000:
            try:
                matched = needle in path.read_text(encoding="utf-8", errors="ignore").casefold()
            except OSError:
                continue
        if matched:
            found.append(path.relative_to(root.resolve()).as_posix())
    return found


def file_metadata(root: Path, relative: str) -> dict[str, str | int]:
    path = _inside(root, Path(relative))
    info = path.stat()
    return {"path": path.relative_to(root.resolve()).as_posix(), "size_bytes": info.st_size,
            "modified_at": datetime.fromtimestamp(info.st_mtime, UTC).isoformat(), "sha256": sha256_file(path)}


def read_file(root: Path, relative: str, max_bytes: int = 5_000_000) -> str:
    path = _inside(root, Path(relative))
    if path.stat().st_size > max_bytes:
        raise ValueError(f"File exceeds read limit ({max_bytes} bytes): {relative}")
    return path.read_text(encoding="utf-8", errors="replace")


def copy_file(root: Path, source: str, destination: str) -> dict[str, str]:
    src, dst = _inside(root, Path(source)), _inside(root, Path(destination))
    if not src.is_file():
        raise FileNotFoundError(src)
    before = sha256_file(src)
    dst.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(src, dst)
    after = sha256_file(dst)
    return {"source": str(src), "destination": str(dst), "source_sha256": before,
            "destination_sha256": after, "status": "MATCH" if before == after else "MISMATCH"}


def extract_zip(root: Path, archive_relative: str, destination_relative: str,
                max_file_bytes: int = 100_000_000, max_total_bytes: int = 500_000_000) -> list[str]:
    archive_path = _inside(root, Path(archive_relative))
    destination = _inside(root, Path(destination_relative))
    destination.mkdir(parents=True, exist_ok=True)
    written: list[str] = []
    total_bytes = 0
    with zipfile.ZipFile(archive_path) as archive:
        for member in archive.infolist():
            output = (destination / member.filename).resolve()
            if not output.is_relative_to(destination.resolve()):
                raise ValueError(f"Archive member escapes destination: {member.filename}")
            if member.is_dir():
                output.mkdir(parents=True, exist_ok=True)
                continue
            if member.flag_bits & 0x1:
                raise ValueError(f"Encrypted ZIP members are not supported: {member.filename}")
            if member.file_size > max_file_bytes or total_bytes + member.file_size > max_total_bytes:
                raise ValueError("ZIP extraction exceeds configured uncompressed size limits.")
            output.parent.mkdir(parents=True, exist_ok=True)
            actual_file_bytes = 0
            with archive.open(member) as src, output.open("wb") as dst:
                for chunk in iter(lambda: src.read(1024 * 1024), b""):
                    actual_file_bytes += len(chunk)
                    total_bytes += len(chunk)
                    if actual_file_bytes > max_file_bytes or total_bytes > max_total_bytes:
                        raise ValueError("ZIP extraction exceeds configured uncompressed size limits.")
                    dst.write(chunk)
            written.append(str(output.relative_to(root.resolve())))
    return written
