"""Digital-forensics toolkit integration (carving, signatures, TSK, chain of custody).

Everything here produces real, re-checkable artefacts:

* hashes are computed from bytes, never copied from the assignment text;
* signature analysis reads magic numbers from the files themselves;
* carving uses Foremost/Scalpel when they are installed (natively or in WSL)
  and otherwise the transparent built-in header/footer carver - each output
  states which tool produced it;
* fragment repair locates structures (e.g. the ZIP End Of Central Directory)
  in the data instead of trusting offsets printed in an assignment;
* every external command is appended to ``logs/commands.jsonl`` and compiled
  into ``commands.txt``.
"""

from __future__ import annotations

import csv
import io
import json
import os
import re
import shutil
import zipfile
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path, PureWindowsPath
from typing import Any

from ..tools.process import run_command
from ..workspace import calculate_hashes, input_manifest, sha256_file
from .base import (
    AppSpec,
    BaseIntegration,
    Capability,
    ExecutionContext,
    IntegrationResult,
    Param,
    evidence,
    param_bool,
    param_int,
    param_list,
    param_str,
)
from .forensics_story import ForensicsNarration

IMAGE_EXTENSIONS = {".dd", ".raw", ".img", ".001", ".e01", ".vmdk", ".vhd", ".bin"}

SIGNATURES: tuple[tuple[str, bytes, str], ...] = (
    ("png", b"\x89PNG\r\n\x1a\n", "PNG image"),
    ("jpg", b"\xff\xd8\xff", "JPEG image"),
    ("pdf", b"%PDF", "PDF document"),
    ("zip", b"PK\x03\x04", "ZIP archive / OOXML"),
    ("gif", b"GIF8", "GIF image"),
    ("rar", b"Rar!\x1a\x07", "RAR archive"),
    ("7z", b"7z\xbc\xaf\x27\x1c", "7-Zip archive"),
    ("exe", b"MZ", "Windows executable"),
    ("elf", b"\x7fELF", "ELF executable"),
    ("sqlite", b"SQLite format 3\x00", "SQLite database"),
    ("gz", b"\x1f\x8b", "gzip"),
    ("bmp", b"BM", "Bitmap image"),
)
EQUIVALENT_EXTENSIONS = {"jpg": {"jpg", "jpeg", "jpe"}, "zip": {"zip", "docx", "xlsx", "pptx", "jar", "odt"},
                         "exe": {"exe", "dll", "sys"}, "sqlite": {"sqlite", "db", "sqlite3"}}
TEXT_EXTENSIONS = {"txt", "log", "csv", "md", "conf", "cfg", "ini", "py", "json", "xml", "html", "sha256", "md5"}


@dataclass
class CarveRule:
    extension: str
    case_sensitive: bool
    max_size: int
    header: bytes
    footer: bytes | None
    mode: str = ""  # REVERSE | NEXT | ""


DEFAULT_RULES = (
    CarveRule("jpg", True, 20_000_000, b"\xff\xd8\xff", b"\xff\xd9"),
    CarveRule("png", True, 5_000_000, b"\x89PNG\r\n\x1a\n", b"IEND\xaeB`\x82"),
    CarveRule("pdf", True, 10_000_000, b"%PDF", b"%%EOF"),
    CarveRule("zip", True, 50_000_000, b"PK\x03\x04", b"PK\x05\x06", "REVERSE"),
    CarveRule("gif", True, 5_000_000, b"GIF8", b"\x00\x3b"),
)


def _unescape(token: str) -> bytes:
    """Decode scalpel.conf escapes such as ``\\x89\\x50`` or ``\\xff\\xd8``."""
    out = bytearray()
    index = 0
    while index < len(token):
        if token[index] == "\\" and index + 1 < len(token):
            nxt = token[index + 1]
            if nxt == "x" and index + 3 < len(token) + 1:
                out.append(int(token[index + 2:index + 4], 16))
                index += 4
                continue
            mapping = {"n": 10, "r": 13, "t": 9, "\\": 92, "s": 32}
            if nxt in mapping:
                out.append(mapping[nxt])
                index += 2
                continue
        out.append(ord(token[index]))
        index += 1
    return bytes(out)


def parse_scalpel_conf(text: str) -> list[CarveRule]:
    rules = []
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        parts = stripped.split()
        if len(parts) < 4:
            continue
        ext, case, size, header = parts[:4]
        footer = parts[4] if len(parts) > 4 and parts[4].upper() not in {"REVERSE", "NEXT"} else None
        mode = next((p.upper() for p in parts[4:] if p.upper() in {"REVERSE", "NEXT"}), "")
        rules.append(CarveRule(ext.lower(), case.lower() == "y", int(size), _unescape(header),
                               _unescape(footer) if footer else None, mode))
    return rules


def detect_signature(data: bytes) -> tuple[str | None, str]:
    for name, magic, description in SIGNATURES:
        if data.startswith(magic):
            return name, description
    if data[:4] == b"\x00\x00\x00\x00" and b"IHDR" in data[:32]:
        return "png?", "PNG with destroyed magic bytes (IHDR chunk present)"
    try:
        data[:512].decode("utf-8")
        if data[:512] and all(ch in b"\t\n\r" or 32 <= ch < 127 or ch >= 128 for ch in data[:512]):
            return "text", "text data"
    except UnicodeDecodeError:
        pass
    return None, "unknown binary data"


def hex_dump(data: bytes, start: int = 0, width: int = 16) -> str:
    lines = []
    for offset in range(0, len(data), width):
        chunk = data[offset:offset + width]
        hexes = " ".join(f"{b:02X}" for b in chunk)
        text = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"{start + offset:08X}:  {hexes:<{width * 3}} {text}")
    return "\n".join(lines)


def windows_to_wsl(path: Path) -> str:
    text = str(path.resolve())
    pure = PureWindowsPath(text)
    if pure.drive and len(pure.drive) == 2:
        rest = "/".join(pure.parts[1:])
        return f"/mnt/{pure.drive[0].lower()}/{rest}"
    return text.replace("\\", "/")


def _eocd_end(data: bytes, start: int = 0) -> int | None:
    """End offset (exclusive) of the last ZIP End Of Central Directory record in ``data``."""
    index = data.rfind(b"PK\x05\x06", start)
    if index < 0 or index + 22 > len(data):
        return None
    comment_length = int.from_bytes(data[index + 20:index + 22], "little")
    return index + 22 + comment_length


class ForensicsAdapter(ForensicsNarration, BaseIntegration):
    name = "forensics"
    APPLICATIONS = (
        AppSpec("foremost", "Foremost", env_var="LAB_AGENT_FOREMOST_PATH", executables=("foremost", "foremost.exe"),
                version_args=("-V",), capabilities=("forensics.carve",)),
        AppSpec("scalpel", "Scalpel", env_var="LAB_AGENT_SCALPEL_PATH", executables=("scalpel", "scalpel.exe"),
                version_args=("-V",), capabilities=("forensics.carve",)),
        AppSpec("sleuthkit", "The Sleuth Kit (fls)", env_var="LAB_AGENT_TSK_PATH", executables=("fls", "fls.exe"),
                install_globs=("sleuthkit*/bin/fls.exe",), version_args=("-V",), capabilities=("forensics.tsk",)),
    )
    CAPABILITIES = (
        Capability(
            "forensics.verify_image_hash", "forensics",
            "Hash a forensic image and compare with its .sha256 reference; writes source_image_sha256_<label>.txt",
            (Param("image", "path"), Param("expected_file", "path"), Param("label", "str", False, "before|after",
                                                                                 choices=("before", "after"))),
            ("hash",), "SHA-256 of the image equals the reference value", keywords=("sha256", "контрольн", "checksum", ".dd")),
        Capability(
            "forensics.working_copy", "forensics", "Copy the forensic image to working/ and prove the copy is bit-identical",
            (Param("image", "path"),), ("hash",), "copy hash equals original hash", keywords=("копи", "copy", "working copy")),
        Capability(
            "forensics.signature_scan", "forensics",
            "Compare file extensions with real magic numbers (header offset 0) and write file_signature_analysis.csv",
            (Param("paths", "list", False, "workspace paths; default: all inputs except images"),),
            ("csv",), "one row per file with extension, signature, offset and verdict",
            keywords=("сигнатур", "signature", "magic", "hex", "расширени", "extension")),
        Capability(
            "forensics.image_signatures", "forensics", "Locate known file headers/footers inside a raw image (offset table)",
            (Param("image", "path"),), ("csv",), "offset table of every header found", keywords=("offset", "смещени", "raw")),
        Capability(
            "forensics.hex_view", "forensics", "Save a hex dump (and rendered figure) of bytes at an offset",
            (Param("path", "path", True), Param("offset", "int", False, "decimal or 0x hex"), Param("length", "int")),
            ("file", "figure"), "hex dump file written from real bytes", keywords=("hex",)),
        Capability(
            "forensics.carve", "forensics",
            "Carve files from a raw image with foremost, scalpel or the built-in header/footer carver",
            (Param("tool", "str", False, "builtin|foremost|scalpel", choices=("builtin", "foremost", "scalpel")),
             Param("image", "path"), Param("types", "list", False, "e.g. pdf,jpg"), Param("config", "path", False, "scalpel.conf"),
             Param("output", "str", False, "results/<output>"), Param("enable_types", "list", False, "scalpel types to uncomment")),
            ("file", "log"), "audit log exists and carved files are listed/validated",
            keywords=("carv", "карвинг", "foremost", "scalpel")),
        Capability(
            "forensics.hash_directory", "forensics", "SHA-256 of all recovered files and validity check -> recovered_files_sha256.csv",
            (Param("directories", "list", False, "results/<tool>_output folders"),), ("csv",),
            "one row per recovered file with SHA-256"),
        Capability(
            "forensics.compare_results", "forensics", "Compare outputs of several carving tools by SHA-256 -> comparison_results.csv",
            (Param("directories", "list"),), ("csv",), "each unique file listed with the tools that found it",
            keywords=("сравн", "compare", "comparison")),
        Capability(
            "forensics.repair_zip_fragments", "forensics",
            "Reassemble a fragmented ZIP: read clusters, restore the local-file-header magic, trim at the real EOCD",
            (Param("image", "path"), Param("offsets", "list", True, "cluster offsets in order, e.g. 0x0041A000,0x0052C000"),
             Param("cluster_size", "int"), Param("output", "str")),
            ("archive",), "result opens as a valid ZIP (CRC-checked)", keywords=("фрагмент", "fragment", "evidence_fixed", "zip")),
        Capability(
            "forensics.tsk", "forensics", "Run a Sleuth Kit command (fsstat, fls, mmls, istat, icat) natively or in WSL",
            (Param("command", "str", True, choices=("fsstat", "fls", "mmls", "istat", "icat", "img_stat")),
             Param("image", "path"), Param("args", "list")),
            ("command_output",), "command exit code 0 and output saved", keywords=("sleuth", "tsk", "fls", "istat", "icat")),
        Capability(
            "forensics.case_records", "forensics",
            "Write case_context.csv, chain_of_custody.csv and commands.txt from the recorded run",
            (Param("case_id", "str"), Param("examiner", "str")), ("csv", "file"),
            "files exist and reference the real hashes/commands", keywords=("chain of custody", "цепочк", "case_context")),
    )

    # ------------------------------------------------------------------ helpers
    @staticmethod
    def _image(parameters: dict[str, Any], context: ExecutionContext) -> Path:
        value = param_str(parameters, "image")
        if value:
            return context.resolve(value, base="input")
        candidates = sorted(p for p in (context.workspace / "input").rglob("*")
                            if p.is_file() and p.suffix.lower() in IMAGE_EXTENSIONS)
        if not candidates:
            extracted = context.workspace / "working" / "extracted"
            candidates = sorted(p for p in extracted.rglob("*") if p.is_file() and p.suffix.lower() in IMAGE_EXTENSIONS) \
                if extracted.is_dir() else []
        if not candidates:
            raise FileNotFoundError("No raw forensic image (.dd/.raw/.img/.e01...) found in the workspace inputs.")
        return candidates[0]

    @staticmethod
    def _rel(path: Path, context: ExecutionContext) -> str:
        return path.resolve().relative_to(context.workspace.resolve()).as_posix()

    def _tool(self, name: str, context: ExecutionContext) -> tuple[list[str], str] | None:
        """Command prefix for a CLI tool: native path first, then WSL."""
        native = context.app_path(name) or shutil.which(name)
        if native:
            return [native], "native"
        wsl_info = context.environment.get("_wsl") if isinstance(context.environment, dict) else None
        if wsl_info is None:
            from ..environment import wsl_tools

            wsl_info = wsl_tools()
            if isinstance(context.environment, dict):
                context.environment["_wsl"] = wsl_info
        if wsl_info.get("available") and (wsl_info.get("tools") or {}).get(name):
            return ["wsl.exe", "-d", str(wsl_info.get("distro", "Ubuntu")), "-e", name], "wsl"
        return None

    def _path_for(self, path: Path, mode: str) -> str:
        return windows_to_wsl(path) if mode == "wsl" and os.name == "nt" else str(path)

    def _commands_log(self, context: ExecutionContext) -> Path:
        return context.folder("logs") / "commands.jsonl"

    # ------------------------------------------------------------------ hashing
    def verify_image_hash(self, parameters: dict[str, Any], context: ExecutionContext) -> IntegrationResult:
        image = self._image(parameters, context)
        label = param_str(parameters, "label", "before") or "before"
        reference_name = param_str(parameters, "expected_file") or f"{image.name}.sha256"
        try:
            reference = context.resolve(reference_name, base="input")
        except FileNotFoundError:
            reference = None
        expected = None
        if reference is not None:
            match = re.search(r"\b[0-9a-fA-F]{64}\b", reference.read_text(encoding="utf-8", errors="replace"))
            expected = match.group(0).lower() if match else None
        if expected is None:
            manifest = {Path(str(e["workspace_copy"])).name: e for e in input_manifest(context.workspace)}
            if image.name in manifest:
                expected, reference_name = str(manifest[image.name]["sha256"]), "input_manifest.json (acquisition hash)"
        digests = calculate_hashes(image)
        status = "SOURCE_UNCHANGED" if expected == digests["sha256"] else ("NO_REFERENCE" if expected is None else "MISMATCH")
        text = (f"image: {self._rel(image, context)}\nsize_bytes: {image.stat().st_size}\n"
                f"md5: {digests['md5']}\nsha1: {digests['sha1']}\nsha256: {digests['sha256']}\n"
                f"reference: {reference_name}\nexpected_sha256: {expected or 'n/a'}\nstatus: {status}\n"
                f"computed_at: {datetime.now(UTC).isoformat()}\n")
        output = context.save_result(f"source_image_sha256_{label}.txt", text)
        verified = status == "SOURCE_UNCHANGED"
        return IntegrationResult(
            verified=verified,
            details={"image": self._rel(image, context), "sha256": digests["sha256"], "expected": expected, "status": status,
                     **({} if verified else {"reason": f"Image hash status {status}"})},
            evidence=[evidence(output, f"SHA-256 of {image.name} ({label} examination): {status}", "hash")],
            checks=[{"type": "hash_match", "path": self._rel(image, context), "expected": expected or "missing"},
                    {"type": "text_contains", "path": f"results/source_image_sha256_{label}.txt", "value": "SOURCE_UNCHANGED"}],
        )

    def working_copy(self, parameters: dict[str, Any], context: ExecutionContext) -> IntegrationResult:
        image = self._image(parameters, context)
        target = context.folder("working") / "evidence_copy" / image.name
        target.parent.mkdir(parents=True, exist_ok=True)
        if not target.exists() or sha256_file(target) != sha256_file(image):
            shutil.copy2(image, target)
        original, copy = sha256_file(image), sha256_file(target)
        output = context.save_result("working_copy_verification.txt",
                                     f"original: {self._rel(image, context)}\ncopy: {self._rel(target, context)}\n"
                                     f"original_sha256: {original}\ncopy_sha256: {copy}\nresult: {'IDENTICAL' if original == copy else 'DIFFERENT'}\n")
        return IntegrationResult(
            verified=original == copy,
            details={"copy": self._rel(target, context), "sha256": copy},
            evidence=[evidence(output, "Working copy is bit-identical to the source image", "hash")],
            checks=[{"type": "hash_match", "path": self._rel(target, context), "same_as": self._rel(image, context)}],
        )

    # ------------------------------------------------------------------ signatures
    def signature_scan(self, parameters: dict[str, Any], context: ExecutionContext) -> IntegrationResult:
        requested = param_list(parameters, "paths")
        roots = [context.workspace / "input", context.workspace / "working" / "extracted"]
        files = [context.resolve(str(p)) for p in requested] if requested else sorted(
            p for root in roots if root.is_dir() for p in root.rglob("*")
            if p.is_file() and p.suffix.lower() not in IMAGE_EXTENSIONS and not p.name.startswith("."))
        if not files:
            return IntegrationResult.failed("No files to analyse")
        rows = []
        for path in files:
            with path.open("rb") as stream:
                head = stream.read(512)
            detected, description = detect_signature(head)
            declared = path.suffix.lower().lstrip(".")
            if detected in {None, "text"}:
                match = declared in TEXT_EXTENSIONS if detected == "text" else None
            else:
                match = declared in EQUIVALENT_EXTENSIONS.get(detected.rstrip("?"), {detected.rstrip("?")})
            if match is True:
                verdict = "extension matches content"
            elif match is None:
                verdict = "no known signature; inspect manually"
            else:
                verdict = f"MISMATCH: content is {description}; extension .{declared} disguises it"
            rows.append({
                "file": self._rel(path, context), "declared_extension": declared or "(none)",
                "detected_type": detected or "unknown", "description": description,
                "signature_hex": " ".join(f"{b:02X}" for b in head[:16]), "header_offset": "0x00000000",
                "match": {True: "yes", False: "no", None: "unknown"}[match], "conclusion": verdict,
            })
        output = context.folder("results") / "file_signature_analysis.csv"
        with output.open("w", encoding="utf-8", newline="") as stream:
            writer = csv.DictWriter(stream, fieldnames=list(rows[0]))
            writer.writeheader()
            writer.writerows(rows)
        mismatches = [row for row in rows if row["match"] == "no"]
        section = {"title": "File signature analysis", "table": rows,
                   "paragraphs": [f"{len(rows)} file(s) analysed; {len(mismatches)} extension mismatch(es)."] +
                   [f"{row['file']}: {row['conclusion']} (first bytes {row['signature_hex']})." for row in mismatches]}
        return IntegrationResult(
            verified=True, details={"rows": rows, "mismatches": len(mismatches)},
            evidence=[evidence(output, "File signature analysis table", "csv")],
            checks=[{"type": "csv_rows", "path": "results/file_signature_analysis.csv", "min": len(rows),
                     "columns": ["file", "declared_extension", "signature_hex", "header_offset", "match"]}],
            report_sections=[section],
        )

    def image_signatures(self, parameters: dict[str, Any], context: ExecutionContext) -> IntegrationResult:
        image = self._image(parameters, context)
        data = image.read_bytes()
        rows = []
        markers = [(name, magic, "header") for name, magic, _ in SIGNATURES if len(magic) >= 3] + [
            ("zip-eocd", b"PK\x05\x06", "footer"), ("zip-central", b"PK\x01\x02", "structure"),
            ("png-iend", b"IEND\xaeB`\x82", "footer"), ("pdf-eof", b"%%EOF", "footer"), ("jpg-eoi", b"\xff\xd9", None)]
        for name, magic, role in markers:
            if role is None:
                continue
            for match in re.finditer(re.escape(magic), data):
                rows.append({"type": name, "role": role, "offset_hex": f"0x{match.start():08X}", "offset": match.start(),
                             "bytes": " ".join(f"{b:02X}" for b in data[match.start():match.start() + 16])})
        rows.sort(key=lambda row: int(str(row["offset"])))
        output = context.folder("results") / "image_signature_offsets.csv"
        with output.open("w", encoding="utf-8", newline="") as stream:
            writer = csv.DictWriter(stream, fieldnames=["type", "role", "offset_hex", "offset", "bytes"])
            writer.writeheader()
            writer.writerows(rows)
        return IntegrationResult(
            verified=bool(rows), details={"count": len(rows), "image": self._rel(image, context),
                                          **({} if rows else {"reason": "No known signatures in the image"})},
            evidence=[evidence(output, f"Signature offsets inside {image.name}", "csv")],
            checks=[{"type": "csv_rows", "path": "results/image_signature_offsets.csv", "min": 1}],
            report_sections=[{"title": f"Signatures located in {image.name}", "table": rows[:60]}],
        )

    def hex_view(self, parameters: dict[str, Any], context: ExecutionContext) -> IntegrationResult:
        path = context.resolve(param_str(parameters, "path"), base="input")
        offset = param_int(parameters, "offset", 0)
        length = max(16, min(param_int(parameters, "length", 64), 4096))
        with path.open("rb") as stream:
            stream.seek(offset)
            data = stream.read(length)
        if not data:
            return IntegrationResult.failed(f"No bytes at offset 0x{offset:X} in {path.name}")
        dump = hex_dump(data, offset)
        stem = f"hex_{path.stem}_{offset:08X}"
        text_file = context.save_result(f"{stem}.txt", f"{self._rel(path, context)} @ 0x{offset:08X} ({len(data)} bytes)\n\n{dump}\n")
        items = [evidence(text_file, f"Hex view of {path.name} at 0x{offset:08X}", "file")]
        figure = self._render_hex(dump, context.folder("results") / f"{stem}.png", f"{path.name} @ 0x{offset:08X}")
        if figure is not None:
            items.append(evidence(figure, f"Rendered hex view of {path.name} at 0x{offset:08X}", "figure"))
        return IntegrationResult(
            verified=True, details={"file": self._rel(path, context), "offset": offset, "first_bytes": data[:16].hex(" ")},
            evidence=items, checks=[{"type": "file_exists", "path": self._rel(text_file, context)}],
            report_sections=[{"title": f"Hex view: {path.name} @ 0x{offset:08X}", "code": dump}],
        )

    @staticmethod
    def _render_hex(dump: str, output: Path, title: str) -> Path | None:
        try:
            from PIL import Image, ImageDraw, ImageFont
        except ImportError:
            return None
        lines = [title, ""] + dump.splitlines()
        font: Any
        try:
            font = ImageFont.truetype("consola.ttf", 16)
        except OSError:
            font = ImageFont.load_default()
        width = 12 + max(int(font.getlength(line)) for line in lines) + 12
        height = 12 + 22 * len(lines) + 12
        image = Image.new("RGB", (max(width, 200), height), "white")
        draw = ImageDraw.Draw(image)
        for index, line in enumerate(lines):
            draw.text((12, 12 + 22 * index), line, fill="black", font=font)
        image.save(output)
        return output

    # ------------------------------------------------------------------ carving
    def carve(self, parameters: dict[str, Any], context: ExecutionContext) -> IntegrationResult:
        tool = param_str(parameters, "tool", "builtin") or "builtin"
        image = self._image(parameters, context)
        output_name = param_str(parameters, "output") or f"{tool}_output"
        if Path(output_name).name != output_name:
            raise ValueError("output must be a folder name inside results/")
        output = context.folder("results") / output_name
        if output.exists():
            shutil.rmtree(output)
        types = [str(t).lower() for t in param_list(parameters, "types")]
        if tool == "builtin":
            return self._carve_builtin(image, output, types, parameters, context)
        prefix = self._tool(tool, context)
        if prefix is None:
            return IntegrationResult.blocked_result(
                f"{tool} is not installed natively or in WSL. Install it (WSL: sudo apt install {tool}) "
                "and resume; the built-in carver result is recorded separately.", tool=tool)
        command, mode = prefix
        if tool == "foremost":
            args = command + ["-v"] + (["-T"] if param_bool(parameters, "timestamp") else [])
            if types:
                args += ["-t", ",".join(types)]
            args += ["-i", self._path_for(image, mode), "-o", self._path_for(output, mode)]
        else:
            config = self._scalpel_config(parameters, context)
            args = command + ["-c", self._path_for(config, mode), "-o", self._path_for(output, mode), self._path_for(image, mode)]
        result = run_command(args, cwd=context.workspace, timeout=3600, log_file=self._commands_log(context))
        audit = output / "audit.txt"
        details = {"tool": tool, "mode": mode, **result.to_dict()}
        if result.exit_code != 0 or not audit.is_file():
            return IntegrationResult.failed(f"{tool} failed (exit {result.exit_code}); see logs/commands.jsonl", **details)
        carved = [p for p in output.rglob("*") if p.is_file() and p.name != "audit.txt"]
        audit_copy = context.save_result(f"{tool}_audit.txt", audit.read_text(encoding="utf-8", errors="replace"))
        return IntegrationResult(
            verified=True, details={**details, "files": len(carved), "output": self._rel(output, context)},
            evidence=[evidence(audit_copy, f"{tool} audit log", "log")] +
                     [evidence(p, f"{tool} recovered {p.name}", "file") for p in carved[:50]],
            checks=[{"type": "file_exists", "path": self._rel(audit, context)},
                    {"type": "command_exit_code", "key": "exit_code", "equals": 0}],
        )

    def _scalpel_config(self, parameters: dict[str, Any], context: ExecutionContext) -> Path:
        source = param_str(parameters, "config")
        text = context.resolve(source, base="input").read_text(encoding="utf-8", errors="replace") if source else ""
        enable = {str(t).lower() for t in param_list(parameters, "enable_types")}
        lines = []
        for line in text.splitlines():
            stripped = line.lstrip("#").strip()
            parts = stripped.split()
            if line.strip().startswith("#") and parts and parts[0].lower() in enable and len(parts) >= 4:
                lines.append(stripped)
            else:
                lines.append(line)
        if not text:
            lines = ["png y 5000000 \\x89\\x50\\x4e\\x47\\x0d\\x0a\\x1a\\x0a \\x49\\x45\\x4e\\x44\\xae\\x42\\x60\\x82",
                     "pdf y 10000000 \\x25\\x50\\x44\\x46 \\x25\\x25\\x45\\x4f\\x46",
                     "jpg y 20000000 \\xff\\xd8\\xff \\xff\\xd9"]
        target = context.folder("results") / "my_scalpel.conf"
        target.write_text("\n".join(lines) + "\n", encoding="utf-8")
        return target

    def _carve_builtin(self, image: Path, output: Path, types: list[str], parameters: dict[str, Any],
                       context: ExecutionContext) -> IntegrationResult:
        config = param_str(parameters, "config")
        if config:
            conf_path = self._scalpel_config(parameters, context)
            rules = parse_scalpel_conf(conf_path.read_text(encoding="utf-8"))
        else:
            rules = list(DEFAULT_RULES)
        if types:
            aliases = {"jpeg": "jpg"}
            wanted = {aliases.get(t, t) for t in types}
            rules = [rule for rule in rules if rule.extension in wanted]
        if not rules:
            return IntegrationResult.failed("No carving rules selected")
        data = image.read_bytes()
        output.mkdir(parents=True, exist_ok=True)
        carved: list[dict[str, Any]] = []
        for rule in rules:
            for match in re.finditer(re.escape(rule.header), data):
                start = match.start()
                window = data[start:start + rule.max_size]
                end: int | None
                if rule.extension == "zip":
                    end = _eocd_end(window)
                elif rule.footer:
                    position = window.find(rule.footer, len(rule.header))
                    end = None if position < 0 else position + len(rule.footer)
                    if end is not None and rule.extension == "pdf":
                        while end < len(window) and window[end:end + 1] in {b"\r", b"\n"}:
                            end += 1
                else:
                    end = None
                if end is None:
                    continue
                blob = window[:end]
                folder = output / rule.extension
                folder.mkdir(exist_ok=True)
                name = f"{start // 512:08d}.{rule.extension}"
                (folder / name).write_bytes(blob)
                carved.append({"name": f"{rule.extension}/{name}", "offset": start, "size": len(blob),
                               "valid": self._validate_blob(rule.extension, blob)})
        audit_lines = [
            "lab-agent built-in carver (header/footer)", f"Invocation: carve image={image.name} rules={[r.extension for r in rules]}",
            f"Start: {datetime.now(UTC).isoformat()}", f"Image size: {len(data)} bytes", "",
            f"{'Num':<5} {'Name (bs=512)':<22} {'Size':>10} {'File Offset':>12}  Comment", ""]
        for index, row in enumerate(carved):
            audit_lines.append(f"{index:<5} {row['name']:<22} {row['size']:>10} {row['offset']:>12}  "
                               f"{'valid' if row['valid'] else 'INVALID/partial'}")
        audit_lines += ["", f"{len(carved)} FILES EXTRACTED"]
        (output / "audit.txt").write_text("\n".join(audit_lines) + "\n", encoding="utf-8")
        audit_copy = context.save_result("builtin_carver_audit.txt", "\n".join(audit_lines) + "\n")
        return IntegrationResult(
            verified=bool(carved),
            details={"tool": "builtin", "files": carved, "output": self._rel(output, context),
                     **({} if carved else {"reason": "no files carved"})},
            evidence=[evidence(audit_copy, "Built-in carver audit log", "log")] +
                     [evidence(output / row["name"], f"Carved {row['name']} at offset 0x{row['offset']:X}", "file") for row in carved],
            checks=[{"type": "file_exists", "path": self._rel(output / "audit.txt", context)},
                    {"type": "dir_not_empty", "path": self._rel(output, context), "min": len(carved) + 1}],
            report_sections=[{"title": "Built-in carving results",
                              "table": [{**row, "offset": f"0x{row['offset']:08X}"} for row in carved]}],
        )

    @staticmethod
    def _validate_blob(extension: str, blob: bytes) -> bool:
        try:
            if extension in {"jpg", "png", "gif", "bmp"}:
                from PIL import Image

                with Image.open(io.BytesIO(blob)) as picture:
                    picture.verify()
                return True
            if extension == "pdf":
                from pypdf import PdfReader

                return len(PdfReader(io.BytesIO(blob)).pages) > 0
            if extension == "zip":
                with zipfile.ZipFile(io.BytesIO(blob)) as archive:
                    return archive.testzip() is None
        except Exception:  # noqa: BLE001 - invalid carved data
            return False
        return True

    def hash_directory(self, parameters: dict[str, Any], context: ExecutionContext) -> IntegrationResult:
        directories = [context.resolve(str(d)) for d in param_list(parameters, "directories")] or sorted(
            p for p in (context.workspace / "results").glob("*_output") if p.is_dir())
        rows = []
        for directory in directories:
            tool = directory.name.removesuffix("_output")
            for path in sorted(p for p in directory.rglob("*") if p.is_file() and p.name != "audit.txt"):
                blob = path.read_bytes()
                offset_match = re.match(r"^(\d{8})", path.stem)
                rows.append({
                    "tool": tool, "file": self._rel(path, context), "type": path.suffix.lstrip("."), "size": len(blob),
                    "sha256": sha256_file(path),
                    "estimated_offset": f"0x{int(offset_match.group(1)) * 512:08X}" if offset_match else "",
                    "status": "valid" if self._validate_blob(path.suffix.lstrip(".").lower(), blob) else "invalid/partial",
                })
        if not rows:
            return IntegrationResult.failed("No recovered files to hash; run a carving step first.")
        output = context.folder("results") / "recovered_files_sha256.csv"
        with output.open("w", encoding="utf-8", newline="") as stream:
            writer = csv.DictWriter(stream, fieldnames=list(rows[0]))
            writer.writeheader()
            writer.writerows(rows)
        return IntegrationResult(
            verified=True, details={"count": len(rows)},
            evidence=[evidence(output, "SHA-256 of recovered files", "csv")],
            checks=[{"type": "csv_rows", "path": "results/recovered_files_sha256.csv", "min": len(rows), "columns": ["sha256"]}]
            + [{"type": "hash_match", "path": row["file"], "expected": row["sha256"]} for row in rows[:25]],
            report_sections=[{"title": "Recovered files", "table": rows}],
        )

    def compare_results(self, parameters: dict[str, Any], context: ExecutionContext) -> IntegrationResult:
        directories = [context.resolve(str(d)) for d in param_list(parameters, "directories")] or sorted(
            p for p in (context.workspace / "results").glob("*_output") if p.is_dir())
        found: dict[str, dict[str, Any]] = {}
        tools = [d.name.removesuffix("_output") for d in directories]
        for directory, tool in zip(directories, tools, strict=True):
            for path in sorted(p for p in directory.rglob("*") if p.is_file() and p.name != "audit.txt"):
                digest = sha256_file(path)
                entry = found.setdefault(digest, {"sha256": digest, "type": path.suffix.lstrip("."),
                                                  "size": path.stat().st_size, "found_by": {}, "names": []})
                entry["found_by"].setdefault(tool, 0)
                entry["found_by"][tool] += 1
                entry["names"].append(self._rel(path, context))
        if not found:
            return IntegrationResult.failed("Nothing to compare; carving outputs are empty.")
        rows = []
        for entry in found.values():
            row = {"sha256": entry["sha256"], "type": entry["type"], "size": entry["size"]}
            for tool in tools:
                row[tool] = entry["found_by"].get(tool, 0)
            missing = [tool for tool in tools if not entry["found_by"].get(tool)]
            duplicates = [tool for tool, count in entry["found_by"].items() if count > 1]
            agreement = ("only one tool produced output" if len(tools) == 1 else
                         "found by all tools" if not missing else f"not found by {', '.join(missing)}")
            row["explanation"] = agreement + (
                f"; duplicates in {', '.join(duplicates)}" if duplicates else "")
            row["files"] = "; ".join(entry["names"])
            rows.append(row)
        output = context.folder("results") / "comparison_results.csv"
        with output.open("w", encoding="utf-8", newline="") as stream:
            writer = csv.DictWriter(stream, fieldnames=list(rows[0]))
            writer.writeheader()
            writer.writerows(rows)
        return IntegrationResult(
            verified=True, details={"unique_files": len(rows), "tools": tools},
            evidence=[evidence(output, "Comparison of carving tools by SHA-256", "csv")],
            checks=[{"type": "csv_rows", "path": "results/comparison_results.csv", "min": 1, "columns": ["sha256", "explanation"]}],
            report_sections=[{"title": "Comparison of carving results", "table": rows}],
        )

    # ------------------------------------------------------------------ fragments
    def repair_zip_fragments(self, parameters: dict[str, Any], context: ExecutionContext) -> IntegrationResult:
        image = self._image(parameters, context)
        offsets = [int(str(o), 0) for o in param_list(parameters, "offsets")]
        if len(offsets) < 1:
            raise ValueError("offsets must list at least one cluster offset")
        cluster = param_int(parameters, "cluster_size", 4096)
        output_name = param_str(parameters, "output", "evidence_fixed.zip") or "evidence_fixed.zip"
        with image.open("rb") as stream:
            fragments = []
            for offset in offsets:
                stream.seek(offset)
                fragments.append(bytearray(stream.read(cluster)))
        original_header = bytes(fragments[0][:4])
        fragments[0][0:4] = b"PK\x03\x04"
        last = bytes(fragments[-1])
        end = _eocd_end(last)
        if end is None:
            return IntegrationResult.failed("No End Of Central Directory record (50 4B 05 06) in the last fragment.")
        eocd_offset = last.rfind(b"PK\x05\x06")
        prefix = b"".join(bytes(f) for f in fragments[:-1])
        # The EOCD records where the central directory starts and how long it is.  Whatever sits
        # between the end of that directory and the EOCD is file-system slack: keeping it pushes the
        # EOCD further out, and every reader then looks for the directory at the wrong offset.  Zero
        # padding is dropped; non-zero bytes are kept, because silently discarding data that might be
        # evidence is worse than producing an archive that fails its own consistency check.
        directory_size = int.from_bytes(last[eocd_offset + 12:eocd_offset + 16], "little")
        directory_start = int.from_bytes(last[eocd_offset + 16:eocd_offset + 20], "little") - len(prefix)
        slack = (last[directory_start + directory_size:eocd_offset]
                 if 0 <= directory_start <= directory_start + directory_size <= eocd_offset else b"")
        dropped = len(slack) if slack and not any(slack) else 0
        tail = last[:directory_start + directory_size] + last[eocd_offset:end] if dropped else last[:end]
        assembled = prefix + tail
        output = context.save_result(output_name, assembled)
        script = context.save_result("carve_script_completed.py", (
            "#!/usr/bin/env python3\n\"\"\"Manual carving generated and executed by lab-agent.\"\"\"\n\n"
            "def perform_manual_carving(image_path, output_path):\n"
            f"    offsets = {[hex(o) for o in offsets]}\n    cluster_size = {cluster}\n"
            "    with open(image_path, 'rb') as img:\n        fragments = []\n"
            "        for offset in offsets:\n            img.seek(int(offset, 16))\n            fragments.append(bytearray(img.read(cluster_size)))\n"
            "    fragments[0][0:4] = b'PK\\x03\\x04'  # restore local file header\n"
            "    prefix = b''.join(bytes(f) for f in fragments[:-1])\n"
            "    last = bytes(fragments[-1])\n    eocd = last.rfind(b'PK\\x05\\x06')\n"
            "    comment_len = int.from_bytes(last[eocd + 20:eocd + 22], 'little')\n"
            "    end = eocd + 22 + comment_len\n"
            "    directory_size = int.from_bytes(last[eocd + 12:eocd + 16], 'little')\n"
            "    directory_start = int.from_bytes(last[eocd + 16:eocd + 20], 'little') - len(prefix)\n"
            "    slack = last[directory_start + directory_size:eocd]\n"
            "    if slack and not any(slack):  # drop zero slack between the directory and the EOCD\n"
            "        tail = last[:directory_start + directory_size] + last[eocd:end]\n"
            "    else:\n        tail = last[:end]\n"
            "    with open(output_path, 'wb') as out:\n        out.write(prefix + tail)\n\n\n"
            "if __name__ == '__main__':\n"
            f"    perform_manual_carving('{image.name}', '{output_name}')\n"))
        try:
            with zipfile.ZipFile(output) as archive:
                bad = archive.testzip()
                members = archive.namelist()
        except zipfile.BadZipFile as exc:
            kept = len(slack) if slack and not dropped else 0
            note = (f" {kept} non-zero bytes between the central directory and the End Of Central Directory were kept "
                    "because they may be evidence; inspect them in the hex view before removing them by hand."
                    if kept else "")
            return IntegrationResult.failed(f"Reassembled file is not a valid ZIP: {exc}.{note}",
                                            slack_bytes_dropped=dropped, slack_bytes_kept=kept)
        details = {
            "original_header_hex": original_header.hex(" ").upper(), "restored_header_hex": "50 4B 03 04",
            "eocd_offset_in_last_fragment": eocd_offset, "eocd_absolute_offset": f"0x{offsets[-1] + eocd_offset:08X}",
            "logical_end_in_last_fragment": end, "size": len(assembled), "members": members, "crc_ok": bad is None,
            "slack_bytes_dropped": dropped,
        }
        section = {"title": "Manual reassembly of the fragmented ZIP", "paragraphs": [
            f"Fragment 1 at 0x{offsets[0]:08X} started with {details['original_header_hex']}; restored to 50 4B 03 04 (ZIP local file header).",
            (f"End Of Central Directory found at 0x{offsets[-1] + eocd_offset:08X} (byte {eocd_offset} of the last fragment); "
             f"the archive logically ends at byte {end} of that fragment (EOCD + 22 bytes + comment)."),
            *([(f"The End Of Central Directory declares the central directory at offset {directory_start + len(prefix)} "
                f"with a length of {directory_size} bytes, so {dropped} zero bytes of file-system slack separated that "
                f"directory from the record. They were left out of the archive: keeping them would move the End Of "
                f"Central Directory {dropped} bytes further out and every reader would look for the directory at the "
                f"wrong offset.")] if dropped else []),
            f"Result {output_name}: {len(assembled)} bytes, members {members}, CRC check {'passed' if bad is None else 'FAILED'}."]}
        return IntegrationResult(
            verified=bad is None, details={**details, **({} if bad is None else {"reason": f"CRC error in {bad}"})},
            evidence=[evidence(output, "Reassembled ZIP archive", "archive"), evidence(script, "Completed carving script", "file")],
            checks=[{"type": "zip_valid", "path": f"results/{output_name}"}],
            report_sections=[section],
        )

    # ------------------------------------------------------------------ Sleuth Kit
    def tsk(self, parameters: dict[str, Any], context: ExecutionContext) -> IntegrationResult:
        command = param_str(parameters, "command")
        image = self._image(parameters, context)
        args = [str(a) for a in param_list(parameters, "args")]
        if any(re.search(r"[;&|`$<>]", a) for a in args):
            raise PermissionError("TSK arguments may not contain shell metacharacters")
        prefix = self._tool(command, context)
        if prefix is None:
            return IntegrationResult.blocked_result(
                f"The Sleuth Kit '{command}' is not installed (Windows: add sleuthkit\\bin to PATH or set "
                "LAB_AGENT_TSK_PATH; WSL: sudo apt install sleuthkit).", command=command)
        base, mode = prefix
        result = run_command(base + args + [self._path_for(image, mode)], cwd=context.workspace, timeout=1800,
                             log_file=self._commands_log(context))
        output = context.save_result(f"tsk_{command}.txt", f"$ {command} {' '.join(args)} {image.name}\n"
                                     f"exit code: {result.exit_code}\n\n{result.stdout}\n{result.stderr}")
        details = {"command": command, "mode": mode, **result.to_dict()}
        if result.exit_code != 0:
            details["reason"] = f"{command} exited with {result.exit_code}: {result.stderr.strip()[:300]}"
        return IntegrationResult(
            verified=result.exit_code == 0, details=details,
            evidence=[evidence(output, f"TSK {command} output", "command_output")],
            checks=[{"type": "command_exit_code", "key": "exit_code", "equals": 0}],
        )

    # ------------------------------------------------------------------ records
    def case_records(self, parameters: dict[str, Any], context: ExecutionContext) -> IntegrationResult:
        config = context.config
        report = getattr(config, "report", None)
        case_id = param_str(parameters, "case_id") or getattr(report, "case_id", "") or f"CASE-{context.assignment}"
        examiner = param_str(parameters, "examiner") or getattr(report, "student_name", "") or "(examiner name not configured)"
        manifest = input_manifest(context.workspace)
        results = context.folder("results")
        with (results / "case_context.csv").open("w", encoding="utf-8", newline="") as stream:
            writer = csv.writer(stream)
            writer.writerow(["field", "value"])
            writer.writerows([["case_id", case_id], ["assignment", context.assignment], ["examiner", examiner],
                              ["student_id", getattr(report, "student_id", "")], ["group", getattr(report, "group", "")],
                              ["workspace", str(context.workspace)], ["created_at", datetime.now(UTC).isoformat()]])
            for entry in manifest:
                writer.writerow([f"input:{Path(str(entry['source'])).name}:sha256", entry["sha256"]])
        custody_rows = []
        for entry in manifest:
            name = Path(str(entry["source"])).name
            custody_rows.append([entry.get("acquired_at", ""), name, "acquired: copied original into workspace/input",
                                 examiner, entry["sha256"], str(entry["source"])])
        events_file = context.workspace / "logs" / "execution.jsonl"
        if events_file.is_file():
            for line in events_file.read_text(encoding="utf-8").splitlines():
                try:
                    record = json.loads(line)
                except json.JSONDecodeError:
                    continue
                custody_rows.append([record.get("timestamp", ""), record.get("capability", ""),
                                     f"step {record.get('step_id')}: {record.get('outcome', '')}", "lab-agent",
                                     "", record.get("summary", "")[:200]])
        with (results / "chain_of_custody.csv").open("w", encoding="utf-8", newline="") as stream:
            writer = csv.writer(stream)
            writer.writerow(["timestamp", "item", "action", "by", "sha256", "note"])
            writer.writerows(custody_rows)
        commands = []
        log = context.workspace / "logs" / "commands.jsonl"
        if log.is_file():
            for line in log.read_text(encoding="utf-8").splitlines():
                try:
                    record = json.loads(line)
                except json.JSONDecodeError:
                    continue
                commands.append(f"# {record.get('timestamp', '')} exit={record.get('exit_code')}\n{' '.join(map(str, record.get('command', [])))}")
        if not commands:
            commands.append("# No external commands were executed; all analysis used lab-agent built-in functions.")
        (results / "commands.txt").write_text("\n\n".join(commands) + "\n", encoding="utf-8")
        return IntegrationResult(
            verified=True, details={"case_id": case_id, "custody_rows": len(custody_rows), "commands": len(commands)},
            evidence=[evidence(results / "case_context.csv", "Case context", "csv"),
                      evidence(results / "chain_of_custody.csv", "Chain of custody", "csv"),
                      evidence(results / "commands.txt", "Command log", "file")],
            checks=[{"type": "csv_rows", "path": "results/chain_of_custody.csv", "min": max(1, len(manifest))},
                    {"type": "csv_rows", "path": "results/case_context.csv", "min": 3},
                    {"type": "file_exists", "path": "results/commands.txt"}],
        )

    # ------------------------------------------------------------------ planning
    def plan_templates(self, analysis: Any, registry: Any) -> list[dict[str, Any]]:
        """Deterministic workflow for carving / signature assignments with a raw image."""
        images = [f for f in getattr(analysis, "files", []) if f.role == "evidence_image"]
        corpus = "\n".join(analysis.extracted_text_files.values()).lower()
        if not images or not any(word in corpus for word in ("carv", "карвинг", "foremost", "scalpel", "signature", "сигнатур")):
            return []
        image_file = images[0]
        image = Path(image_file.path.split("::")[-1]).name
        image_path = image_file.workspace_path or f"input/{image}"
        checksum = next((f for f in analysis.files if f.role == "checksum" and Path(f.path.split("::")[-1]).name.startswith(image)), None)
        sha_param = {"expected_file": checksum.workspace_path} if checksum is not None and checksum.workspace_path else {}
        config_file = next((f for f in analysis.files if f.path.lower().endswith("scalpel.conf")), None)
        config = config_file.workspace_path if config_file is not None else ""
        steps: list[dict[str, Any]] = []

        def add(title: str, action: str, parameters: dict[str, Any], **extra: Any) -> int:
            steps.append({"title": title, "action": action, "parameters": parameters, **extra})
            return len(steps)

        s_hash = add(f"Verify SHA-256 of {image} before examination", "forensics.verify_image_hash",
                     {"image": image_path, "label": "before", **sha_param},
                     evidence_type="hash", requirement="Проверка контрольного значения исходного образа")
        s_copy = add("Create verified working copy of the image", "forensics.working_copy", {"image": image_path},
                     depends_on=[s_hash], evidence_type="hash")
        add("Analyse file signatures vs extensions", "forensics.signature_scan", {}, evidence_type="csv",
            requirement="Анализ файловых сигнатур, расширений и Hex-заголовков")
        suspicious = [f for f in analysis.files if f.role == "suspicious" and f.workspace_path]
        for item in suspicious[:3]:
            add(f"Hex view of {Path(item.workspace_path).name} header (real type vs extension)", "forensics.hex_view",
                {"path": item.workspace_path, "offset": 0, "length": 64}, evidence_type="figure",
                requirement="Результаты Hex-анализа: путь к файлу, смещение, показанные байты")
        add("Locate file signatures inside the raw image", "forensics.image_signatures",
            {"image": f"working/evidence_copy/{image}"}, depends_on=[s_copy], evidence_type="csv")
        carve_steps = [add("Carve PDF and JPG with the built-in carver (reference result)", "forensics.carve",
                           {"tool": "builtin", "image": f"working/evidence_copy/{image}", "types": "pdf,jpg,png,zip",
                            "output": "builtin_output"}, depends_on=[s_copy], evidence_type="log")]
        if "foremost" in corpus:
            carve_steps.append(add("Run Foremost for PDF and JPG", "forensics.carve",
                                   {"tool": "foremost", "image": f"working/evidence_copy/{image}", "types": "pdf,jpg",
                                    "output": "foremost_output"}, depends_on=[s_copy], evidence_type="log",
                                   requirement="Запуск Foremost с документированными параметрами"))
        if "scalpel" in corpus:
            carve_steps.append(add("Run Scalpel with PNG enabled in the configuration", "forensics.carve",
                                   {"tool": "scalpel", "image": f"working/evidence_copy/{image}", "enable_types": "png",
                                    "output": "scalpel_output", **({"config": config} if config else {})},
                                   depends_on=[s_copy], evidence_type="log",
                                   requirement="Настройка и запуск Scalpel"))
        # The reference carver is enough to hash and compare; the external carvers are waited for (in any
        # outcome) so that their files are included, and a later resume rebuilds both lists.
        s_rec = add("Hash all recovered files", "forensics.hash_directory", {}, depends_on=[carve_steps[0]],
                    run_after=carve_steps[1:], evidence_type="csv", requirement="SHA-256 восстановленных файлов")
        add("Compare carving results between tools", "forensics.compare_results", {}, depends_on=[s_rec], evidence_type="csv",
            requirement="Сравнение результатов Foremost, Scalpel и Autopsy")
        offsets = re.findall(r"0x00?([0-9a-f]{6,8})", corpus)
        cluster_offsets = sorted({int(o, 16) for o in offsets if int(o, 16) % 512 == 0 and int(o, 16) > 0})
        if "zip" in corpus and len(cluster_offsets) >= 2:
            for offset in cluster_offsets[:2]:
                add(f"Hex view of cluster at 0x{offset:08X}", "forensics.hex_view",
                    {"path": f"working/evidence_copy/{image}", "offset": hex(offset), "length": 64},
                    depends_on=[s_copy], evidence_type="figure")
            add("Reassemble the fragmented ZIP (repair header, trim at EOCD)", "forensics.repair_zip_fragments",
                {"image": f"working/evidence_copy/{image}", "offsets": ",".join(hex(o) for o in cluster_offsets[:2]),
                 "cluster_size": 4096, "output": "evidence_fixed.zip"}, depends_on=[s_copy], evidence_type="archive")
        if any(w in corpus for w in ("sleuth", "tsk", "fls")):
            add("Inspect file system with TSK fsstat", "forensics.tsk", {"command": "fsstat", "image": f"working/evidence_copy/{image}"},
                depends_on=[s_copy], evidence_type="command_output", required=False)
        if "autopsy" in corpus and registry.has("autopsy.ingest"):
            add("Autopsy: create case, add data source and run ingest", "autopsy.ingest",
                {"data_source": f"working/evidence_copy/{image}"}, depends_on=[s_copy], evidence_type="log",
                requirement="Корректное исследование образа в Autopsy")
            add("Autopsy: verify case database and export results", "autopsy.inspect_results", {}, depends_on=[len(steps)],
                evidence_type="csv")
        s_after = add(f"Verify SHA-256 of {image} after examination (SOURCE_UNCHANGED)", "forensics.verify_image_hash",
                      {"image": image_path, "label": "after", **sha_param},
                      run_after=[i + 1 for i in range(len(steps))], evidence_type="hash")
        add("Write case context, chain of custody and command log", "forensics.case_records", {}, run_after=[s_after],
            evidence_type="csv", requirement="Цепочка хранения")
        if getattr(analysis, "questions", None):
            add("Student answers to the analytical questions", "core.manual_review",
                {"reason": "The analytical questions require the student's own written answers; the agent does not write them."},
                required=True)
        return steps


def create_adapters(services: Any) -> list[ForensicsAdapter]:
    return [ForensicsAdapter()]
