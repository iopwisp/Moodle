"""Assignment analysis: read every supplied file, classify it and extract requirements.

Supported text sources: PDF, DOCX, TXT, MD, CSV, JSON and ZIP archives (their
documents are read in memory; binary members such as ``evidence.dd`` are
classified and later extracted into ``working/extracted/``).  Other files are
kept as inputs and classified by extension and magic bytes.
"""

from __future__ import annotations

import csv
import hashlib
import io
import json
import re
import zipfile
from pathlib import Path, PurePosixPath
from xml.etree import ElementTree

from .logging_setup import get_logger
from .models import AssignmentAnalysis, ExecutionPlan, InputFile, PlannedTask

SUPPORTED = {".pdf", ".docx", ".txt", ".md", ".csv", ".json", ".zip"}
TEXT_MEMBER_TYPES = {".txt", ".md", ".csv", ".json", ".conf", ".cfg", ".ini", ".py", ".sha256", ".md5", ".yaml", ".yml", ".tex"}
JUNK = re.compile(r"(^|/)(__MACOSX|\.DS_Store|Thumbs\.db|desktop\.ini)(/|$)|(^|/)\._", re.IGNORECASE)
MAX_MEMBER_BYTES = 20_000_000

TOOL_PATTERNS: dict[str, tuple[str, ...]] = {
    "PowerShell": ("powershell", "get-filehash", "command prompt"),
    "Python": ("python", "script", "programming"),
    "Hex editor": ("hex workshop", "hex-редактор", "hex editor", "mhex"),
}
ROLE_BY_SUFFIX = {
    **{s: "evidence_image" for s in (".dd", ".raw", ".img", ".001", ".e01", ".vmdk", ".vhd", ".vhdx", ".aff", ".bin")},
    **{s: "checksum" for s in (".sha256", ".sha1", ".md5")},
    **{s: "capture" for s in (".pcap", ".pcapng", ".cap")},
    **{s: "config" for s in (".conf", ".cfg", ".ini", ".yaml", ".yml")},
    **{s: "script" for s in (".py", ".ps1", ".sh", ".bat")},
    **{s: "project" for s in (".pkt", ".pka", ".tex", ".bib")},
    **{s: "image" for s in (".png", ".jpg", ".jpeg", ".gif", ".bmp")},
}
SCREENSHOT_TERMS = ("screenshot", "screen shot", "скриншот", "снимок экрана")
EVIDENCE_TERMS = SCREENSHOT_TERMS + ("evidence", "proof", "verify", "hash", "capture")
OUTPUT_TERMS = ("submit", "deliverable", "save as", "report", "output file", "представить", "отчёт", "отчет", "сдач")
VERIFY_TERMS = ("verify", "verification", "провер", "убедит", "самоконтрол", "must", "должен", "критери")
COMMAND_RE = re.compile(
    r"^\s*(?:\$\s*|#\s*|PS>\s*)?(?:sudo\s+)?(foremost|scalpel|fls|icat|istat|fsstat|mmls|blkcat|dd|ping|ipconfig|tshark|"
    r"python3?|Get-FileHash|certutil|sha256sum|md5sum|show\s+\w+|configure\s+terminal|ip\s+address|interface\s+\S+)\b.*",
    re.IGNORECASE)
STEP_RE = re.compile(r"^\s*(?:step|шаг|часть|part|task|задание|задача)\s*№?\s*(\d+(?:\.\d+)*)\s*[:.)\-–]?\s*(.*)$", re.IGNORECASE)
NUMBERED_RE = re.compile(r"^\s*(?:\d{1,2}[.)]|[-*•])\s*(?=\S)")
FILENAME_RE = re.compile(r"\b[\w\-]+\.(?:csv|txt|docx|pdf|html?|pkt|pka|pcapng|pcap|zip|conf|png|jpe?g|py|json|xlsx|dd|e01|tex)\b",
                         re.IGNORECASE)
URL_RE = re.compile(r"https?://[^\s<>()\[\]{}\"']+")
HEX64_RE = re.compile(r"\b[0-9a-fA-F]{64}\b")


def get_tool_patterns() -> dict[str, tuple[str, ...]]:
    """Tool detection keywords: built-in list plus every integration's capability keywords."""
    patterns = dict(TOOL_PATTERNS)
    try:
        from .config import get_config
        from .integrations.registry import build_registry

        registry = build_registry(config=get_config())
        for adapter in registry.adapters():
            names = [spec.display_name for spec in getattr(adapter, "applications", list)()] or [adapter.name]
            keywords = {kw.lower() for cap in adapter.capabilities() for kw in cap.keywords}
            for spec in getattr(adapter, "applications", list)():
                keywords.add(spec.display_name.lower())
            if keywords:
                patterns.setdefault(names[0], tuple(sorted(keywords)))
    except Exception as exc:  # noqa: BLE001 - analysis must work even if a plugin is broken
        get_logger("analyzer").warning("integration keywords unavailable: %s", exc)
    return patterns


def _docx_bytes_text(data: bytes) -> str:
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        root = ElementTree.fromstring(archive.read("word/document.xml"))
    ns = {"w": "http://schemas.openxmlformats.org/wordprocessingml/2006/main"}
    return "\n".join("".join(node.itertext()) for node in root.findall(".//w:p", ns))


def _docx_text(path: Path) -> str:
    return _docx_bytes_text(path.read_bytes())


def _pdf_bytes_text(data: bytes) -> str:
    try:
        from pypdf import PdfReader
    except ImportError as exc:
        raise ValueError("PDF extraction requires the optional 'documents' extra: pip install -e .[documents]") from exc
    return "\n".join(page.extract_text() or "" for page in PdfReader(io.BytesIO(data)).pages)


def _pdf_text(path: Path) -> str:
    return _pdf_bytes_text(path.read_bytes())


def _decode(data: bytes) -> str:
    for encoding in ("utf-8-sig", "cp1251"):
        try:
            return data.decode(encoding)
        except UnicodeDecodeError:
            continue
    return data.decode("utf-8", errors="replace")


def _text_from_bytes(name: str, data: bytes) -> str:
    suffix = PurePosixPath(name).suffix.lower()
    if suffix == ".docx":
        return _docx_bytes_text(data)
    if suffix == ".pdf":
        return _pdf_bytes_text(data)
    if suffix == ".csv":
        return "\n".join(" | ".join(row) for row in csv.reader(io.StringIO(_decode(data))))
    if suffix == ".json":
        return json.dumps(json.loads(_decode(data)), ensure_ascii=False, indent=2)
    return _decode(data)


def extract_text(path: Path) -> str:
    suffix = path.suffix.lower()
    if suffix not in SUPPORTED - {".zip"} and suffix not in TEXT_MEMBER_TYPES:
        raise ValueError(f"Unsupported assignment format: {suffix or '(no extension)'}")
    return _text_from_bytes(path.name, path.read_bytes())


def _looks_binary(data: bytes) -> bool:
    return b"\x00" in data[:4096] or data[:8] in {b"\x89PNG\r\n\x1a\n"}


def _role(name: str, head: bytes, text: str | None) -> tuple[str, str]:
    lowered = name.lower()
    suffix = PurePosixPath(lowered).suffix
    if lowered.endswith((".pcap.gz",)):
        return "capture", ""
    if suffix in {".docx", ".pdf"} and text is not None:
        instruction = re.search(r"assignment|lab|лаборатор|задани|practical|практич", lowered + " " + text[:3000], re.IGNORECASE)
        return ("assignment" if instruction else "reference"), ""
    if suffix in ROLE_BY_SUFFIX:
        role = ROLE_BY_SUFFIX[suffix]
        if suffix in {".txt", ".log"}:
            role = "reference"
        return role, ""
    if suffix in {".txt", ".md", ".log"}:
        if head and _looks_binary(head):
            return "suspicious", "extension says text but content is binary"
        if re.search(r"readme|reference|справочник|памятка|guide", lowered):
            return "reference", ""
        return ("assignment" if re.search(r"assignment|lab|задани", lowered) else "reference"), ""
    if suffix in {".csv", ".json"}:
        return "data", ""
    return "other", ""


class _Collector:
    def __init__(self) -> None:
        self.files: list[InputFile] = []
        self.texts: dict[str, str] = {}
        self.hashes: dict[str, str] = {}
        self._names: dict[str, str] = {}  # workspace path -> sha256 prefix

    def workspace_path(self, name: str, digest: str, archive: str | None, member: str | None) -> str:
        if archive is not None and member is not None:
            clean = PurePosixPath(member)
            return f"working/extracted/{Path(archive).stem}/{clean.as_posix()}"
        candidate = f"input/{name}"
        if candidate in self._names and self._names[candidate] != digest[:8]:
            candidate = f"input/{Path(name).stem}_{digest[:8]}{Path(name).suffix}"
        self._names[candidate] = digest[:8]
        return candidate

    def add(self, display: str, name: str, data: bytes, *, archive: str | None = None, member: str | None = None,
            source: str | None = None) -> None:
        digest = hashlib.sha256(data).hexdigest()
        text: str | None = None
        suffix = PurePosixPath(name).suffix.lower()
        if suffix in {".docx", ".pdf"} or (suffix in TEXT_MEMBER_TYPES and not _looks_binary(data[:4096])):
            try:
                text = _text_from_bytes(name, data)
            except Exception as exc:  # noqa: BLE001 - keep going, record the failure
                text = f"[Extraction failed: {exc}]"
        role, note = _role(name, data[:4096], text)
        path = self.workspace_path(name, digest, archive, member)
        self.files.append(InputFile(path=source or display, role=role, size=len(data), note=note, archive=archive,
                                    workspace_path=path, sha256=digest))
        if text is not None:
            self.texts[display] = text
            for match in HEX64_RE.findall(text):
                self.hashes.setdefault(display, match.lower())


def analyze(paths: list[Path]) -> AssignmentAnalysis:
    if not paths:
        raise ValueError("Provide at least one assignment file or directory.")
    files: list[Path] = []
    for path in paths:
        if not path.exists():
            raise FileNotFoundError(path)
        candidates = sorted(p for p in path.rglob("*") if p.is_file()) if path.is_dir() else [path]
        files.extend(p for p in candidates if not JUNK.search(p.as_posix()))
    readable = [p for p in files if p.suffix.lower() in SUPPORTED]
    if not readable:
        raise ValueError("No supported assignment files found (.pdf, .docx, .txt, .md, .csv, .json, .zip).")

    collector = _Collector()
    limitations = ["Text extraction is deterministic. A configured AI planner may refine the execution plan after this first pass."]
    for file in files:
        if file.suffix.lower() == ".zip":
            data = file.read_bytes()
            collector.files.append(InputFile(path=str(file.resolve()), role="archive", size=len(data),
                                             workspace_path=collector.workspace_path(file.name, hashlib.sha256(data).hexdigest(), None, None),
                                             sha256=hashlib.sha256(data).hexdigest()))
            try:
                with zipfile.ZipFile(io.BytesIO(data)) as archive:
                    inventory = []
                    for member in archive.infolist():
                        if member.is_dir() or JUNK.search(member.filename):
                            continue
                        inventory.append(f"[ZIP member: {member.filename} | {member.file_size} bytes]")
                        if member.flag_bits & 0x1:
                            limitations.append(f"Encrypted ZIP member skipped: {member.filename}")
                            continue
                        if member.file_size > MAX_MEMBER_BYTES and PurePosixPath(member.filename).suffix.lower() not in ROLE_BY_SUFFIX:
                            continue
                        blob = archive.read(member) if member.file_size <= 2_000_000_000 else b""
                        collector.add(f"{file.resolve()}::{member.filename}", PurePosixPath(member.filename).name, blob,
                                      archive=str(file.resolve()), member=member.filename,
                                      source=f"{file.resolve()}::{member.filename}")
                    collector.texts.setdefault(str(file.resolve()), "\n".join(inventory))
            except (zipfile.BadZipFile, OSError) as exc:
                collector.texts[str(file.resolve())] = f"[Extraction failed: {exc}]"
            continue
        data = file.read_bytes()
        collector.add(str(file), file.name, data, source=str(file.resolve()))

    extracted = {key: value for key, value in collector.texts.items()}
    documents = [text for key, text in extracted.items() if not text.startswith("[ZIP member") and not text.startswith("[Extraction")]
    corpus = "\n".join(documents) or "\n".join(extracted.values())
    lines = [line.rstrip() for line in corpus.splitlines()]
    lower = corpus.lower()

    # An assignment with explicit sub-task structure ("Task 3.1", "Задача 2.1", ...) is a handful of tasks, not
    # one requirement per prose bullet: keep one line per dotted task number so the plan mirrors the real tasks
    # instead of exploding every background/objective/appendix bullet into a step.
    dotted_tasks: dict[str, str] = {}
    for line in lines:
        match = STEP_RE.match(line)
        if match and match.group(1) and "." in match.group(1):
            title = re.sub(r"^[\s—–:.)\-]+", "", match.group(2)).strip().rstrip(",;")
            if len(title) >= 8:
                dotted_tasks.setdefault(match.group(1), f"Task {match.group(1)}: {title}")
    if len(dotted_tasks) >= 2:
        req_lines = list(dotted_tasks.values())
    else:
        req_lines = [NUMBERED_RE.sub("", line).strip(" \t-*•") for line in lines
                     if NUMBERED_RE.match(line) and len(line.strip()) > 3]
        if not req_lines:
            req_lines = [line.strip() for line in lines if len(line.strip()) > 20][:30]
    sections = []
    for line in lines:
        match = STEP_RE.match(line)
        if match:
            sections.append({"number": match.group(1), "title": match.group(2).strip() or line.strip()})
    tools = [name for name, words in get_tool_patterns().items() if any(term in lower for term in words)]
    screenshot_requirements = [line.strip() for line in lines if any(t in line.lower() for t in SCREENSHOT_TERMS)]
    expected_outputs = [line.strip() for line in lines if any(t in line.lower() for t in OUTPUT_TERMS)]
    commands = list(dict.fromkeys(line.strip() for line in lines if COMMAND_RE.match(line)))
    input_names = {Path(f.path.split("::")[-1]).name.lower() for f in collector.files}
    deliverables = list(dict.fromkeys(m for m in FILENAME_RE.findall(corpus) if m.lower() not in input_names))
    questions = [line.strip() for line in lines if line.strip().endswith("?") and len(line.strip()) > 25]
    criteria = [line.strip() for line in lines if any(t in line.lower() for t in VERIFY_TERMS) and len(line.strip()) > 15][:60]
    title_source = next((text for key, text in extracted.items()
                         if any(f.role == "assignment" and (f.path == key or key.endswith(f.path)) for f in collector.files)), corpus)
    title = next((line.strip().lstrip("# ") for line in title_source.splitlines() if len(line.strip()) > 10), "")
    objective = extract_objective(title_source.splitlines()) or extract_objective(lines) or next(
        (line.strip().lstrip("# ") for line in lines if len(line.strip()) > 20), "Review the supplied assignment materials")
    if any(value.startswith("[Extraction failed:") for value in extracted.values()):
        limitations.append("At least one file could not be extracted; inspect the analysis JSON before execution.")
    suspicious = [f for f in collector.files if f.role == "suspicious"]
    if suspicious:
        limitations.append("Files whose extension does not match their content: " + ", ".join(Path(f.path).name for f in suspicious))
    readable_sources = [p for p in readable]
    name = readable_sources[0].parent.name if len(files) > 1 else readable_sources[0].stem
    return AssignmentAnalysis(
        assignment=name, source_files=[str(p.resolve()) for p in files], objective=objective[:500], tools=tools,
        requirements=req_lines[:100], screenshot_requirements=screenshot_requirements[:50],
        expected_outputs=expected_outputs[:50], limitations=limitations, extracted_text_files=extracted,
        title=title[:300], files=collector.files, sections=sections[:80], steps=[s["title"] for s in sections][:80],
        commands=commands[:80], deliverables=deliverables[:80], verification_criteria=criteria,
        urls=list(dict.fromkeys(u.rstrip(".,;") for u in URL_RE.findall(corpus)))[:40], hashes=collector.hashes,
        questions=questions[:60],
    )


OBJECTIVE_RE = re.compile(r"^\s*(?:\d+[.)]\s*)?(?:#+\s*)?(цел[ьи](?:\s+(?:лабораторной\s+)?работы)?|learning\s+objectives?|"
                          r"objectives?|goals?|aims?|purpose)\s*[:.\-–—]?\s*(.*)$", re.IGNORECASE)
SECTION_START_RE = re.compile(r"^\s*(?:#+\s*)?(?:часть|раздел|задани|ход\s|порядок|теор|практ|оборудован|материал|требован|"
                              r"исходн|сценари|кейс|легенд|введени|part\b|section|task|procedure|theory|equipment|materials|"
                              r"requirements|deliverables|scenario|background|introduction|case\b)", re.IGNORECASE)
LEADING_SYMBOLS_RE = re.compile(r"^[^\w«\"(]+")


def extract_objective(lines: list[str]) -> str:
    """The text of the "Objective" / "Цель работы" section, joined into one sentence-like string."""
    for index, line in enumerate(lines):
        match = OBJECTIVE_RE.match(line)
        if not match or len(line.strip()) > 400:
            continue
        parts = [match.group(2).strip()] if match.group(2).strip() else []
        numbered = False
        for following in lines[index + 1:index + 12]:
            text = following.strip()
            if not text:
                if parts:
                    break
                continue
            words = LEADING_SYMBOLS_RE.sub("", text)  # emoji or bullets in front of a heading
            if SECTION_START_RE.match(words) or OBJECTIVE_RE.match(words):
                break
            item = bool(NUMBERED_RE.match(text))
            if numbered and not item:  # the numbered list of goals has ended
                break
            numbered = numbered or item
            parts.append(NUMBERED_RE.sub("", text).strip(" \t-*•"))
        parts = [p.rstrip(".;") for p in parts if p]
        parts = parts[:1] + [p[0].lower() + p[1:] if len(p) > 1 and p[1].islower() else p for p in parts[1:]]
        if parts:
            return "; ".join(parts)[:600] + "."
    return ""


def build_plan(analysis: AssignmentAnalysis) -> ExecutionPlan:
    """Transparent first-pass plan: one reviewable task per requirement (no capability guessing).

    The capability-aware planner in :mod:`lab_agent.ai` replaces this plan; it is kept
    for ``lab-agent analyze`` and for readers who want the raw requirement checklist.
    """
    steps: list[PlannedTask] = []
    for index, requirement in enumerate(analysis.requirements, start=1):
        lowered = requirement.lower()
        evidence_required = any(term in lowered for term in EVIDENCE_TERMS)
        evidence_type = ("screenshot" if any(term in lowered for term in SCREENSHOT_TERMS)
                         else "hash" if "hash" in lowered or "sha256" in lowered else None)
        steps.append(PlannedTask(
            id=index, title=requirement[:120], description=requirement,
            tool=next((name.lower().replace(" ", "_") for name in analysis.tools if name.lower() in lowered), "manual"),
            action="core.manual_review", evidence_required=evidence_required, evidence_type_required=evidence_type,
            expected_result="Requirement addressed with a verifiable result",
            verification="Review the result and record supporting evidence",
            evidence_path=f"evidence/step_{index:02d}" if evidence_required else None, requirement_refs=[requirement[:200]],
        ))
    if not steps:
        steps = [PlannedTask(id=1, title="Review assignment materials", description=analysis.objective)]
    return ExecutionPlan(assignment=analysis.assignment, objective=analysis.objective, steps=steps,
                         source_files=analysis.source_files, planner="checklist")
