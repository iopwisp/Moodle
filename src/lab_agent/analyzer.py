"""Assignment extraction and a transparent, deterministic first-pass planner."""

from __future__ import annotations

import csv
import json
import re
import zipfile
from pathlib import Path
from xml.etree import ElementTree

from .models import AssignmentAnalysis, ExecutionPlan, PlannedTask

SUPPORTED = {".pdf", ".docx", ".txt", ".md", ".csv", ".json", ".zip"}
TOOL_PATTERNS: dict[str, tuple[str, ...]] = {
    "PowerShell": ("powershell", "get-filehash", "sha256", "command prompt"),
    "Autopsy": ("autopsy", "disk image", "forensic", "ingest"),
    "Burp Suite": ("burp", "proxy", "repeater", "intercept"),
    "Browser": ("browser", "website", "web page", "url", "http"),
    "Python": ("python", "script", "programming"),
}
SCREENSHOT_TERMS = ("screenshot", "screen shot", "скриншот", "снимок экрана")
EVIDENCE_TERMS = SCREENSHOT_TERMS + ("evidence", "proof", "verify", "hash", "capture")
OUTPUT_TERMS = ("submit", "deliverable", "save as", "report", "output file", "представить", "отчёт")


def _docx_text(path: Path) -> str:
    with zipfile.ZipFile(path) as archive:
        root = ElementTree.fromstring(archive.read("word/document.xml"))
    ns = {"w": "http://schemas.openxmlformats.org/wordprocessingml/2006/main"}
    return "\n".join("".join(node.itertext()) for node in root.findall(".//w:p", ns))


def _pdf_text(path: Path) -> str:
    try:
        from pypdf import PdfReader
    except ImportError as exc:
        raise ValueError("PDF extraction requires the optional 'documents' extra: pip install -e .[documents]") from exc
    return "\n".join(page.extract_text() or "" for page in PdfReader(path).pages)


def extract_text(path: Path) -> str:
    suffix = path.suffix.lower()
    if suffix in {".txt", ".md"}:
        return path.read_text(encoding="utf-8-sig", errors="replace")
    if suffix == ".docx":
        return _docx_text(path)
    if suffix == ".pdf":
        return _pdf_text(path)
    if suffix == ".csv":
        with path.open(encoding="utf-8-sig", newline="") as stream:
            return "\n".join(" | ".join(row) for row in csv.reader(stream))
    if suffix == ".json":
        return json.dumps(json.loads(path.read_text(encoding="utf-8-sig")), ensure_ascii=False, indent=2)
    raise ValueError(f"Unsupported assignment format: {suffix or '(no extension)'}")


def _archive_inventory(path: Path) -> str:
    lines: list[str] = []
    with zipfile.ZipFile(path) as archive:
        for item in archive.infolist():
            if item.is_dir():
                continue
            lines.append(f"[ZIP member: {item.filename} | {item.file_size} bytes]")
            if Path(item.filename).suffix.lower() in {".txt", ".md", ".csv", ".json"} and item.file_size <= 1_000_000:
                try:
                    lines.append(archive.read(item).decode("utf-8-sig", errors="replace")[:100_000])
                except (KeyError, OSError, RuntimeError):
                    lines.append("[Could not read member]")
    return "\n".join(lines)


def analyze(paths: list[Path]) -> AssignmentAnalysis:
    if not paths:
        raise ValueError("Provide at least one assignment file or directory.")
    files: list[Path] = []
    readable_files: list[Path] = []
    for path in paths:
        if not path.exists():
            raise FileNotFoundError(path)
        candidates = sorted(p for p in path.rglob("*") if p.is_file()) if path.is_dir() else [path]
        files.extend(candidates)
        readable_files.extend(p for p in candidates if p.suffix.lower() in SUPPORTED)
    if not readable_files:
        raise ValueError("No supported assignment files found (.pdf, .docx, .txt, .md, .csv, .json, .zip).")

    extracted: dict[str, str] = {}
    for file in readable_files:
        try:
            extracted[str(file)] = _archive_inventory(file) if file.suffix.lower() == ".zip" else extract_text(file)
        except (OSError, ValueError, zipfile.BadZipFile, ElementTree.ParseError) as exc:
            extracted[str(file)] = f"[Extraction failed: {exc}]"
    corpus = "\n".join(extracted.values())
    lower = corpus.lower()
    req_lines = [line.strip(" \t-*•") for line in corpus.splitlines() if re.match(r"^\s*(?:\d+[.)]|[-*•])\s+\S", line)]
    if not req_lines:
        req_lines = [line.strip() for line in corpus.splitlines() if len(line.strip()) > 20][:30]
    tools = [name for name, words in TOOL_PATTERNS.items() if any(term in lower for term in words)]
    screenshot_requirements = [line.strip() for line in corpus.splitlines() if any(t in line.lower() for t in SCREENSHOT_TERMS)]
    expected_outputs = [line.strip() for line in corpus.splitlines() if any(t in line.lower() for t in OUTPUT_TERMS)]
    objective = next((line.strip().lstrip("# ") for line in corpus.splitlines() if len(line.strip()) > 20), "Review the supplied assignment materials")
    limitations = ["Text extraction is deterministic. A configured AI planner may refine the execution plan after this first pass."]
    if any(value.startswith("[Extraction failed:") for value in extracted.values()):
        limitations.append("At least one file could not be extracted; inspect the analysis JSON before execution.")
    return AssignmentAnalysis(
        assignment=readable_files[0].parent.name if len(files) > 1 else readable_files[0].stem,
        source_files=[str(p.resolve()) for p in files], objective=objective[:500], tools=tools,
        requirements=req_lines[:100], screenshot_requirements=screenshot_requirements[:50],
        expected_outputs=expected_outputs[:50], limitations=limitations, extracted_text_files=extracted,
    )


def build_plan(analysis: AssignmentAnalysis) -> ExecutionPlan:
    steps = [PlannedTask(
        id=i, title=requirement[:120], description=requirement,
        tool=next((name.lower().replace(" ", "_") for name in analysis.tools if name.lower() in requirement.lower()), "manual"),
        evidence_required=any(term in requirement.lower() for term in EVIDENCE_TERMS),
        evidence_type_required=("screenshot" if any(term in requirement.lower() for term in SCREENSHOT_TERMS)
                                else "hash" if "hash" in requirement.lower() or "sha256" in requirement.lower()
                                else None),
        expected_result="Requirement addressed with a verifiable result", verification="Review the result and record supporting evidence",
        evidence_path=f"evidence/step_{i:02d}" if any(term in requirement.lower() for term in EVIDENCE_TERMS) else None,
    ) for i, requirement in enumerate(analysis.requirements, start=1)]
    if not steps:
        steps = [PlannedTask(id=1, title="Review assignment materials", description=analysis.objective)]
    return ExecutionPlan(assignment=analysis.assignment, objective=analysis.objective, steps=steps, source_files=analysis.source_files)
