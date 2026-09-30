"""Local LaTeX compilation (latexmk / pdflatex / xelatex / tectonic) with log analysis."""

from __future__ import annotations

import shutil
from pathlib import Path
from typing import Any

from ..tools.process import run_command
from .base import (
    AppSpec,
    BaseIntegration,
    Capability,
    ExecutionContext,
    IntegrationResult,
    Param,
    evidence,
    param_str,
)

ENGINES = ("latexmk", "pdflatex", "xelatex", "lualatex", "tectonic")


class LatexAdapter(BaseIntegration):
    name = "latex"
    APPLICATIONS = tuple(AppSpec(engine, engine, executables=(f"{engine}.exe", engine), version_args=("--version",),
                                 install_globs=(f"MiKTeX/miktex/bin/x64/{engine}.exe", f"texlive/*/bin/win64/{engine}.exe"),
                                 capabilities=("latex.compile",)) for engine in ENGINES)
    CAPABILITIES = (
        Capability("latex.compile", "latex", "Compile a .tex document locally and validate the PDF",
                   (Param("main", "path", False, "main .tex file; default: the input .tex containing \\documentclass"),
                    Param("engine", "str", False, choices=ENGINES)),
                   ("pdf", "log"), "engine exit code 0, no '! ' errors in the log, PDF readable",
                   keywords=("latex", "tex", "pdflatex")),
    )

    def _engine(self, requested: str, context: ExecutionContext) -> tuple[str, str] | None:
        for engine in ([requested] if requested else list(ENGINES)):
            path = context.app_path(engine) or shutil.which(engine)
            if path:
                return engine, path
        return None

    def compile(self, parameters: dict[str, Any], context: ExecutionContext) -> IntegrationResult:
        main_value = param_str(parameters, "main")
        main: Path | None
        if main_value:
            main = context.resolve(main_value, base="input")
        else:
            main = next((p for p in sorted((context.workspace / "input").rglob("*.tex"))
                         if "\\documentclass" in p.read_text(encoding="utf-8", errors="ignore")), None)
            if main is None:
                return IntegrationResult.failed("No .tex file with \\documentclass in the inputs.")
        found = self._engine(param_str(parameters, "engine"), context)
        if found is None:
            return IntegrationResult.blocked_result("No LaTeX engine installed (MiKTeX/TeX Live/tectonic); use overleaf.* instead.")
        engine, path = found
        build = context.folder("working") / "latex_build"
        if engine == "latexmk":
            args = [path, "-pdf", "-interaction=nonstopmode", "-halt-on-error", f"-outdir={build}", str(main)]
        elif engine == "tectonic":
            args = [path, "--outdir", str(build), str(main)]
        else:
            args = [path, "-interaction=nonstopmode", "-halt-on-error", f"-output-directory={build}", str(main)]
        result = run_command(args, cwd=main.parent, timeout=600, log_file=context.folder("logs") / "commands.jsonl")
        log_file = build / f"{main.stem}.log"
        log_text = log_file.read_text(encoding="utf-8", errors="replace") if log_file.is_file() else result.stdout
        errors = [line for line in log_text.splitlines() if line.startswith("! ")]
        pdf = build / f"{main.stem}.pdf"
        items = []
        log_copy = context.save_result(f"{main.stem}_latex.log", log_text or result.stderr)
        items.append(evidence(log_copy, f"{engine} log", "log"))
        if pdf.is_file():
            target = context.save_result(f"{main.stem}.pdf", pdf.read_bytes())
            items.append(evidence(target, "Compiled PDF", "pdf"))
        ok = result.exit_code == 0 and not errors and pdf.is_file()
        return IntegrationResult(ok, {"engine": engine, "exit_code": result.exit_code, "errors": errors[:10],
                                      **({} if ok else {"reason": (errors or [f"{engine} exit code {result.exit_code}"])[0]})},
                                 items, checks=[{"type": "pdf_valid", "path": f"results/{main.stem}.pdf"}] if pdf.is_file() else [])

    def plan_templates(self, analysis: Any, registry: Any) -> list[dict[str, Any]]:
        tex = [f for f in getattr(analysis, "files", []) if f.path.lower().endswith(".tex")]
        corpus = "\n".join(analysis.extracted_text_files.values()).lower()
        if not tex or "overleaf" in corpus:
            return []
        return [{"title": f"Compile {Path(tex[0].path).name}", "action": "latex.compile",
                 "parameters": {"main": f"input/{Path(tex[0].path).name}"}, "evidence_type": "pdf"}]



def create_adapters(services: Any) -> list[LatexAdapter]:
    return [LatexAdapter()]
