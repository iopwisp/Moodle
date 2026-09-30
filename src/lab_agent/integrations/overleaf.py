"""Overleaf integration (web, through the shared Playwright session).

Selectors live in ``profiles/overleaf.yaml`` (versioned) because the Overleaf
UI changes over time.  The Overleaf host must be authorized before the run
(``policy.network.authorized_targets`` or ``--allowed-target www.overleaf.com``).
Credentials are read from ``LAB_AGENT_OVERLEAF_EMAIL`` /
``LAB_AGENT_OVERLEAF_PASSWORD`` (environment or OS keyring) and never logged.
If Overleaf shows a captcha or SSO page the run waits in the headed browser for
the student to finish it and otherwise reports BLOCKED.
"""

from __future__ import annotations

import time
import zipfile
from pathlib import Path
from typing import Any
from urllib.parse import urljoin

from ..credentials import get_secret
from .base import (
    BaseIntegration,
    Capability,
    CapabilityBlocked,
    ExecutionContext,
    IntegrationResult,
    Param,
    evidence,
    param_float,
    param_list,
    param_str,
)

DEFAULT_SELECTORS = {
    "base_url": "https://www.overleaf.com",
    "email": "input[name='email']",
    "password": "input[name='password']",
    "submit": "button[type='submit']",
    "logged_in_url": "/project",
    "new_project": "button:has-text('New project'), button:has-text('New Project')",
    "upload_project": "text=Upload project",
    "file_input": "input[type='file']",
    "recompile": "button:has-text('Recompile')",
    "compile_error": ".log-entry-header-error, [data-testid='log-entry-error']",
    "download_pdf": "a[aria-label='Download PDF'], a:has-text('Download PDF')",
    "pdf_viewer": ".pdf-viewer, .pdfjs-viewer",
    "editor": ".cm-content, #editor",
}


def _profile() -> dict[str, Any]:
    try:
        from ..desktop.profiles import load_profile

        return load_profile("overleaf")
    except (FileNotFoundError, RuntimeError):
        return {}


class OverleafAdapter(BaseIntegration):
    name = "overleaf"
    CAPABILITIES = (
        Capability("overleaf.open", "overleaf", "Open Overleaf in the browser session", (), ("screenshot",),
                   "Overleaf page loaded", network=True, keywords=("overleaf",)),
        Capability("overleaf.login", "overleaf", "Log in with credentials from the environment/keyring", (), (),
                   "project dashboard reached", network=True),
        Capability("overleaf.create_project", "overleaf", "Create a project by uploading a zip of the LaTeX sources",
                   (Param("source_dir", "path", False, "folder with main.tex; default: all .tex/.bib/figures in input"),
                    Param("name", "str")), ("screenshot",), "editor opened for the new project", network=True),
        Capability("overleaf.upload_files", "overleaf", "Upload additional files into the open project",
                   (Param("files", "list", True),), (), "files listed in the project tree", network=True),
        Capability("overleaf.edit_files", "overleaf", "Replace the content of the open document in the editor",
                   (Param("path", "path", True, "local file whose content is typed into the open editor"),), (),
                   "editor contains the new text", network=True),
        Capability("overleaf.compile", "overleaf", "Recompile the project", (), ("screenshot",), "no compile errors listed",
                   network=True, keywords=("compile", "компил")),
        Capability("overleaf.wait_compile", "overleaf", "Wait until the PDF preview is ready", (Param("timeout", "float"),), (),
                   "PDF preview visible", network=True),
        Capability("overleaf.download_pdf", "overleaf", "Download the compiled PDF to results/", (Param("name", "str"),), ("pdf",),
                   "downloaded file is a readable PDF", network=True),
        Capability("overleaf.verify_pdf", "overleaf", "Validate a PDF in results/ (pages, expected text)",
                   (Param("path", "path"), Param("expected_text", "str")), ("pdf",), "PDF readable and contains the text"),
    )

    def __init__(self, config: Any = None) -> None:
        self.config = config
        self.selectors = {**DEFAULT_SELECTORS, **(_profile().get("selectors") or {})}
        self.project_url: str | None = None
        self._browser: Any = None

    def _session(self, context: ExecutionContext) -> Any:
        if self._browser is None:
            from .browser import BrowserAdapter

            self._browser = BrowserAdapter(context.config or self.config)
        return self._browser.ensure_session(context)

    def _url(self, path: str = "") -> str:
        return urljoin(self.selectors["base_url"].rstrip("/") + "/", path.lstrip("/"))

    def _shot(self, context: ExecutionContext, label: str) -> Path:
        session = self._session(context)
        picture = context.folder("screenshots") / f"overleaf_{label}_{context.stamp()}.png"
        session.page.screenshot(path=str(picture))
        return picture

    def shutdown(self) -> None:
        if self._browser is not None:
            self._browser.shutdown()
            self._browser = None

    # ------------------------------------------------------------------ capabilities
    def open(self, parameters: dict[str, Any], context: ExecutionContext) -> IntegrationResult:
        session = self._session(context)
        status = session.goto(self._url("/project"))
        picture = self._shot(context, "open")
        ok = status is not None and status < 500
        return IntegrationResult(ok, {"url": session.page.url, "status": status}, [evidence(picture, "Overleaf opened", "screenshot")])

    def login(self, parameters: dict[str, Any], context: ExecutionContext) -> IntegrationResult:
        session = self._session(context)
        page = session.page
        if self.selectors["logged_in_url"] in (page.url or "") and "/login" not in page.url:
            return IntegrationResult(True, {"already_logged_in": True})
        email = get_secret("LAB_AGENT_OVERLEAF_EMAIL")
        password = get_secret("LAB_AGENT_OVERLEAF_PASSWORD")
        if not email or not password:
            raise CapabilityBlocked("Set LAB_AGENT_OVERLEAF_EMAIL and LAB_AGENT_OVERLEAF_PASSWORD (environment or OS keyring).")
        session.goto(self._url("/login"))
        page.locator(self.selectors["email"]).first.fill(email)
        page.locator(self.selectors["password"]).first.fill(password)
        page.locator(self.selectors["submit"]).first.click()
        deadline = time.monotonic() + param_float(parameters, "timeout", 180)
        while time.monotonic() < deadline:
            if "/project" in page.url and "/login" not in page.url:
                return IntegrationResult(True, {"url": page.url})
            context.sleep(1)
        raise CapabilityBlocked("Overleaf login did not complete (captcha, SSO or wrong credentials). "
                                "Finish the login in the open browser window and resume.")

    def _project_zip(self, parameters: dict[str, Any], context: ExecutionContext) -> Path:
        source = param_str(parameters, "source_dir")
        folder = context.resolve(source) if source else context.workspace / "input"
        files = [p for p in folder.rglob("*") if p.is_file() and p.suffix.lower() in
                 {".tex", ".bib", ".cls", ".sty", ".png", ".jpg", ".jpeg", ".pdf", ".eps", ".bst"}]
        if not any(p.suffix.lower() == ".tex" for p in files):
            raise FileNotFoundError("No .tex file found for the Overleaf project.")
        name = param_str(parameters, "name") or f"{context.assignment}_overleaf"
        archive = context.folder("working") / f"{name}.zip"
        with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED) as bundle:
            for path in files:
                bundle.write(path, path.relative_to(folder).as_posix())
        return archive

    def create_project(self, parameters: dict[str, Any], context: ExecutionContext) -> IntegrationResult:
        archive = self._project_zip(parameters, context)
        session = self._session(context)
        page = session.page
        session.goto(self._url("/project"))
        if "/login" in page.url:
            raise CapabilityBlocked("Not logged in to Overleaf; run overleaf.login first.")
        page.locator(self.selectors["new_project"]).first.click()
        page.locator(self.selectors["upload_project"]).first.click()
        page.locator(self.selectors["file_input"]).first.set_input_files(str(archive))
        page.wait_for_url("**/project/*", timeout=120_000)
        page.locator(self.selectors["editor"]).first.wait_for(timeout=60_000)
        self.project_url = page.url
        picture = self._shot(context, "project")
        return IntegrationResult(True, {"project_url": page.url, "archive": archive.name},
                                 [evidence(picture, "Overleaf project created", "screenshot")])

    def upload_files(self, parameters: dict[str, Any], context: ExecutionContext) -> IntegrationResult:
        files = [context.resolve(str(f), base="input") for f in param_list(parameters, "files")]
        page = self._session(context).page
        if not self.project_url:
            raise RuntimeError("No Overleaf project is open.")
        page.locator(self.selectors.get("upload_button", "button[aria-label='Upload']")).first.click()
        page.locator(self.selectors["file_input"]).first.set_input_files([str(f) for f in files])
        for file in files:
            page.get_by_text(file.name).first.wait_for(timeout=60_000)
        return IntegrationResult(True, {"uploaded": [f.name for f in files]})

    def edit_files(self, parameters: dict[str, Any], context: ExecutionContext) -> IntegrationResult:
        text = context.resolve(param_str(parameters, "path"), base="input").read_text(encoding="utf-8")
        page = self._session(context).page
        editor = page.locator(self.selectors["editor"]).first
        editor.click()
        page.keyboard.press("Control+A")
        page.keyboard.insert_text(text)
        present = text.strip().splitlines()[0][:40] in editor.inner_text() if text.strip() else True
        return IntegrationResult(present, {"chars": len(text), **({} if present else {"reason": "editor content not updated"})})

    def compile(self, parameters: dict[str, Any], context: ExecutionContext) -> IntegrationResult:
        page = self._session(context).page
        page.locator(self.selectors["recompile"]).first.click()
        waited = self.wait_compile(parameters, context)
        errors = page.locator(self.selectors["compile_error"]).count()
        picture = self._shot(context, "compiled")
        ok = waited.verified and errors == 0
        return IntegrationResult(ok, {"errors": errors, **({} if ok else {"reason": f"{errors} compile error(s) or no PDF preview"})},
                                 [evidence(picture, "Overleaf after compilation", "screenshot")],
                                 checks=[{"type": "details_value", "key": "errors", "equals": 0}])

    def wait_compile(self, parameters: dict[str, Any], context: ExecutionContext) -> IntegrationResult:
        page = self._session(context).page
        try:
            page.locator(self.selectors["pdf_viewer"]).first.wait_for(timeout=int(param_float(parameters, "timeout", 120) * 1000))
        except Exception as exc:  # noqa: BLE001
            return IntegrationResult.failed(f"PDF preview did not appear: {exc}")
        return IntegrationResult(True, {"pdf_preview": True})

    def download_pdf(self, parameters: dict[str, Any], context: ExecutionContext) -> IntegrationResult:
        page = self._session(context).page
        name = Path(param_str(parameters, "name") or f"{context.assignment}_overleaf.pdf").name
        with page.expect_download(timeout=120_000) as info:
            page.locator(self.selectors["download_pdf"]).first.click()
        target = context.folder("results") / name
        info.value.save_as(str(target))
        return self.verify_pdf({"path": f"results/{name}"}, context)

    def verify_pdf(self, parameters: dict[str, Any], context: ExecutionContext) -> IntegrationResult:
        path = context.resolve(param_str(parameters, "path") or f"results/{context.assignment}_overleaf.pdf")
        check: dict[str, Any] = {"type": "pdf_valid", "path": path.relative_to(context.workspace.resolve()).as_posix()}
        if param_str(parameters, "expected_text"):
            check["text_contains"] = param_str(parameters, "expected_text")
        return IntegrationResult(True, {"pdf": check["path"]}, [evidence(path, "Compiled PDF", "pdf")], checks=[check])


def create_adapters(services: Any) -> list[OverleafAdapter]:
    return [OverleafAdapter(services.config)]
