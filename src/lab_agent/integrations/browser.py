"""Browser integration (Playwright) for authorized web labs.

Targets are limited to localhost and hosts explicitly authorized before the
run.  A single browser session is kept across steps so that login state and
page state carry over.  Headed mode is the default for evidence-oriented labs
(``browser.headless`` in config.yaml).
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from ..credentials import get_secret, redact
from ..policy import PolicyEngine
from .base import (
    BaseIntegration,
    Capability,
    CapabilityBlocked,
    ExecutionContext,
    IntegrationResult,
    Param,
    evidence,
    param_bool,
    param_float,
    param_str,
)
from .sessions import BrowserSession
from .web_story import BrowserNarration

URL = Param("url", "url", True, "http(s) URL on localhost or an authorized host")
SELECTOR = Param("selector", "str", True, "Playwright/CSS selector, e.g. '#login' or 'text=Submit'")


def _cap(name: str, description: str, params: tuple[Param, ...] = (), evidence_types: tuple[str, ...] = (),
         verification: str = "", network: bool = False) -> Capability:
    return Capability(f"browser.{name}", "browser", description, params, evidence_types, verification,
                      network=network, keywords=("browser", "браузер", "http://", "https://", "web", "сайт"))


class BrowserAdapter(BrowserNarration, BaseIntegration):
    name = "browser"
    CAPABILITIES = (
        _cap("launch", "Start the browser session (headed by default)", (Param("headless", "bool"), Param("proxy", "str")), (),
             "browser session is running"),
        _cap("navigate", "Open an authorized URL in the current session", (URL,), ("screenshot",),
             "HTTP status 2xx/3xx and page title recorded", network=True),
        _cap("visit", "Open an authorized URL, record status/title and capture the page", (URL,), ("screenshot",),
             "HTTP status 2xx/3xx; full-page screenshot", network=True),
        _cap("click", "Click an element", (SELECTOR,), (), "element existed and was clicked"),
        _cap("type", "Fill an input (text, or a secret read from an environment variable)",
             (SELECTOR, Param("text", "str"), Param("secret_env", "str", False, "env var holding a credential")), (),
             "input value set"),
        _cap("select", "Choose an option in a <select>", (SELECTOR, Param("value", "str", True)), (), "option selected"),
        _cap("wait_for", "Wait for a selector, visible text or URL fragment",
             (Param("selector", "str"), Param("text", "str"), Param("url_contains", "str"), Param("timeout", "float")), (),
             "condition became true before the timeout"),
        _cap("read_text", "Read text of an element into results/", (SELECTOR, Param("name", "str")), ("json",),
             "text captured"),
        _cap("inspect", "Record URL, title, status and whether expected text/elements exist",
             (Param("expected_text", "str"), Param("selector", "str")), ("json",),
             "expected text/element present on the page"),
        _cap("screenshot", "Capture the current page", (Param("name", "str"), Param("full_page", "bool")), ("screenshot",),
             "valid PNG of the page"),
        _cap("download", "Click a download link and save the file to results/", (SELECTOR, Param("name", "str")), ("file",),
             "downloaded file exists and is non-empty"),
        _cap("upload", "Set a workspace file on a file input", (SELECTOR, Param("path", "path", True)), (), "file attached"),
        _cap("close", "Close the browser session", (), (), "session closed"),
    )

    def __init__(self, config: Any = None) -> None:
        self.config = config
        self.session: BrowserSession | None = None

    # ------------------------------------------------------------------ session
    def _policy(self, context: ExecutionContext) -> PolicyEngine:
        from ..config import get_config

        return PolicyEngine(context.config or self.config or get_config(), context.allowed_targets)

    def ensure_session(self, context: ExecutionContext, *, headless: bool | None = None, proxy: str | None = None) -> BrowserSession:
        if self.session is not None and self.session.active and (proxy is None or proxy == self.session.proxy):
            return self.session
        if self.session is not None:
            self.session.close()
        config = context.config or self.config
        browser_cfg = getattr(config, "browser", None)
        self.session = BrowserSession(
            self._policy(context).url_allowed,
            headless=headless if headless is not None else bool(getattr(browser_cfg, "headless", False)),
            proxy=proxy, timeout_seconds=float(getattr(browser_cfg, "timeout_seconds", 45)),
            allow_external_subresources=bool(getattr(browser_cfg, "allow_external_subresources", True)),
        )
        self.session.start()
        return self.session

    def shutdown(self) -> None:
        if self.session is not None:
            self.session.close()
            self.session = None

    def _page(self, context: ExecutionContext) -> Any:
        if self.session is None or not self.session.active:
            raise RuntimeError("No browser page is open; run browser.navigate first.")
        return self.session.require_page()

    def _shot(self, context: ExecutionContext, name: str, full_page: bool = True) -> Path:
        page = self._page(context)
        output = context.folder("screenshots") / name
        page.screenshot(path=str(output), full_page=full_page)
        return output

    # ------------------------------------------------------------------ capabilities
    def launch(self, parameters: dict[str, Any], context: ExecutionContext) -> IntegrationResult:
        headless = param_bool(parameters, "headless") if "headless" in parameters else None
        session = self.ensure_session(context, headless=headless, proxy=param_str(parameters, "proxy") or None)
        return IntegrationResult(True, {"headless": session.headless, "proxy": session.proxy},
                                 checks=[{"type": "details_value", "key": "headless", "equals": session.headless}])

    def navigate(self, parameters: dict[str, Any], context: ExecutionContext) -> IntegrationResult:
        url = param_str(parameters, "url")
        session = self.ensure_session(context)
        status = session.goto(url)
        page = session.page
        picture = self._shot(context, f"browser_{context.step_id or 0:02d}_{context.stamp()}.png")
        details = {"url": page.url, "requested_url": url, "title": page.title(), "status": status,
                   "blocked_navigations": list(session.blocked_navigations)}
        ok = status is not None and 200 <= status < 400
        if not ok:
            details["reason"] = f"HTTP status {status} for {url}"
        record = context.save_result(f"browser_step_{context.step_id or 0:02d}.json", details)
        return IntegrationResult(ok, details, [evidence(picture, f"Browser: {details['title'] or url}", "screenshot"),
                                               evidence(record, "Page load record", "json")],
                                 checks=[{"type": "image_valid", "path": str(picture)},
                                         {"type": "details_value", "key": "status", "min": 200, "max": 399}])

    def visit(self, parameters: dict[str, Any], context: ExecutionContext) -> IntegrationResult:
        result = self.navigate(parameters, context)
        (context.folder("results") / "browser.json").write_text(json.dumps(result.details, ensure_ascii=False, indent=2),
                                                               encoding="utf-8")
        return result

    def click(self, parameters: dict[str, Any], context: ExecutionContext) -> IntegrationResult:
        page = self._page(context)
        selector = param_str(parameters, "selector")
        page.locator(selector).first.click()
        try:
            page.wait_for_load_state("load", timeout=10_000)
        except Exception:  # noqa: BLE001, S110
            pass
        return IntegrationResult(True, {"selector": selector, "url": page.url},
                                 checks=[{"type": "details_value", "key": "selector", "equals": selector}])

    def type(self, parameters: dict[str, Any], context: ExecutionContext) -> IntegrationResult:
        page = self._page(context)
        selector = param_str(parameters, "selector")
        secret_env = param_str(parameters, "secret_env")
        if secret_env:
            value = get_secret(secret_env)
            if not value:
                raise CapabilityBlocked(f"Credential {secret_env} is not set (environment variable or OS keyring).")
        else:
            value = str(parameters.get("text", ""))
        locator = page.locator(selector).first
        locator.fill(value)
        filled = locator.input_value() == value
        return IntegrationResult(filled, {"selector": selector, "chars": len(value), "secret": bool(secret_env),
                                          **({} if filled else {"reason": "input value did not stick"})})

    def select(self, parameters: dict[str, Any], context: ExecutionContext) -> IntegrationResult:
        page = self._page(context)
        selector, value = param_str(parameters, "selector"), param_str(parameters, "value")
        chosen = page.locator(selector).first.select_option(value)
        return IntegrationResult(bool(chosen), {"selector": selector, "selected": chosen})

    def wait_for(self, parameters: dict[str, Any], context: ExecutionContext) -> IntegrationResult:
        page = self._page(context)
        timeout = int(param_float(parameters, "timeout", 30) * 1000)
        selector, text, fragment = (param_str(parameters, key) for key in ("selector", "text", "url_contains"))
        if selector:
            page.locator(selector).first.wait_for(state="visible", timeout=timeout)
        if text:
            page.get_by_text(text).first.wait_for(state="visible", timeout=timeout)
        if fragment:
            page.wait_for_url(f"**{fragment}**", timeout=timeout)
        if not (selector or text or fragment):
            raise ValueError("browser.wait_for needs selector, text or url_contains")
        return IntegrationResult(True, {"url": page.url, "selector": selector, "text": text})

    def read_text(self, parameters: dict[str, Any], context: ExecutionContext) -> IntegrationResult:
        page = self._page(context)
        selector = param_str(parameters, "selector")
        text = page.locator(selector).first.inner_text()
        name = param_str(parameters, "name") or f"browser_text_{context.step_id or 0:02d}.json"
        output = context.save_result(name if name.endswith(".json") else name + ".json",
                                     {"url": page.url, "selector": selector, "text": redact(text)})
        return IntegrationResult(True, {"selector": selector, "text": redact(text)[:2000]},
                                 [evidence(output, f"Text of {selector}", "json")])

    def inspect(self, parameters: dict[str, Any], context: ExecutionContext) -> IntegrationResult:
        page = self._page(context)
        expected, selector = param_str(parameters, "expected_text"), param_str(parameters, "selector")
        content = page.content()
        details: dict[str, Any] = {"url": page.url, "title": page.title(),
                                   "status": self.session.last_status if self.session else None}
        ok = True
        if expected:
            details["expected_text_found"] = expected in page.inner_text("body")
            ok &= details["expected_text_found"]
        if selector:
            details["selector_count"] = page.locator(selector).count()
            ok &= details["selector_count"] > 0
        details["html_bytes"] = len(content)
        if not ok:
            details["reason"] = "expected text or element not present"
        output = context.save_result(f"browser_inspect_{context.step_id or 0:02d}.json", details)
        return IntegrationResult(ok, details, [evidence(output, "Page inspection", "json")])

    def screenshot(self, parameters: dict[str, Any], context: ExecutionContext) -> IntegrationResult:
        name = param_str(parameters, "name") or f"browser_{context.step_id or 0:02d}_{context.stamp()}.png"
        picture = self._shot(context, name, param_bool(parameters, "full_page", True))
        return IntegrationResult(True, {"url": self._page(context).url}, [evidence(picture, "Browser page", "screenshot")],
                                 checks=[{"type": "image_valid", "path": str(picture)}])

    def download(self, parameters: dict[str, Any], context: ExecutionContext) -> IntegrationResult:
        page = self._page(context)
        with page.expect_download() as info:
            page.locator(param_str(parameters, "selector")).first.click()
        download = info.value
        name = Path(param_str(parameters, "name") or download.suggested_filename).name
        target = context.folder("results") / name
        download.save_as(str(target))
        size = target.stat().st_size if target.is_file() else 0
        return IntegrationResult(size > 0, {"file": f"results/{name}", "size": size},
                                 [evidence(target, f"Downloaded {name}", "file")] if size else [],
                                 checks=[{"type": "file_exists", "path": f"results/{name}"}])

    def upload(self, parameters: dict[str, Any], context: ExecutionContext) -> IntegrationResult:
        page = self._page(context)
        path = context.resolve(param_str(parameters, "path"))
        page.locator(param_str(parameters, "selector")).first.set_input_files(str(path))
        return IntegrationResult(True, {"file": path.name})

    def close(self, parameters: dict[str, Any], context: ExecutionContext) -> IntegrationResult:
        self.shutdown()
        return IntegrationResult(True, {"closed": True})

    def plan_templates(self, analysis: Any, registry: Any) -> list[dict[str, Any]]:
        return []

    # Documentation/reference hosts and placeholder targets a line merely cites, never a page to open.
    _DOC_HOSTS = ("portswigger.net", "developer.mozilla.org", "owasp.org", "w3.org", "wikipedia.org", "rfc-editor.org")
    _PLACEHOLDER = ("your-lab-id", "example.", "attacker.", "victim.", "<", "yourusername")
    _OPEN_VERB = re.compile(r"\b(open|visit|go to|navigate|browse|load|log ?in (?:at|to)|перейд|откр|заход)\b", re.IGNORECASE)

    def match_requirement(self, text: str, analysis: Any) -> tuple[str, dict[str, Any], float] | None:
        urls = re.findall(r"https?://[^\s<>()\[\]{}\"']+", text)
        if not urls:
            return None
        url = urls[0].rstrip(".,;")
        host = re.sub(r"^https?://", "", url).split("/")[0].lower()
        # A reference citation ("Tool — https://...") or a doc/placeholder link is not an instruction to visit;
        # only an explicit "open/visit this URL" line becomes a browser step.
        cited = " — http" in text or " — https" in text or re.match(r"^\s*(references|see also|mdn|appendix)\b", text, re.IGNORECASE)
        if (any(token in url.lower() for token in self._PLACEHOLDER) or any(host.endswith(d) for d in self._DOC_HOSTS)
                or cited or not self._OPEN_VERB.search(text)):
            return None
        return "browser.visit", {"url": url}, 10.0


def create_adapters(services: Any) -> list[BrowserAdapter]:
    return [BrowserAdapter(services.config)]
