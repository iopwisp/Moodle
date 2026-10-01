"""Burp Suite integration for local / explicitly authorized web labs.

Burp Community exposes no API, so every step is verified by an *observable*
effect instead of trusting the GUI:

* ``configure_proxy`` / ``wait_for_proxy`` - the listener answers on the port
  and ``http://burp/`` through the proxy returns Burp's own page;
* ``send_request`` - a request to an authorized target goes through the
  proxy and its response is saved;
* ``intercept_request`` - with Intercept on, a request through the proxy does
  *not* complete (it is held by Burp); ``forward_request`` then releases it and
  the response arrives - both states are measured;
* ``send_to_repeater`` / ``capture_evidence`` - profile hotkeys + window screenshot.
"""

from __future__ import annotations

import socket
import threading
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Any

from ..policy import PolicyEngine
from .base import (
    AppSpec,
    BaseIntegration,
    Capability,
    ExecutionContext,
    IntegrationResult,
    Param,
    evidence,
    param_float,
    param_int,
    param_str,
)
from .web_story import BurpNarration

BURP_SPEC = AppSpec(
    "burp", "Burp Suite", env_var="LAB_AGENT_BURP_PATH",
    executables=("BurpSuiteCommunity.exe", "BurpSuite.exe", "BurpSuitePro.exe", "burpsuite"),
    install_globs=("BurpSuite*/BurpSuite*.exe", "BurpSuiteCommunity/BurpSuiteCommunity.exe"),
    registry_name_re=r"Burp Suite", capabilities=("burp.*",),
)
PORT = Param("port", "int", False, "proxy listener port (default 8080)")


def port_open(port: int, host: str = "127.0.0.1", timeout: float = 1.5) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(timeout)
        return sock.connect_ex((host, port)) == 0


def fetch_via_proxy(url: str, port: int, timeout: float = 20, method: str = "GET", body: bytes | None = None) -> dict[str, Any]:
    proxy = f"http://127.0.0.1:{port}"
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({"http": proxy, "https": proxy}))
    request = urllib.request.Request(url, data=body, method=method, headers={"User-Agent": "lab-agent/0.3 (authorized lab)"})
    started = time.monotonic()
    try:
        with opener.open(request, timeout=timeout) as response:
            content = response.read(200_000)
            return {"status": response.status, "headers": dict(response.headers), "body": content.decode("utf-8", "replace"),
                    "seconds": round(time.monotonic() - started, 3)}
    except urllib.error.HTTPError as exc:
        return {"status": exc.code, "headers": dict(exc.headers or {}), "body": exc.read(200_000).decode("utf-8", "replace"),
                "seconds": round(time.monotonic() - started, 3)}


@dataclass
class PendingRequest:
    url: str
    port: int
    started: float = field(default_factory=time.monotonic)
    result: dict[str, Any] | None = None
    error: str | None = None
    thread: threading.Thread | None = None

    def run(self, timeout: float) -> None:
        def worker() -> None:
            try:
                self.result = fetch_via_proxy(self.url, self.port, timeout=timeout)
            except Exception as exc:  # noqa: BLE001
                self.error = f"{type(exc).__name__}: {exc}"

        self.thread = threading.Thread(target=worker, daemon=True)
        self.thread.start()


class BurpAdapter(BurpNarration, BaseIntegration):
    name = "burp"
    APPLICATIONS = (BURP_SPEC,)
    CAPABILITIES = (
        Capability("burp.launch", "burp", "Start Burp Suite (temporary project, default settings) and wait for its window",
                   (PORT,), ("screenshot",), "Burp window visible", requires=("app:burp",), keywords=("burp",)),
        Capability("burp.configure_proxy", "burp", "Ensure the Burp proxy listener is active on 127.0.0.1:<port>",
                   (PORT,), ("json",), "listener accepts connections and http://burp/ is served by Burp",
                   requires=("app:burp",), keywords=("proxy", "прокси")),
        Capability("burp.wait_for_proxy", "burp", "Wait until the proxy listener answers", (PORT, Param("timeout", "float")),
                   ("json",), "listener accepts connections"),
        Capability("burp.open_target", "burp", "Open an authorized URL in a browser routed through Burp",
                   (Param("url", "url", True), PORT), ("screenshot",), "page loaded through the proxy", network=True),
        Capability("burp.send_request", "burp", "Send an HTTP request to an authorized target through the proxy and save the response",
                   (Param("url", "url", True), PORT, Param("method", "str", choices=("GET", "POST", "HEAD"))), ("json",),
                   "response received through Burp and recorded", network=True),
        Capability("burp.intercept_request", "burp",
                   "With Intercept ON, send a request and prove Burp holds it (request does not complete)",
                   (Param("url", "url", True), PORT, Param("hold_seconds", "float")), ("screenshot", "json"),
                   "request still pending after hold_seconds while Burp window shows it", network=True,
                   keywords=("intercept", "перехват")),
        Capability("burp.forward_request", "burp", "Forward the held request (profile hotkey) and prove it completes",
                   (Param("timeout", "float"),), ("json",), "held request completes with an HTTP response"),
        Capability("burp.send_to_repeater", "burp", "Send the selected request to Repeater (profile hotkey) and capture it",
                   (), ("screenshot",), "Repeater tab visible", requires=("app:burp",), keywords=("repeater",)),
        Capability("burp.inspect_response", "burp", "Check the last recorded response for expected status/text",
                   (Param("expected_status", "int"), Param("expected_text", "str")), ("json",),
                   "recorded response matches the expectation"),
        Capability("burp.capture_evidence", "burp", "Screenshot of the Burp window", (Param("name", "str"),), ("screenshot",),
                   "valid window screenshot", requires=("app:burp",)),
    )

    def __init__(self, config: Any = None) -> None:
        self.config = config
        self.pending: PendingRequest | None = None
        self.last_response: dict[str, Any] | None = None

    def _app(self, context: ExecutionContext) -> Any:
        from ..applications import ManagedApplication

        return ManagedApplication("burp", context, spec=BURP_SPEC)

    def _port(self, parameters: dict[str, Any]) -> int:
        return param_int(parameters, "port", 8080)

    def _check_scope(self, url: str, context: ExecutionContext) -> None:
        from ..config import get_config

        if not PolicyEngine(context.config or self.config or get_config(), context.allowed_targets).url_allowed(url):
            raise PermissionError(f"{url} is not an authorized target")

    def _burp_page(self, port: int) -> tuple[bool, str]:
        try:
            response = fetch_via_proxy("http://burp/", port, timeout=10)
        except Exception as exc:  # noqa: BLE001
            return False, str(exc)
        return ("Burp Suite" in response["body"]), f"HTTP {response['status']}"

    # ------------------------------------------------------------------ lifecycle
    def launch(self, parameters: dict[str, Any], context: ExecutionContext) -> IntegrationResult:
        """Start Burp and wait until its proxy listener is up.

        Verified on Burp Suite Community 2026.8 / Windows 11: the start-up wizard (Temporary project ->
        Next -> Start Burp) is a Swing dialog that UI Automation cannot see unless the Java Access Bridge
        is enabled, and the proxy only starts after it. If the listener does not come up, the step is
        BLOCKED with instructions instead of being reported as done.
        """
        app = self._app(context)
        port = self._port(parameters)
        args = [] if app.running_window() is not None else ["--disable-auto-update"]
        app.launch(args)
        if app.has_operation("start_temporary_project"):
            app.run_operation("start_temporary_project")
        deadline = time.monotonic() + param_float(parameters, "timeout", float(app.profile.get("proxy_wait_seconds", 20)))
        while not port_open(port) and time.monotonic() < deadline:
            context.sleep(1)
        picture = app.screenshot(f"burp_launch_{context.stamp()}.png")
        items = [evidence(picture, "Burp Suite window", "screenshot")]
        if not port_open(port):
            return IntegrationResult.blocked_result(
                f"Burp is open but the proxy on 127.0.0.1:{port} is not listening. In the Burp window choose "
                "'Temporary project' -> Next -> 'Use Burp defaults' -> 'Start Burp', then resume; the agent verifies "
                "the proxy through http://burp/.", port=port)
        return IntegrationResult(True, {"window": app.driver.window_title(app.window) if app.window is not None else "",
                                        "port": port}, items,
                                 checks=[{"type": "image_valid", "path": str(picture)}, {"type": "port_open", "port": port}])

    def wait_for_proxy(self, parameters: dict[str, Any], context: ExecutionContext) -> IntegrationResult:
        port = self._port(parameters)
        deadline = time.monotonic() + param_float(parameters, "timeout", 60)
        while not port_open(port):
            if time.monotonic() > deadline:
                return IntegrationResult.failed(f"Nothing is listening on 127.0.0.1:{port}")
            context.sleep(1)
        output = context.save_result("burp_proxy.json", {"port": port, "listening": True})
        return IntegrationResult(True, {"port": port}, [evidence(output, "Proxy listener check", "json")],
                                 checks=[{"type": "port_open", "port": port}])

    def configure_proxy(self, parameters: dict[str, Any], context: ExecutionContext) -> IntegrationResult:
        port = self._port(parameters)
        waited = self.wait_for_proxy(parameters, context)
        if not waited.verified:
            return waited
        is_burp, detail = self._burp_page(port)
        output = context.save_result("burp_proxy_config.json", {"listener": f"127.0.0.1:{port}", "burp_page": is_burp,
                                                                "detail": detail})
        return IntegrationResult(is_burp, {"port": port, "burp_page": is_burp,
                                           **({} if is_burp else {"reason": f"Port {port} is open but is not Burp ({detail})"})},
                                 [evidence(output, "Burp proxy listener verification", "json")],
                                 checks=[{"type": "port_open", "port": port},
                                         {"type": "details_value", "key": "burp_page", "equals": True}])

    # ------------------------------------------------------------------ traffic
    def send_request(self, parameters: dict[str, Any], context: ExecutionContext) -> IntegrationResult:
        url, port = param_str(parameters, "url"), self._port(parameters)
        self._check_scope(url, context)
        method = param_str(parameters, "method", "GET") or "GET"
        response = fetch_via_proxy(url, port, method=method)
        self.last_response = {"url": url, "method": method, **response}
        output = context.save_result(f"burp_response_{context.step_id or 0:02d}.json", self.last_response)
        return IntegrationResult(True, {"url": url, "status": response["status"]},
                                 [evidence(output, f"Response for {method} {url} through Burp", "json")],
                                 checks=[{"type": "details_value", "key": "status", "min": 100, "max": 599}])

    def open_target(self, parameters: dict[str, Any], context: ExecutionContext) -> IntegrationResult:
        url, port = param_str(parameters, "url"), self._port(parameters)
        self._check_scope(url, context)
        from .browser import BrowserAdapter

        browser = BrowserAdapter(context.config or self.config)
        session = browser.ensure_session(context, proxy=f"http://127.0.0.1:{port}")
        try:
            status = session.goto(url)
            picture = context.folder("screenshots") / f"burp_target_{context.stamp()}.png"
            session.page.screenshot(path=str(picture), full_page=True)
            title = session.page.title()
        finally:
            browser.shutdown()
        ok = status is not None and status < 500
        return IntegrationResult(ok, {"url": url, "status": status, "title": title, **({} if ok else {"reason": f"HTTP {status}"})},
                                 [evidence(picture, f"{url} loaded through Burp", "screenshot")],
                                 checks=[{"type": "image_valid", "path": str(picture)}])

    def intercept_request(self, parameters: dict[str, Any], context: ExecutionContext) -> IntegrationResult:
        url, port = param_str(parameters, "url"), self._port(parameters)
        self._check_scope(url, context)
        hold = param_float(parameters, "hold_seconds", 4)
        app = self._app(context)
        if app.has_operation("intercept_on"):
            app.launch()
            app.run_operation("intercept_on")
        self.pending = PendingRequest(url, port)
        self.pending.run(timeout=300)
        context.sleep(hold)
        held = self.pending.result is None and self.pending.error is None
        items = []
        if app.running_window() is not None:
            picture = app.screenshot(f"burp_intercept_{context.stamp()}.png")
            items.append(evidence(picture, "Burp Proxy > Intercept holding the request", "screenshot"))
        record = context.save_result("burp_intercept.json", {"url": url, "held": held, "hold_seconds": hold,
                                                             "completed_early": self.pending.result is not None,
                                                             "error": self.pending.error})
        items.append(evidence(record, "Interception measurement", "json"))
        reason = {} if held else {"reason": "The request completed immediately - Intercept is off or the proxy is not Burp"}
        return IntegrationResult(held, {"url": url, "held": held, **reason}, items,
                                 checks=[{"type": "details_value", "key": "held", "equals": True}])

    def forward_request(self, parameters: dict[str, Any], context: ExecutionContext) -> IntegrationResult:
        if self.pending is None or self.pending.thread is None:
            return IntegrationResult.failed("No intercepted request is pending; run burp.intercept_request first.")
        app = self._app(context)
        if not app.has_operation("forward"):
            return IntegrationResult.blocked_result("The Burp profile declares no 'forward' operation for this version.")
        app.launch()
        app.run_operation("forward")
        timeout = param_float(parameters, "timeout", 30)
        self.pending.thread.join(timeout)
        response = self.pending.result
        ok = response is not None
        if response is not None:
            self.last_response = {"url": self.pending.url, **response}
        record = context.save_result("burp_forwarded.json", {"url": self.pending.url, "completed": ok,
                                                             "response": response, "error": self.pending.error})
        return IntegrationResult(ok, {"completed": ok, "status": (response or {}).get("status"),
                                      **({} if ok else {"reason": "Held request did not complete after forwarding"})},
                                 [evidence(record, "Forwarded request result", "json")])

    def send_to_repeater(self, parameters: dict[str, Any], context: ExecutionContext) -> IntegrationResult:
        app = self._app(context)
        if not app.has_operation("send_to_repeater"):
            return IntegrationResult.blocked_result("The Burp profile declares no 'send_to_repeater' operation.")
        app.launch()
        app.run_operation("send_to_repeater")
        picture = app.screenshot(f"burp_repeater_{context.stamp()}.png")
        return IntegrationResult(True, {}, [evidence(picture, "Request sent to Repeater", "screenshot")],
                                 checks=[{"type": "image_valid", "path": str(picture)}])

    def inspect_response(self, parameters: dict[str, Any], context: ExecutionContext) -> IntegrationResult:
        if not self.last_response:
            return IntegrationResult.failed("No response has been recorded in this run.")
        status_ok = "expected_status" not in parameters or self.last_response["status"] == param_int(parameters, "expected_status", 200)
        text = param_str(parameters, "expected_text")
        text_ok = not text or text in self.last_response.get("body", "")
        ok = status_ok and text_ok
        output = context.save_result(f"burp_inspection_{context.step_id or 0:02d}.json",
                                     {"status": self.last_response["status"], "status_ok": status_ok, "text_ok": text_ok,
                                      "headers": self.last_response.get("headers", {})})
        return IntegrationResult(ok, {"status": self.last_response["status"], **({} if ok else {"reason": "response mismatch"})},
                                 [evidence(output, "Response inspection", "json")])

    def capture_evidence(self, parameters: dict[str, Any], context: ExecutionContext) -> IntegrationResult:
        app = self._app(context)
        if app.running_window() is None:
            return IntegrationResult.failed("The Burp window is not open.")
        picture = app.screenshot(param_str(parameters, "name") or f"burp_{context.stamp()}.png")
        return IntegrationResult(True, {}, [evidence(picture, "Burp Suite window", "screenshot")],
                                 checks=[{"type": "image_valid", "path": str(picture)}])

    def shutdown(self) -> None:
        self.pending = None


def create_adapters(services: Any) -> list[BurpAdapter]:
    return [BurpAdapter(services.config)]
