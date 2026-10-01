"""Wireshark, browser, Burp and Overleaf integrations.

Wireshark and browser tests run the real tools (tshark, Playwright Chromium)
when they are installed and are skipped otherwise; Burp and Overleaf run
against local stand-ins that reproduce the observable network behaviour.
"""

from __future__ import annotations

import http.server
import shutil
import socket
import socketserver
import struct
import threading
import time
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from fakes import FakeDriver, FakeWindow, fake_screenshot

from lab_agent.integrations.base import ExecutionContext
from lab_agent.tools.process import CommandResult

TSHARK = shutil.which("tshark") or (r"C:\Program Files\Wireshark\tshark.exe" if Path(r"C:\Program Files\Wireshark\tshark.exe").is_file() else None)


def _chromium_available() -> bool:
    try:
        from playwright.sync_api import sync_playwright

        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            browser.close()
        return True
    except Exception:  # noqa: BLE001
        return False


CHROMIUM = _chromium_available()


def build_pcap(path: Path) -> None:
    """Minimal pcap: 3 UDP/IPv4 DNS-port packets and 1 TCP SYN to port 80."""

    def ipv4(proto: int, payload: bytes, src: bytes, dst: bytes) -> bytes:
        header = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(payload), 1, 0, 64, proto, 0, src, dst)
        return header + payload

    frames = []
    for index in range(3):
        udp = struct.pack("!HHHH", 5000 + index, 53, 8 + 4, 0) + b"test"
        frames.append(b"\x00" * 12 + b"\x08\x00" + ipv4(17, udp, bytes([10, 0, 0, 1]), bytes([10, 0, 0, 2])))
    tcp = struct.pack("!HHIIBBHHH", 40000, 80, 1, 0, 0x50, 0x02, 1024, 0, 0)
    frames.append(b"\x00" * 12 + b"\x08\x00" + ipv4(6, tcp, bytes([10, 0, 0, 1]), bytes([93, 184, 216, 34])))
    data = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    for index, frame in enumerate(frames):
        data += struct.pack("<IIII", 1700000000 + index, 0, len(frame), len(frame)) + frame
    path.write_bytes(data)


@pytest.fixture
def pcap_context(tmp_path: Path) -> ExecutionContext:
    (tmp_path / "input").mkdir()
    build_pcap(tmp_path / "input" / "traffic.pcap")
    apps = {}
    if TSHARK:
        apps["tshark"] = {"available": True, "path": TSHARK}
        capinfos = Path(TSHARK).with_name("capinfos.exe" if TSHARK.endswith(".exe") else "capinfos")
        if capinfos.exists():
            apps["capinfos"] = {"available": True, "path": str(capinfos)}
    return ExecutionContext(tmp_path, "net", step_id=1, environment=apps, screenshot_fn=fake_screenshot)


@pytest.mark.skipif(not TSHARK, reason="tshark (Wireshark) is not installed")
def test_wireshark_real_tshark_analysis(pcap_context: ExecutionContext, registry) -> None:
    opened = registry.execute("wireshark.open_capture", {}, pcap_context)
    assert opened.verified and opened.details["packets"] == 4
    udp = registry.execute("wireshark.apply_filter", {"filter": "udp.dstport == 53"}, pcap_context)
    assert udp.verified and udp.details["matches"] == 3
    none = registry.execute("wireshark.apply_filter", {"filter": "http.request", "min_matches": 1}, pcap_context)
    assert not none.verified and none.details["matches"] == 0
    fields = registry.execute("wireshark.inspect_packets", {"filter": "tcp", "fields": "ip.src,ip.dst,tcp.dstport"}, pcap_context)
    assert fields.verified and fields.details["rows"] == 1
    exported = registry.execute("wireshark.export", {"filter": "udp", "output": "dns.pcapng"}, pcap_context)
    assert exported.verified and exported.details["packets"] == 3


def test_wireshark_rejects_filter_injection(pcap_context: ExecutionContext, registry) -> None:
    with pytest.raises(ValueError):
        registry.execute("wireshark.apply_filter", {"filter": "udp; rm -rf /"}, pcap_context)


def test_wireshark_verification_uses_matches_not_exit_code(pcap_context: ExecutionContext, registry, monkeypatch) -> None:
    pcap_context.environment["tshark"] = {"available": True, "path": "tshark"}
    monkeypatch.setattr("lab_agent.integrations.wireshark.run_command",
                        lambda command, **kw: CommandResult(command, 0, "", "", 0.1))  # exit 0, but no packets
    result = registry.execute("wireshark.apply_filter", {"filter": "dns"}, pcap_context)
    assert not result.verified and result.details["matches"] == 0


# ---------------------------------------------------------------------------- local web server
class _Site(http.server.BaseHTTPRequestHandler):
    pages: dict[str, tuple[int, str, dict[str, str]]] = {}

    def do_GET(self) -> None:
        status, body, headers = self.pages.get(self.path.split("?")[0], (404, "missing", {}))
        self.send_response(status)
        self.send_header("Content-Type", headers.get("Content-Type", "text/html; charset=utf-8"))
        for key, value in headers.items():
            if key != "Content-Type":
                self.send_header(key, value)
        encoded = body.encode()
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def do_POST(self) -> None:
        self.do_GET()

    def log_message(self, *args: Any) -> None:
        pass


@pytest.fixture
def site() -> Iterator[str]:
    server = socketserver.ThreadingTCPServer(("127.0.0.1", 0), _Site)
    server.daemon_threads = True
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    url = f"http://127.0.0.1:{server.server_address[1]}"
    _Site.pages = {
        "/": (200, "<html><title>Lab</title><body><h1>Login</h1><form><input id='user'><select id='role'>"
                   "<option value='a'>A</option><option value='b'>B</option></select>"
                   "<button id='go' onclick=\"document.getElementById('msg').textContent='Welcome admin';return false\">Go</button>"
                   "<p id='msg'></p><a id='dl' href='/file.txt' download>file</a>"
                   "<a id='away' href='https://example.com/'>external</a></form></body></html>", {}),
        "/file.txt": (200, "report data", {"Content-Type": "text/plain", "Content-Disposition": "attachment; filename=file.txt"}),
        "/redirect": (302, "", {"Location": "https://example.com/"}),
    }
    yield url
    server.shutdown()


@pytest.mark.skipif(not CHROMIUM, reason="Playwright Chromium is not installed")
def test_browser_real_session_and_scope(site: str, tmp_path: Path, registry, config) -> None:
    config.browser.headless = True
    context = ExecutionContext(tmp_path, "web", step_id=1, config=config)
    try:
        nav = registry.execute("browser.navigate", {"url": site + "/"}, context)
        assert nav.verified and nav.details["title"] == "Lab" and nav.details["status"] == 200
        assert registry.execute("browser.type", {"selector": "#user", "text": "admin"}, context).verified
        assert registry.execute("browser.select", {"selector": "#role", "value": "b"}, context).verified
        assert registry.execute("browser.click", {"selector": "#go"}, context).verified
        registry.execute("browser.wait_for", {"text": "Welcome admin", "timeout": 5}, context)
        text = registry.execute("browser.read_text", {"selector": "#msg"}, context)
        assert text.details["text"] == "Welcome admin"
        assert registry.execute("browser.inspect", {"expected_text": "Welcome admin", "selector": "#go"}, context).verified
        downloaded = registry.execute("browser.download", {"selector": "#dl"}, context)
        assert downloaded.verified and (tmp_path / "results" / "file.txt").read_text() == "report data"
        with pytest.raises(PermissionError):
            registry.execute("browser.navigate", {"url": "https://example.com/"}, context)
        redirected = registry.execute("browser.navigate", {"url": site + "/redirect"}, context)
        assert not redirected.verified and redirected.details["status"] == 403
        assert "example.com" not in redirected.details["url"]
        assert any("example.com" in u for u in redirected.details["blocked_navigations"])
        registry.execute("browser.navigate", {"url": site + "/"}, context)
        registry.execute("browser.click", {"selector": "#away"}, context)
        page_url = registry.adapter("browser").session.page.url
        assert "example.com" not in page_url
    finally:
        registry.adapter("browser").shutdown()


# ---------------------------------------------------------------------------- Burp stand-in
class FakeBurp(socketserver.ThreadingTCPServer):
    """Behaves like Burp's proxy: Ctrl+T toggles Intercept, Forward releases the oldest held request,
    switching Intercept off releases everything that is held."""

    daemon_threads = True
    allow_reuse_address = True

    def __init__(self) -> None:
        self.intercept = False
        self.queue: list[threading.Event] = []
        self.lock = threading.Lock()
        super().__init__(("127.0.0.1", 0), self._handler())

    def toggle(self) -> None:
        with self.lock:
            self.intercept = not self.intercept
            if not self.intercept:
                for gate in self.queue:
                    gate.set()
                self.queue.clear()

    def forward(self) -> None:
        with self.lock:
            if self.queue:
                self.queue.pop(0).set()

    def release_all(self) -> None:
        with self.lock:
            self.intercept = False
            for gate in self.queue:
                gate.set()
            self.queue.clear()

    def _handler(self) -> type:
        server = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self) -> None:
                if self.path.startswith("http://burp"):
                    body = b"<html><title>Burp Suite Community Edition</title>Welcome to Burp Suite</html>"
                else:
                    gate = None
                    with server.lock:
                        if server.intercept:
                            gate = threading.Event()
                            server.queue.append(gate)
                    if gate is not None:
                        gate.wait(30)
                    body = b"<html>lab target via proxy</html>"
                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *args: Any) -> None:
                pass

        return Handler


@pytest.fixture
def burp() -> Iterator[FakeBurp]:
    server = FakeBurp()
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield server
    server.release_all()
    server.shutdown()


def _fake_burp_app(burp: FakeBurp, tmp_path: Path) -> Any:
    class FakeApp:
        profile = {"operations": {"intercept_on": [], "intercept_off": [], "forward": []}}

        def has_operation(self, name: str) -> bool:
            return name in self.profile["operations"]

        def launch(self, *a: Any, **k: Any) -> None:
            pass

        def run_operation(self, name: str, variables: Any = None) -> None:
            if name in {"intercept_on", "intercept_off"}:  # both are the Ctrl+T toggle in the real profile
                burp.toggle()
            if name == "forward":
                burp.forward()

        def running_window(self) -> Any:
            return FakeWindow("Burp Suite Community Edition")

        def screenshot(self, name: str) -> Path:
            return fake_screenshot(tmp_path, name=name)

    return FakeApp()


def test_burp_proxy_intercept_and_forward(burp: FakeBurp, tmp_path: Path, registry, monkeypatch) -> None:
    port = burp.server_address[1]
    context = ExecutionContext(tmp_path, "web", step_id=1, screenshot_fn=fake_screenshot)
    proxy = registry.execute("burp.configure_proxy", {"port": port}, context)
    assert proxy.verified and proxy.details["burp_page"]
    sent = registry.execute("burp.send_request", {"url": "http://127.0.0.1:9/", "port": port}, context)
    assert sent.details["status"] == 200
    assert registry.execute("burp.inspect_response", {"expected_text": "lab target"}, context).verified
    with pytest.raises(PermissionError):
        registry.execute("burp.send_request", {"url": "http://example.com/", "port": port}, context)

    monkeypatch.setattr(registry.adapter("burp"), "_app", lambda ctx: _fake_burp_app(burp, tmp_path))
    held = registry.execute("burp.intercept_request", {"url": "http://127.0.0.1:9/admin", "port": port, "hold_seconds": 1}, context)
    assert held.verified and held.details["held"] and held.details["intercept_toggled"]
    forwarded = registry.execute("burp.forward_request", {"timeout": 10}, context)
    assert forwarded.verified and forwarded.details["status"] == 200
    assert forwarded.details["intercept_off"] and not burp.intercept  # left as a student would leave it


def test_burp_intercept_already_on_with_a_queue(burp: FakeBurp, tmp_path: Path, registry, monkeypatch) -> None:
    """Seen on the real Burp: Intercept left on by an earlier run, the browser's own request queued first."""
    port = burp.server_address[1]
    context = ExecutionContext(tmp_path, "web", step_id=1, screenshot_fn=fake_screenshot)
    burp.toggle()
    from lab_agent.integrations.burp import PendingRequest

    stale = PendingRequest("http://127.0.0.1:9/favicon.ico", port)
    stale.run(timeout=30)
    time.sleep(0.5)
    monkeypatch.setattr(registry.adapter("burp"), "_app", lambda ctx: _fake_burp_app(burp, tmp_path))
    held = registry.execute("burp.intercept_request", {"url": "http://127.0.0.1:9/admin", "port": port, "hold_seconds": 1}, context)
    assert held.verified and not held.details["intercept_toggled"]  # measured as already on: not toggled off
    forwarded = registry.execute("burp.forward_request", {"timeout": 15}, context)
    assert forwarded.verified and forwarded.details["forwards"] == 2  # the stale request first, then ours
    assert forwarded.details["intercept_off"] and not burp.intercept


def test_burp_intercept_off_is_detected(burp: FakeBurp, tmp_path: Path, registry, monkeypatch) -> None:
    context = ExecutionContext(tmp_path, "web", step_id=1, screenshot_fn=fake_screenshot)
    adapter = registry.adapter("burp")
    monkeypatch.setattr(adapter, "_app", lambda ctx: type("A", (), {"has_operation": lambda s, n: False,
                                                                     "running_window": lambda s: None})())
    held = registry.execute("burp.intercept_request", {"url": "http://127.0.0.1:9/", "port": burp.server_address[1],
                                                       "hold_seconds": 1}, context)
    assert not held.verified and "Intercept is off" in held.details["reason"]


def test_burp_port_without_burp_fails(tmp_path: Path, registry, site: str) -> None:
    port = int(site.rsplit(":", 1)[1])
    result = registry.execute("burp.configure_proxy", {"port": port}, ExecutionContext(tmp_path, "w"))
    assert not result.verified


def test_burp_launch_uses_window_evidence(tmp_path: Path, registry, monkeypatch) -> None:
    driver = FakeDriver()
    driver.add_window(FakeWindow("Burp Suite Community Edition v2026.1 - Temporary Project"))
    monkeypatch.setattr("lab_agent.applications.default_driver", lambda: driver)
    exe = tmp_path / "BurpSuite.exe"
    exe.write_bytes(b"MZ")
    monkeypatch.setenv("LAB_AGENT_BURP_PATH", str(exe))
    monkeypatch.setattr(ExecutionContext, "sleep", lambda self, s: None)
    monkeypatch.setattr("lab_agent.integrations.burp.port_open", lambda port, host="127.0.0.1", timeout=1.5: False)
    blocked = registry.execute("burp.launch", {"timeout": 0}, ExecutionContext(tmp_path, "w", screenshot_fn=fake_screenshot))
    assert blocked.blocked and "Start Burp" in blocked.reason
    monkeypatch.setattr("lab_agent.integrations.burp.port_open", lambda port, host="127.0.0.1", timeout=1.5: True)
    result = registry.execute("burp.launch", {}, ExecutionContext(tmp_path, "w", screenshot_fn=fake_screenshot))
    assert result.verified and result.evidence[0]["type"] == "screenshot"


# ---------------------------------------------------------------------------- Overleaf stand-in
@pytest.mark.skipif(not CHROMIUM, reason="Playwright Chromium is not installed")
def test_overleaf_flow_against_local_standin(site: str, tmp_path: Path, registry, config, monkeypatch) -> None:
    from reportlab.pdfgen import canvas

    pdf = tmp_path / "compiled.pdf"
    page = canvas.Canvas(str(pdf))
    page.drawString(72, 720, "Lab Report")
    page.save()
    pdf_text = pdf.read_bytes().decode("latin-1")
    _Site.pages.update({
        "/login": (200, "<form onsubmit=\"location.href='/project';return false\"><input name='email'><input name='password' "
                        "type='password'><button type='submit'>Log in</button></form>", {}),
        "/project": (200, "<button onclick=\"document.getElementById('m').hidden=false\">New project</button>"
                          "<div id='m' hidden><a href='#' onclick=\"return false\">Upload project</a>"
                          "<input type='file' onchange=\"location.href='/project/abc'\"></div>", {}),
        "/project/abc": (200, "<div class='cm-content'>\\documentclass{article}</div><button onclick=\""
                              "document.getElementById('v').hidden=false\">Recompile</button><div id='v' class='pdf-viewer' hidden>"
                              "PDF</div><a aria-label='Download PDF' href='/output.pdf' download>Download PDF</a>", {}),
        "/output.pdf": (200, pdf_text, {"Content-Type": "application/pdf", "Content-Disposition": "attachment; filename=output.pdf"}),
    })
    (tmp_path / "input").mkdir()
    (tmp_path / "input" / "main.tex").write_text("\\documentclass{article}\\begin{document}Lab Report\\end{document}")
    monkeypatch.setenv("LAB_AGENT_OVERLEAF_EMAIL", "student@example.edu")
    monkeypatch.setenv("LAB_AGENT_OVERLEAF_PASSWORD", "correct horse battery")
    config.browser.headless = True
    adapter = registry.adapter("overleaf")
    adapter.selectors["base_url"] = site
    context = ExecutionContext(tmp_path, "latex_lab", step_id=1, config=config)
    try:
        assert registry.execute("overleaf.login", {"timeout": 10}, context).verified
        assert registry.execute("overleaf.create_project", {}, context).verified
        assert registry.execute("overleaf.compile", {}, context).verified
        downloaded = registry.execute("overleaf.download_pdf", {"name": "report.pdf"}, context)
        assert downloaded.checks[0]["type"] == "pdf_valid" and (tmp_path / "results" / "report.pdf").is_file()
    finally:
        adapter.shutdown()


def test_overleaf_without_credentials_is_blocked(tmp_path: Path, registry, config, monkeypatch) -> None:
    monkeypatch.delenv("LAB_AGENT_OVERLEAF_EMAIL", raising=False)
    monkeypatch.delenv("LAB_AGENT_OVERLEAF_PASSWORD", raising=False)
    adapter = registry.adapter("overleaf")
    monkeypatch.setattr(adapter, "_session", lambda ctx: type("S", (), {"page": type("P", (), {"url": "about:blank"})()})())
    from lab_agent.integrations.base import CapabilityBlocked

    with pytest.raises(CapabilityBlocked, match="LAB_AGENT_OVERLEAF_EMAIL"):
        registry.execute("overleaf.login", {}, ExecutionContext(tmp_path, "x", config=config))


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def test_wait_for_proxy_times_out(tmp_path: Path, registry, monkeypatch) -> None:
    monkeypatch.setattr(ExecutionContext, "sleep", lambda self, s: time.sleep(0.01))
    result = registry.execute("burp.wait_for_proxy", {"port": _free_port(), "timeout": 0.2}, ExecutionContext(tmp_path, "w"))
    assert not result.verified
