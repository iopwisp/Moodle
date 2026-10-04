from __future__ import annotations

from pathlib import Path

import pytest
from fakes import FakeDriver, FakeIOSConsole, FakeWindow, fake_screenshot, pt_device_window

from lab_agent.integrations.base import CapabilityBlocked, ExecutionContext
from lab_agent.integrations.packet_tracer import generate_configs, parse_ping, validate_topology

TOPOLOGY = {
    "devices": {
        "R1": {"type": "router", "interfaces": {"GigabitEthernet0/0": "192.168.1.1/24", "GigabitEthernet0/1": "10.0.0.1/30"}},
        "R2": {"type": "router", "interfaces": {"GigabitEthernet0/0": "192.168.2.1/24", "GigabitEthernet0/1": "10.0.0.2/30"}},
        "PC1": {"type": "pc", "ip": "192.168.1.10/24", "gateway": "192.168.1.1"},
        "PC2": {"type": "pc", "ip": "192.168.2.10/24", "gateway": "192.168.2.1"},
    },
    "links": [["R1:GigabitEthernet0/1", "R2:GigabitEthernet0/1"]],
    "routes": {"R1": [["192.168.2.0/24", "10.0.0.2"]], "R2": [["192.168.1.0/24", "10.0.0.1"]]},
}


def test_topology_model_and_config_generation() -> None:
    report = validate_topology(TOPOLOGY)
    assert report["valid"], report["problems"]
    assert report["reachability"]["PC1"]["PC2"] and report["reachability"]["PC2"]["PC1"]
    configs = generate_configs(TOPOLOGY)
    assert " ip address 192.168.1.1 255.255.255.0" in configs["R1"]
    assert "ip route 192.168.2.0 255.255.255.0 10.0.0.2" in configs["R1"]
    assert configs["PC1"] == ["ipconfig 192.168.1.10 255.255.255.0 192.168.1.1"]


def test_topology_errors_are_detected() -> None:
    broken = {**TOPOLOGY, "routes": {}, "devices": {**TOPOLOGY["devices"],
                                                     "PC2": {"type": "pc", "ip": "192.168.1.10/24", "gateway": "192.168.9.1"}}}
    report = validate_topology(broken)
    assert not report["valid"]
    joined = " ".join(report["problems"])
    assert "duplicate IP 192.168.1.10" in joined and "gateway 192.168.9.1" in joined


def test_ping_parser() -> None:
    assert parse_ping("Packets: Sent = 4, Received = 3, Lost = 1 (25% loss)")["received"] == 3
    assert parse_ping("Success rate is 100 percent (5/5), round-trip")["received"] == 5
    assert parse_ping("Request timed out.") is None


@pytest.fixture
def pt(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> tuple[ExecutionContext, FakeDriver]:
    driver = FakeDriver()
    driver.add_window(FakeWindow("Cisco Packet Tracer - lab.pkt", class_name="CAppWindow"))
    monkeypatch.setattr("lab_agent.applications.default_driver", lambda: driver)
    monkeypatch.setattr(ExecutionContext, "sleep", lambda self, seconds: None)
    return ExecutionContext(tmp_path, "net_lab", step_id=2, screenshot_fn=fake_screenshot), driver


def test_router_configuration_through_cli_is_verified(pt, registry) -> None:
    context, driver = pt
    pt_device_window(driver, "R1", FakeIOSConsole("R1"))
    result = registry.execute("packet_tracer.configure_router", {
        "device": "R1", "commands": ["hostname R1", "interface GigabitEthernet0/0", "ip address 192.168.1.1 255.255.255.0",
                                     "no shutdown"]}, context)
    assert result.verified, result.details
    running = (context.workspace / "results" / "pt_R1_running_config.txt").read_text()
    assert "ip address 192.168.1.1 255.255.255.0" in running


def test_ios_errors_fail_the_step(pt, registry) -> None:
    context, driver = pt
    pt_device_window(driver, "R1", FakeIOSConsole("R1"))
    result = registry.execute("packet_tracer.configure_router", {"device": "R1", "commands": ["bogus command"]}, context)
    assert not result.verified and "Invalid input" in result.details["reason"]


def test_pc_ip_and_real_ping_parsing(pt, registry) -> None:
    context, driver = pt
    pt_device_window(driver, "PC1", FakeIOSConsole("PC1", pc=True))
    configured = registry.execute("packet_tracer.configure_pc", {"device": "PC1", "ip": "192.168.1.10/24", "gateway": "192.168.1.1"},
                                  context)
    assert configured.verified
    ping = registry.execute("packet_tracer.verify_connectivity", {"source": "PC1", "target": "192.168.2.10"}, context)
    assert ping.verified and ping.details["stats"]["received"] == 4


def test_failed_ping_fails(pt, registry) -> None:
    context, driver = pt
    pt_device_window(driver, "PC1", FakeIOSConsole("PC1", pc=True, ping_ok=False))
    ping = registry.execute("packet_tracer.verify_connectivity", {"source": "PC1", "target": "192.168.2.10"}, context)
    assert not ping.verified


def test_device_window_missing_asks_the_user(pt, registry) -> None:
    context, _ = pt
    with pytest.raises(CapabilityBlocked, match="Open the R9 window"):
        registry.execute("packet_tracer.enter_command", {"device": "R9", "command": "show ip interface brief"}, context)


def test_canvas_actions_need_a_real_window(pt, registry) -> None:
    """Without a real window handle the canvas steps must never fall back to moving the real mouse."""
    context, _ = pt
    with pytest.raises(CapabilityBlocked, match="real Packet Tracer window"):
        registry.execute("packet_tracer.add_device", {"device": "R3", "model": "2911"}, context)
    with pytest.raises(CapabilityBlocked, match="real Packet Tracer window"):
        registry.execute("packet_tracer.connect_devices", {"a": "R1:G0/0", "b": "SW1:F0/1"}, context)


def test_create_topology_writes_configs(tmp_path: Path, registry) -> None:
    context = ExecutionContext(tmp_path, "net_lab", step_id=1)
    result = registry.execute("packet_tracer.create_topology", {"topology": TOPOLOGY}, context)
    assert result.verified
    assert (tmp_path / "results" / "pt_config_R1.txt").is_file()


def test_login_wall_blocks_launch(tmp_path: Path, registry, monkeypatch) -> None:
    """Real PT 8.2.2 opens a CNetspaceLogin window next to the main window; launch must be BLOCKED."""
    driver = FakeDriver()
    driver.add_window(FakeWindow("Cisco Packet Tracer", class_name="CAppWindow"))
    driver.add_window(FakeWindow("Cisco Packet Tracer Login", class_name="CNetspaceLogin"))
    monkeypatch.setattr("lab_agent.applications.default_driver", lambda: driver)
    monkeypatch.setattr(ExecutionContext, "sleep", lambda self, seconds: None)
    exe = tmp_path / "PacketTracer.exe"
    exe.write_bytes(b"MZ")
    monkeypatch.setenv("LAB_AGENT_PACKET_TRACER_PATH", str(exe))
    with pytest.raises(CapabilityBlocked, match="login"):
        registry.execute("packet_tracer.launch", {}, ExecutionContext(tmp_path, "net", screenshot_fn=fake_screenshot))


def test_open_project_uses_its_own_window_next_to_the_students_one(tmp_path: Path, registry, monkeypatch) -> None:
    """Seen on PT 8.2.2: the student's own Packet Tracer was open; retries started extra copies and screenshots
    could pick the student's window. The project window (its title shows the file path) must be the target."""
    driver = FakeDriver()
    driver.add_window(FakeWindow("Cisco Packet Tracer", class_name="CAppWindow"))  # the student's instance
    monkeypatch.setattr("lab_agent.applications.default_driver", lambda: driver)
    monkeypatch.setattr(ExecutionContext, "sleep", lambda self, seconds: None)
    exe = tmp_path / "PacketTracer.exe"
    exe.write_bytes(b"MZ")
    monkeypatch.setenv("LAB_AGENT_PACKET_TRACER_PATH", str(exe))
    (tmp_path / "input").mkdir()
    project = tmp_path / "input" / "Create_a_Simple_Network.pka"
    project.write_bytes(b"pka")
    launches: list[list[str]] = []

    def launch(executable: str, args: list[str], cwd: Path | None = None):  # type: ignore[no-untyped-def]
        launches.append(args)
        driver.add_window(FakeWindow(f"Cisco Packet Tracer - {args[0]} - Guest - 2026-10-05", class_name="CAppWindow"))
        return type("P", (), {"pid": 7, "poll": lambda self: None})()

    monkeypatch.setattr("lab_agent.applications.launch_application", launch)
    shots: list[str | None] = []

    def screenshot(workspace: Path, *, name: str | None = None, window_title_re: str | None = None) -> Path:
        shots.append(window_title_re)
        return fake_screenshot(workspace, name=name)

    context = ExecutionContext(tmp_path, "net", screenshot_fn=screenshot)
    first = registry.execute("packet_tracer.open_project", {"file": "input/Create_a_Simple_Network.pka"}, context)
    assert first.verified and "Create_a_Simple_Network" in first.details["title"]
    again = registry.execute("packet_tracer.open_project", {"file": "input/Create_a_Simple_Network.pka"}, context)
    assert again.verified and len(launches) == 1  # a retry attaches instead of starting a second copy
    assert registry.execute("packet_tracer.capture_topology", {}, context).verified
    assert shots and all(pattern and "Create_a_Simple_Network" in pattern for pattern in shots)
