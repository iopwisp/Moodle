from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
import yaml
from fakes import FakeControl, FakeDriver, FakeWindow, fake_screenshot
from PIL import Image, ImageDraw

from lab_agent.integrations.base import CapabilityBlocked, ExecutionContext
from lab_agent.integrations.pt_canvas import (
    CanvasError,
    CanvasState,
    PTCanvas,
    find_icons,
    free_spot,
    resolve_model,
)

PROFILE = yaml.safe_load((Path(__file__).parents[1] / "profiles" / "packet_tracer.yaml").read_text(encoding="utf-8"))
CATALOG, ALIASES = PROFILE["canvas"]["catalog"], PROFILE["canvas"]["aliases"]
PORTS = {"PC-PT": ["RS 232", "USB0", "FastEthernet0"], "Laptop-PT": ["RS 232", "FastEthernet0"],
         "Cable-Modem-PT": ["Port 0", "Port 1"], "Linksys-WRT300N": ["Internet", "Ethernet 1", "Ethernet 2"],
         "Cloud-PT": ["Serial0", "Coaxial7"]}
BASE_NAME = {"PC-PT": "PC", "Laptop-PT": "Laptop", "Cable-Modem-PT": "Cable Modem"}


# ---------------------------------------------------------------------------- pure helpers
def test_everyday_names_resolve_to_panel_buttons() -> None:
    assert resolve_model("Cable Modem", CATALOG, ALIASES) == ("Network Devices", "WAN Emulation", "Cable-Modem-PT")
    assert resolve_model("PC", CATALOG, ALIASES) == ("End Devices", "End Devices", "PC-PT")
    assert resolve_model("2960", CATALOG, ALIASES)[2] == "2960 IOS15"
    assert resolve_model("wireless router", CATALOG, ALIASES)[2] == "Linksys-WRT300N"
    assert resolve_model("2911", CATALOG, ALIASES) == ("Network Devices", "Routers", "2911")
    with pytest.raises(ValueError, match="Unknown Packet Tracer device model"):
        resolve_model("Toaster", CATALOG, ALIASES)


def test_icons_are_found_on_a_real_packet_tracer_canvas() -> None:
    """Capture from PT 8.2.2 at 150 %: router, cloud, server, cable modem, PC and laptop, with cables between them."""
    image = Image.open(Path(__file__).parent / "fixtures" / "pt_canvas_8.2.2.png")
    boxes = find_icons(image, scale=1.5)
    centres = [((b[0] + b[2]) // 2, (b[1] + b[3]) // 2) for b in boxes]
    assert len(boxes) == 6
    expected = {"Wireless Router": (364, 230), "Internet": (636, 232), "cisco.srv": (802, 232),
                "Cable Modem": (500, 380), "PC": (188, 542), "Laptop": (542, 540)}
    for name, (x, y) in expected.items():
        assert any(abs(x - cx) < 25 and abs(y - cy) < 25 for cx, cy in centres), name
    spot = free_spot(image, box=225)
    assert all(abs(spot[0] - cx) > 112 or abs(spot[1] - cy) > 112 for cx, cy in centres)


# ---------------------------------------------------------------------------- a fake Packet Tracer
class FakePT:
    """Canvas, device panel, port menus and device windows that react to clicks and drags like PT does."""

    def __init__(self) -> None:
        self.driver = FakeDriver()
        controls = [FakeControl("Workspace", "Group", class_name="CWorkspace", rect=(400, 100, 1600, 800)),
                    FakeControl("List of device models", "Group", class_name="CDeviceSpecificBox", rect=(300, 860, 1200, 980))]
        x = 10
        for name in ("Network Devices", "End Devices", "Connections"):  # category row
            controls.append(FakeControl(name, "CheckBox", class_name="CDeviceButton", rect=(x, 860, x + 30, 890)))
            x += 40
        x = 10
        for name in ("WAN Emulation", "Wireless Devices", "End Devices", "Connections"):  # sub-category row
            controls.append(FakeControl(name, "CheckBox", class_name="CDeviceButton", rect=(x, 920, x + 30, 950)))
            x += 40
        x = 310
        for name in ("PC-PT", "Laptop-PT", "Cable-Modem-PT", "Copper Straight-Through", "Coaxial"):
            controls.append(FakeControl(name, "CheckBox", class_name="CDeviceButton", rect=(x, 870, x + 35, 905)))
            x += 45
        self.main = self.driver.add_window(FakeWindow("Cisco Packet Tracer - lab.pka", controls, class_name="CAppWindow",
                                                      rect=(0, 0, 1600, 1000)))
        self.devices: dict[str, dict[str, Any]] = {}
        self.links: list[tuple[str, str, str, str, str]] = []
        self.cable: str | None = None
        self.pending: tuple[str, str] | None = None
        self.editing: tuple[str, str] | None = None
        self.counts: dict[str, int] = {}

    def add(self, name: str, model: str, point: tuple[int, int]) -> None:
        self.devices[name] = {"model": model, "point": point, "used": set()}

    def capture(self, window: Any) -> Image.Image:
        image = Image.new("RGB", (1600, 1000), "white")
        draw = ImageDraw.Draw(image)
        for device in self.devices.values():
            x, y = device["point"]
            draw.rectangle((x - 20, y - 20, x + 20, y + 20), fill=(60, 120, 170))
        return image

    # -- what a click hits
    def _control_at(self, x: int, y: int) -> FakeControl | None:
        for window in [w for w in self.driver.windows if not w.closed]:
            for control in window.controls:
                left, top, right, bottom = control.rect
                if control.class_name not in {"CWorkspace", "CDeviceSpecificBox"} and left <= x <= right and top <= y <= bottom:
                    return control
        return None

    def _device_at(self, x: int, y: int) -> str | None:
        return next((n for n, d in self.devices.items() if abs(d["point"][0] - x) <= 25 and abs(d["point"][1] - y) <= 25), None)

    def click(self, x: int, y: int) -> None:
        control = self._control_at(x, y)
        if control is not None and control.control_type == "MenuItem":
            self._port_chosen(control.name)
        elif control is not None and control.name in {"Copper Straight-Through", "Coaxial"}:
            self.cable = control.name
        elif control is not None and control.control_type == "TabItem":
            pass
        elif control is not None and control.control_type == "Edit":
            self.editing = (control.text, control.text)
        elif (device := self._device_at(x, y)) is not None:
            if self.cable:
                free = [p for p in PORTS[self.devices[device]["model"]] if p not in self.devices[device]["used"]]
                items = [FakeControl(p, "MenuItem", rect=(x, y + 30 * i, x + 150, y + 30 * i + 28)) for i, p in enumerate(free)]
                self.driver.add_window(FakeWindow("Cisco Packet Tracer", items, class_name="QMenu"))
                self.pending_device = device
            else:
                self.driver.add_window(FakeWindow(device, [FakeControl("Config", "TabItem", rect=(1000, 400, 1060, 420)),
                                                           FakeControl("", "Edit", text=device, rect=(1100, 450, 1400, 470))]))

    def _port_chosen(self, port: str) -> None:
        menu = self.driver.find_window({"class_name": "QMenu"})
        assert menu is not None
        menu.closed = True
        self.devices[self.pending_device]["used"].add(port)
        if self.pending is None:
            self.pending = (self.pending_device, port)
        else:
            self.links.append((self.pending[0], self.pending[1], self.pending_device, port, str(self.cable)))
            self.pending, self.cable = None, None

    def press(self, key: str) -> None:
        if key == "esc":
            for window in self.driver.windows:
                if window.class_name == "QMenu":
                    window.closed = True
            self.cable, self.pending = None, None
        elif key == "end":
            return
        elif key == "backspace" and self.editing:
            self.editing = (self.editing[0], self.editing[1][:-1])
        elif key == "enter" and self.editing:
            old, new = self.editing
            self.devices[new] = self.devices.pop(old)
            window = self.driver.find_window({"title": old})
            assert window is not None
            window.name = new
            self.editing = None

    def type_text(self, text: str) -> None:
        if self.editing:
            self.editing = (self.editing[0], self.editing[1] + text)

    def drag(self, start: tuple[int, int], end: tuple[int, int]) -> None:
        control = self._control_at(*start)
        assert control is not None and control.class_name == "CDeviceButton", start
        base = BASE_NAME[control.name]
        number = self.counts.get(base, 0)
        self.counts[base] = number + 1
        self.add(f"{base}{number}", control.name, end)


class FakePointer:
    def __init__(self, pt: FakePT) -> None:
        self.pt = pt
        self.actions: list[tuple[Any, ...]] = []

    def click(self, x: int, y: int, *, window: Any = None, double: bool = False) -> None:
        self.actions.append(("click", x, y))
        self.pt.click(x, y)

    def drag(self, start: tuple[int, int], end: tuple[int, int], *, window: Any = None) -> None:
        self.actions.append(("drag", start, end))
        self.pt.drag(start, end)

    def type_text(self, text: str, *, window: Any = None) -> None:
        self.actions.append(("type", text))
        self.pt.type_text(text)

    def press(self, *keys: str, window: Any = None) -> None:
        for key in keys:
            self.actions.append(("press", key))
            self.pt.press(key)


@pytest.fixture
def fake_pt(tmp_path: Path) -> tuple[FakePT, PTCanvas]:
    pt = FakePT()
    pt.add("Wireless Router", "Linksys-WRT300N", (700, 300))
    pt.add("Internet", "Cloud-PT", (1000, 300))
    canvas = PTCanvas(pt.driver, pt.main, FakePointer(pt), PROFILE, capture=pt.capture,
                      state=CanvasState(tmp_path / "pt_canvas.json"), sleep=lambda seconds: None)
    return pt, canvas


def test_survey_names_every_device_by_the_window_it_opens(fake_pt) -> None:  # type: ignore[no-untyped-def]
    pt, canvas = fake_pt
    assert canvas.survey() == {"Wireless Router": [700, 300], "Internet": [1000, 300]}
    assert all(window.closed for window in pt.driver.windows if window.name in {"Wireless Router", "Internet"})
    assert CanvasState.load(canvas.state.path).devices["Internet"] == [1000, 300]


def test_place_rename_and_cable_like_the_simple_network_activity(fake_pt) -> None:  # type: ignore[no-untyped-def]
    pt, canvas = fake_pt
    created, point = canvas.place("PC", near="Wireless Router")
    assert created == "PC0" and pt.devices["PC0"]["model"] == "PC-PT"
    assert point[1] > 300  # placed below the router, on free canvas
    canvas.rename("PC0", "PC")
    assert "PC" in pt.devices and canvas.state.devices["PC"] == list(point)
    modem, _ = canvas.place("Cable Modem")
    canvas.rename(modem, "Cable Modem")

    canvas.connect("PC", "FastEthernet0", "Wireless Router", "Ethernet 1", "straight")
    canvas.connect("Wireless Router", "Internet", "Cable Modem", "Port 1", "straight")
    canvas.connect("Cable Modem", "Port 0", "Internet", "Coaxial7", "coaxial")
    assert pt.links == [("PC", "FastEthernet0", "Wireless Router", "Ethernet 1", "Copper Straight-Through"),
                        ("Wireless Router", "Internet", "Cable Modem", "Port 1", "Copper Straight-Through"),
                        ("Cable Modem", "Port 0", "Internet", "Coaxial7", "Coaxial")]


def test_a_taken_or_unknown_port_fails_and_lists_the_free_ones(fake_pt) -> None:  # type: ignore[no-untyped-def]
    pt, canvas = fake_pt
    canvas.connect("Wireless Router", "Ethernet 1", "Internet", "Serial0", "straight")
    with pytest.raises(CanvasError, match=r"Port 'Ethernet 1' of Wireless Router is not free; free ports: Internet, Ethernet 2"):
        canvas.connect("Wireless Router", "Ethernet 1", "Internet", "Coaxial7", "coaxial")
    assert pt.driver.find_window({"class_name": "QMenu"}) is None  # the menu was closed again


def test_missing_device_is_reported_with_what_is_there(fake_pt) -> None:  # type: ignore[no-untyped-def]
    _, canvas = fake_pt
    with pytest.raises(CanvasError, match="No device named 'Switch0'.*found: Wireless Router, Internet"):
        canvas.locate("Switch0")


def test_adapter_runs_canvas_steps_with_evidence(fake_pt, tmp_path: Path, registry, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    pt, _ = fake_pt
    monkeypatch.setattr("lab_agent.applications.default_driver", lambda: pt.driver)
    monkeypatch.setattr(PTCanvas, "_capture_window", staticmethod(pt.capture))
    monkeypatch.setattr(ExecutionContext, "sleep", lambda self, seconds: None)
    adapter = registry.adapter("packet_tracer")
    adapter.pointer_factory = lambda: FakePointer(pt)
    context = ExecutionContext(tmp_path / "ws", "net", step_id=4, screenshot_fn=fake_screenshot)
    added = registry.execute("packet_tracer.add_device", {"model": "Laptop", "device": "Laptop"}, context)
    assert added.verified and added.details["created_as"] == "Laptop0" and "Laptop" in pt.devices
    linked = registry.execute("packet_tracer.connect_devices", {"a": "Laptop:FastEthernet0", "b": "Wireless Router:Ethernet 2"}, context)
    assert linked.verified and linked.details["b"] == "Wireless Router:Ethernet 2"
    bad = registry.execute("packet_tracer.connect_devices", {"a": "Laptop:FastEthernet0", "b": "Internet:Coaxial7"}, context)
    assert not bad.verified and "not free" in bad.reason and bad.evidence  # screenshot of the failure


def test_real_pointer_is_never_used_without_a_real_window(fake_pt, tmp_path: Path, registry, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    pt, _ = fake_pt
    monkeypatch.setattr("lab_agent.applications.default_driver", lambda: pt.driver)
    with pytest.raises(CapabilityBlocked, match="real Packet Tracer window"):
        registry.execute("packet_tracer.survey_canvas", {}, ExecutionContext(tmp_path, "net", screenshot_fn=fake_screenshot))


def test_windows_of_other_programs_are_not_taken_for_devices(fake_pt) -> None:  # type: ignore[no-untyped-def]
    """Seen live: a chat app retitled its window ("My love (388647)") while the survey clicked a device."""
    pt, canvas = fake_pt
    canvas.pid = 100
    original = pt.driver.list_windows

    def with_processes() -> list[dict[str, Any]]:
        rows = [{**row, "process_id": 100} for row in original()]
        return [*rows, {"name": f"Chat ({len(pt.driver.windows)})", "visible": True, "process_id": 200}]

    pt.driver.list_windows = with_processes  # type: ignore[method-assign]
    assert set(canvas.survey()) == {"Wireless Router", "Internet"}
