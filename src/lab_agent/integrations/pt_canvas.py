"""Packet Tracer canvas automation: place devices, name them and cable them like a student does.

The logical workspace (class ``CWorkspace``) exposes nothing to UI Automation, but everything around it does:

* the device-type panel - every category, sub-category, device model and cable is a ``CDeviceButton`` named
  "End Devices", "PC-PT", "Copper Straight-Through", ... (catalog in ``profiles/packet_tracer.yaml``);
* the port menu that opens when a cable is attached to a device - a ``QMenu`` whose ``MenuItem`` entries are the
  free ports ("FastEthernet0", "Ethernet 1", "Coaxial7");
* device windows - top-level windows titled with the device's display name (tabs Physical / Config / Desktop).

So only two things need the real mouse: dragging a model onto the canvas and clicking a device on it.  Devices
are found by *surveying* the canvas: icon-sized blobs are detected in a ``PrintWindow`` capture, each one is
clicked, and the title of the window that opens names it.  Nothing is guessed from OCR, and every position the
agent uses was confirmed by the device window it opened.  The map is kept in ``working/pt_canvas.json``.
"""

from __future__ import annotations

import json
import re
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

Rect = tuple[int, int, int, int]
Point = tuple[int, int]


class CanvasError(RuntimeError):
    """The canvas did not react as expected; the message says what to check."""


def normalize(name: str) -> str:
    return re.sub(r"[^a-z0-9]", "", name.casefold())


def resolve_model(model: str, catalog: dict[str, dict[str, list[str]]], aliases: dict[str, str]) -> tuple[str, str, str]:
    """``"Cable Modem"`` -> ``("Network Devices", "WAN Emulation", "Cable-Modem-PT")``."""
    wanted = {normalize(model)}
    for alias, target in aliases.items():
        if normalize(alias) == normalize(model):
            wanted.add(normalize(str(target)))
    entries = [(category, sub, name) for category, subs in catalog.items() for sub, names in subs.items() for name in names]
    for category, sub, name in entries:
        if normalize(name) in wanted:
            return category, sub, name
    for category, sub, name in entries:  # "2960" -> "2960 IOS15", "Laptop" -> "Laptop-PT"
        key = normalize(name)
        if any(key.startswith(item) and item for item in wanted) or any(key == item + "pt" for item in wanted):
            return category, sub, name
    known = ", ".join(sorted({name for _, _, name in entries}))
    raise ValueError(f"Unknown Packet Tracer device model {model!r}. Known models: {known}")


def find_icons(image: Any, *, scale: float = 1.0) -> list[Rect]:
    """Bounding boxes of icon-sized solid blobs on a mostly white canvas capture (PIL image).

    Cables (2-4 px lines), link lights and label text are thin and disappear under a minimum filter; device
    icons are solid enough to survive it.  Boxes are in the image's own pixel coordinates, sorted top-down.
    """
    from PIL import Image, ImageChops, ImageFilter

    rgb = image.convert("RGB")
    difference = ImageChops.difference(rgb, Image.new("RGB", rgb.size, (255, 255, 255)))
    red, green, blue = difference.split()
    ink = ImageChops.lighter(red, ImageChops.lighter(green, blue)).point(lambda value: 255 if value > 28 else 0)
    erode = max(3, round(3 * scale) | 1)  # 5 px at 150 %: removes cables and text, keeps even thin icons (modems)
    solid = ink.filter(ImageFilter.MinFilter(erode))
    cell = 4
    grid = solid.resize((max(1, solid.width // cell), max(1, solid.height // cell)), Image.Resampling.BOX)
    width, height = grid.size
    data = grid.tobytes()  # one byte per cell (mode L)
    seen = bytearray(width * height)
    boxes: list[Rect] = []
    minimum, maximum = 14 * scale, 140 * scale
    for start in range(width * height):
        if seen[start] or data[start] < 100:
            continue
        stack = [start]
        seen[start] = 1
        left, top, right, bottom = width, height, 0, 0
        while stack:
            index = stack.pop()
            x, y = index % width, index // width
            left, top, right, bottom = min(left, x), min(top, y), max(right, x), max(bottom, y)
            for nx, ny in ((x + 1, y), (x - 1, y), (x, y + 1), (x, y - 1)):
                neighbour = ny * width + nx
                if 0 <= nx < width and 0 <= ny < height and not seen[neighbour] and data[neighbour] >= 100:
                    seen[neighbour] = 1
                    stack.append(neighbour)
        box = (left * cell, top * cell, (right + 1) * cell, (bottom + 1) * cell)
        box_width, box_height = box[2] - box[0], box[3] - box[1]
        if minimum <= max(box_width, box_height) <= maximum and min(box_width, box_height) >= minimum / 2:
            boxes.append(box)
    return sorted(boxes, key=lambda b: (b[1] // 40, b[0]))


def free_spot(image: Any, *, near: Point | None = None, box: int = 150, step: int = 40) -> Point:
    """A point whose surrounding ``box`` x ``box`` square of the capture is empty canvas (image coordinates)."""
    from PIL import Image, ImageChops

    rgb = image.convert("RGB")
    difference = ImageChops.difference(rgb, Image.new("RGB", rgb.size, (255, 255, 255))).convert("L")
    width, height = rgb.size
    half = box // 2
    candidates = [(x, y) for y in range(half + 20, height - half - 20, step) for x in range(half + 20, width - half - 20, step)]
    target = near or (width // 3, height // 2)
    candidates.sort(key=lambda p: (p[0] - target[0]) ** 2 + (p[1] - target[1]) ** 2)
    for x, y in candidates:
        if difference.crop((x - half, y - half, x + half, y + half)).getbbox() is None:
            return x, y
    raise CanvasError("No free space left on the visible canvas; zoom out or make room, then resume.")


def centre(rect: Rect) -> Point:
    return (rect[0] + rect[2]) // 2, (rect[1] + rect[3]) // 2


@dataclass
class CanvasState:
    """Device name -> screen point, confirmed by the device window each point opened."""

    path: Path | None = None
    devices: dict[str, list[int]] = field(default_factory=dict)

    @classmethod
    def load(cls, path: Path | None) -> CanvasState:
        if path is not None and path.is_file():
            return cls(path, json.loads(path.read_text(encoding="utf-8")).get("devices", {}))
        return cls(path)

    def save(self) -> None:
        if self.path is not None:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self.path.write_text(json.dumps({"devices": self.devices}, indent=2, ensure_ascii=False), encoding="utf-8")


class PTCanvas:
    """Drives one Packet Tracer main window (a UIA window from :class:`~lab_agent.desktop.uia.UIDriver`)."""

    def __init__(self, driver: Any, window: Any, pointer: Any, profile: dict[str, Any], *,
                 capture: Callable[[Any], Any] | None = None, state: CanvasState | None = None,
                 sleep: Callable[[float], None] = time.sleep, wait: float = 0.6) -> None:
        canvas = profile.get("canvas", {})
        self.driver, self.window, self.pointer = driver, window, pointer
        self.catalog: dict[str, dict[str, list[str]]] = canvas.get("catalog", {})
        self.aliases: dict[str, str] = {str(k): str(v) for k, v in canvas.get("aliases", {}).items()}
        self.cables: dict[str, str] = {str(k): str(v) for k, v in canvas.get("cables", {}).items()}
        self.capture = capture or self._capture_window
        self.state = state or CanvasState()
        self.sleep = sleep
        self.wait = wait
        try:  # device windows belong to the Packet Tracer process; other apps retitle their windows too (chat badges)
            self.pid: int | None = int(window.process_id())
        except Exception:  # noqa: BLE001 - fake windows have no process
            self.pid = None

    # ------------------------------------------------------------------ geometry
    @staticmethod
    def _capture_window(window: Any) -> Any:
        from ..tools.screenshot import capture_window

        image = capture_window(int(window.handle))
        if image is None:
            raise CanvasError("The Packet Tracer window could not be captured (PrintWindow returned nothing).")
        return image

    def _rect(self, element: Any) -> Rect:
        return self.driver.rectangle(element)

    def _control(self, selector: dict[str, Any], what: str, timeout: float = 3) -> Any:
        control = self.driver.find_control(self.window, selector, timeout=timeout)
        if control is None:
            raise CanvasError(f"{what} is not visible in Packet Tracer ({selector}).")
        return control

    def workspace(self) -> Rect:
        return self._rect(self._control({"class_name": "CWorkspace"}, "The logical workspace"))

    def workspace_image(self) -> tuple[Any, Rect]:
        """Capture of the workspace area only, with its screen rectangle."""
        image = self.capture(self.window)
        window_rect = self._capture_origin()
        area = self.workspace()
        crop = image.crop((area[0] - window_rect[0], area[1] - window_rect[1], area[2] - window_rect[0], area[3] - window_rect[1]))
        return crop, area

    def _capture_origin(self) -> Rect:
        """Where the ``PrintWindow`` capture starts on screen.

        UI Automation reports a maximized window without its invisible resize borders ((0, 34) on this machine)
        while ``PrintWindow`` draws the whole Win32 window rectangle ((-11, -11)); using the UIA rectangle shifted
        every survey click about 40 px down.
        """
        handle = getattr(self.window, "handle", None)
        if handle:
            try:
                import ctypes
                from ctypes import wintypes

                rect = wintypes.RECT()
                if ctypes.windll.user32.GetWindowRect(int(handle), ctypes.byref(rect)):
                    return rect.left, rect.top, rect.right, rect.bottom
            except Exception:  # noqa: BLE001, S110 - not Windows
                pass
        return self._rect(self.window)

    def _scale(self) -> float:
        handle = getattr(self.window, "handle", None)
        try:
            import ctypes

            return ctypes.windll.user32.GetDpiForWindow(int(handle)) / 96 if handle else 1.0
        except Exception:  # noqa: BLE001 - not Windows / no handle in tests
            return 1.0

    # ------------------------------------------------------------------ panel
    def press_button(self, name: str, *, found_index: int = 0) -> None:
        button = self._control({"title": name, "class_name": "CDeviceButton", "found_index": found_index}, f"Panel button {name!r}")
        self.pointer.click(*centre(self._rect(button)), window=self.window)
        self.sleep(self.wait / 2)

    def choose_model(self, model: str) -> str:
        category, sub, name = resolve_model(model, self.catalog, self.aliases)
        self.press_button(category)
        # the sub-category row repeats some names ("End Devices", "Connections"): the second match is the sub-category
        self.press_button(sub, found_index=1 if sub == category else 0)
        button = self._control({"title": name, "class_name": "CDeviceButton"}, f"Device model {name!r}")
        box = self.driver.find_control(self.window, {"class_name": "CDeviceSpecificBox"}, timeout=1)
        if box is not None and self._rect(button)[2] > self._rect(box)[2]:
            raise CanvasError(f"{name} is outside the visible part of the device list; widen the Packet Tracer window.")
        return name

    # ------------------------------------------------------------------ windows
    def _windows(self) -> set[str]:
        return {str(w.get("name", "")) for w in self.driver.list_windows()
                if w.get("visible", True) and w.get("name") and (self.pid is None or w.get("process_id") in (None, self.pid))}

    def _await_new_window(self, before: set[str], timeout: float = 6.0) -> str | None:  # a server window needs ~5 s
        deadline = time.monotonic() + timeout
        ignore = {self.driver.window_title(self.window), "Cisco Packet Tracer"}
        while True:
            fresh = sorted(self._windows() - before - ignore)
            if fresh:
                return fresh[0]
            if time.monotonic() >= deadline:
                return None
            self.sleep(0.2)

    def close_window(self, title: str) -> None:
        window = self.driver.find_window({"title": title}, timeout=1)
        if window is not None:
            self.driver.close(window)
            self.sleep(self.wait / 2)

    def device_at(self, point: Point) -> str | None:
        """Click a canvas point in select mode and return the name of the device window it opened (then close it)."""
        self.pointer.press("esc", window=self.window)  # leave cable / placement mode
        before = self._windows()
        self.pointer.click(*point, window=self.window)
        name = self._await_new_window(before)
        if name:
            self.close_window(name)
        return name

    # ------------------------------------------------------------------ devices
    def survey(self) -> dict[str, list[int]]:
        """Click every icon on the visible canvas and record which device it is."""
        image, area = self.workspace_image()
        found: dict[str, list[int]] = {}
        margin = int(12 * self._scale())  # toolbar buttons overlap the workspace edges; never click them
        for box in find_icons(image, scale=self._scale()):
            if box[0] < margin or box[1] < margin or box[2] > image.width - margin or box[3] > image.height - margin:
                continue
            point = (area[0] + (box[0] + box[2]) // 2, area[1] + (box[1] + box[3]) // 2)
            name = self.device_at(point)
            if name and name not in found:
                found[name] = list(point)
        self.state.devices = found
        self.state.save()
        return found

    def locate(self, name: str) -> Point:
        point = self.state.devices.get(name)
        if point is not None:
            return int(point[0]), int(point[1])
        found = self.survey()
        if name not in found:
            raise CanvasError(f"No device named {name!r} on the visible canvas; found: {', '.join(found) or 'none'}.")
        return int(found[name][0]), int(found[name][1])

    def place(self, model: str, *, at: tuple[float, float] | None = None, near: str | None = None) -> tuple[str, Point]:
        """Drag ``model`` onto free canvas space; returns the name Packet Tracer gave it and its point."""
        name = self.choose_model(model)
        image, area = self.workspace_image()
        if at is not None:
            target = (area[0] + int(at[0] * (area[2] - area[0])), area[1] + int(at[1] * (area[3] - area[1])))
        else:
            anchor = None
            if near:
                px, py = self.locate(near)
                anchor = (px - area[0], py - area[1] + int(140 * self._scale()))
            spot = free_spot(image, near=anchor, box=int(150 * self._scale()))
            target = (area[0] + spot[0], area[1] + spot[1])
        button = self._control({"title": name, "class_name": "CDeviceButton"}, f"Device model {name!r}")
        self.pointer.drag(centre(self._rect(button)), target, window=self.window)
        self.sleep(self.wait)
        created = self.device_at(target)
        if not created:
            raise CanvasError(f"{name} was dragged to {target} but no device window opens there.")
        self.state.devices[created] = list(target)
        self.state.save()
        return created, target

    def open_device(self, name: str) -> Any:
        window = self.driver.find_window({"title": name}, timeout=0)
        if window is not None:
            return window
        point = self.locate(name)
        self.pointer.press("esc", window=self.window)
        self.pointer.click(*point, window=self.window)
        window = self.driver.find_window({"title": name}, timeout=4)
        if window is None:
            raise CanvasError(f"Clicking {name} did not open its window; run packet_tracer.survey_canvas and resume.")
        return window

    def rename(self, name: str, new_name: str) -> None:
        """Config tab -> Display Name.  The device window title follows the field, which is the check."""
        window = self.open_device(name)
        tab = self.driver.find_control(window, {"title": "Config", "control_type": "TabItem"}, timeout=3)
        if tab is None:
            raise CanvasError(f"{name} has no Config tab.")
        self.pointer.click(*centre(self._rect(tab)), window=window)
        self.sleep(self.wait / 2)
        field_ = self.driver.find_control(window, {"control_type": "Edit", "found_index": 0}, timeout=3)
        if field_ is None:
            raise CanvasError(f"The Display Name field of {name} was not found.")
        self.pointer.click(*centre(self._rect(field_)), window=window)
        self.pointer.press("end", *(["backspace"] * (len(self.driver.read_value(field_) or name) + 2)), window=window)
        self.pointer.type_text(new_name, window=window)
        self.pointer.press("enter", window=window)
        renamed = self.driver.find_window({"title": new_name}, timeout=3)
        if renamed is None:
            raise CanvasError(f"{name} was not renamed to {new_name!r} (its window title did not change).")
        self.driver.close(renamed)
        self.sleep(self.wait / 2)
        point = self.state.devices.pop(name, None)
        self.state.devices[new_name] = point if point is not None else list(self.locate(new_name))
        self.state.save()

    # ------------------------------------------------------------------ cables
    def _menu(self, timeout: float = 2.5) -> Any:
        return self.driver.find_window({"class_name": "QMenu"}, timeout=timeout)

    def _choose_port(self, device: str, port: str) -> str:
        menu = self._menu()
        if menu is None:
            raise CanvasError(f"No port menu opened on {device}.")
        items = [element for element in self.driver.snapshot(menu) if str(element.get("control_type")) == "MenuItem"]
        names = [str(item.get("name", "")) for item in items]
        match = next((item for item in items if normalize(str(item.get("name", ""))) == normalize(port)), None)
        if match is None:
            self.pointer.press("esc", "esc", window=self.window)
            raise CanvasError(f"Port {port!r} of {device} is not free; free ports: {', '.join(names) or 'none'}.")
        self.pointer.click(*centre(tuple(match["rect"])), window=self.window)  # type: ignore[arg-type]
        self.sleep(self.wait / 2)
        return str(match.get("name"))

    def connect(self, a: str, a_port: str, b: str, b_port: str, cable: str = "straight") -> dict[str, str]:
        cable_name = self.cables.get(cable.casefold(), cable)
        first, second = self.locate(a), self.locate(b)
        self.pointer.press("esc", window=self.window)
        self.press_button("Connections")
        self.press_button(cable_name)
        self.pointer.click(*first, window=self.window)
        chosen_a = self._choose_port(a, a_port) if a_port else ""
        self.pointer.click(*second, window=self.window)
        chosen_b = self._choose_port(b, b_port) if b_port else ""
        if self._menu(timeout=0.5) is not None:
            self.pointer.press("esc", "esc", window=self.window)
            raise CanvasError("A port menu is still open after cabling; the link was not made.")
        return {"cable": cable_name, "a": f"{a}:{chosen_a}", "b": f"{b}:{chosen_b}"}
