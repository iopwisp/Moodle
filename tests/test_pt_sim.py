from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import pytest
from fakes import fake_screenshot

from lab_agent import cli
from lab_agent.desktop.uia import element_matches
from lab_agent.integrations.base import ExecutionContext
from lab_agent.integrations.pt_sim import (
    STEP_FORWARD,
    WORKSPACE_LIST,
    Event,
    PTSimulation,
    SimulationError,
    _same_port,
    parse_tracert,
    path_text,
    table_rows,
    trace_path,
)


def hops(*rows: tuple[str, str, str, str]) -> list[Event]:
    return [Event(*row) for row in rows]


# ---------------------------------------------------------------------------- pure helpers
def test_path_follows_the_answer_back_and_ignores_retries_and_flooding() -> None:
    """Shapes seen in the real Event List: a DNS query retried after 15 s, a switch flooding to a dead end."""
    events = hops(("0.000", "--", "PC", "DNS"), ("0.001", "PC", "Switch", "DNS"),        # first try, lost
                  ("15.001", "--", "PC", "DNS"), ("15.002", "PC", "Switch", "DNS"),
                  ("15.003", "Switch", "Laptop", "DNS"), ("15.003", "Switch", "Router", "DNS"),  # flooded copy
                  ("15.004", "Router", "Server", "DNS"), ("15.005", "Server", "Router", "DNS"),
                  ("15.006", "Router", "Switch", "DNS"), ("15.007", "Switch", "PC", "DNS"),
                  ("15.010", "--", "PC", "HTTP"), ("15.011", "PC", "Switch", "HTTP"))
    dns = trace_path(events, "PC", "dns")
    assert dns["complete"] and dns["turnaround"] == "Server"
    assert path_text(dns["request"]) == "PC > Switch > Router > Server"
    assert path_text(dns["reply"]) == "Server > Router > Switch > PC"
    http = trace_path(events, "PC", "HTTP")
    assert not http["complete"] and http["request"] == ["PC", "Switch"] and http["reply"] == []


def test_destination_splits_an_asymmetric_round_trip() -> None:
    events = hops(("1", "PC", "R1", "HTTP"), ("2", "R1", "Server", "HTTP"), ("3", "Server", "R2", "HTTP"),
                  ("4", "R2", "PC", "HTTP"))
    assert trace_path(events, "PC", "HTTP")["reply"] == []  # where it turned is unknown without a hint
    path = trace_path(events, "PC", "HTTP", destination="Server")
    assert path["request"] == ["PC", "R1", "Server"] and path["reply"] == ["Server", "R2", "PC"]


def test_tracert_hops_and_timeouts_are_parsed_from_the_last_run() -> None:
    text = ("C:\\>tracert 10.0.0.9\nTracing route to 10.0.0.9 over a maximum of 30 hops: \n\n  1   0 ms  0 ms  0 ms  192.168.1.1\n"
            "Trace complete.\nC:\\>tracert 10.0.0.9\nTracing route to 10.0.0.9 over a maximum of 30 hops: \n\n"
            "  1   1 ms      0 ms      0 ms      192.168.1.1\n  2   *         *         *         Request timed out.\n"
            "  3   <1 ms     12 ms     0 ms      10.0.0.9\n\nTrace complete.\n")
    trace = parse_tracert(text)
    assert trace["target"] == "10.0.0.9" and trace["complete"]
    assert [h["address"] for h in trace["hops"]] == ["192.168.1.1", "", "10.0.0.9"]
    assert trace["hops"][1]["timed_out"] and trace["hops"][2]["times"] == ["<1 ms", "12 ms", "0 ms"]


def test_ports_match_by_abbreviation() -> None:
    assert _same_port("Gig0/1", "GigabitEthernet0/1") and _same_port("Fa0", "FastEthernet0")
    assert _same_port("", "Serial0/0/0") and _same_port("Ethernet 1", "Ethernet1")
    assert not _same_port("Gig0/1", "GigabitEthernet0/2") and not _same_port("0/1", "GigabitEthernet0/1")


def test_row_headers_count_rows_whose_cells_are_off_screen() -> None:
    elements = [{"control_type": "Header", "name": "Name", "rect": [10, 0, 50, 10]},
                {"control_type": "Header", "name": "1", "rect": [0, 10, 10, 20]},
                {"control_type": "DataItem", "name": "PC0", "rect": [10, 10, 50, 20]},
                {"control_type": "Header", "name": "2", "rect": [0, 20, 10, 30]}]
    assert table_rows(elements, "DataItem") == (["Name"], [["PC0"]], 2)


# ---------------------------------------------------------------------------- a fake Packet Tracer
@dataclass
class El:
    name: str
    control_type: str
    rect: tuple[int, int, int, int] = (0, 0, 0, 0)
    class_name: str = ""
    children: list[El] = field(default_factory=list)
    on_click: Any = None
    text: str = ""
    owner: Any = None  # top-level window this element lives in

    def info(self) -> dict[str, Any]:
        return {"name": self.name, "control_type": self.control_type, "class_name": self.class_name,
                "automation_id": "", "rect": list(self.rect), "visible": True}


PROTOCOLS = {"IPv4": ["ARP", "DNS", "ICMP"], "IPv6": ["ICMPv6"], "Misc": ["FTP", "HTTPS", "HTTP", "TCP"]}


class FakeSimPT:
    """Simulation Panel, filter dialog, Workspace List and a PC whose browser and Command Prompt start traffic."""

    def __init__(self, *, route: list[str] | None = None) -> None:
        self.mode = "realtime"
        self.filters = {p for names in PROTOCOLS.values() for p in names}
        self.menu: dict[str, Any] | None = None
        self.events: list[Event] = []
        self.script: list[Event] = []
        self.dock_left = 2170
        self.route = route or ["PC0", "Switch0", "Router1", "Server0"]
        self.devices = {"PC0": (100, 400), "Switch0": (300, 300), "Router1": (500, 300), "Server0": (700, 300)}
        self.links = [["Copper Straight-Through", "PC0:FastEthernet0", "Green", "Switch0:FastEthernet0/1", "Green"],
                      ["Copper Straight-Through", "Switch0:GigabitEthernet0/1", "Green", "Router1:GigabitEthernet0/0", "Green"],
                      ["Copper Straight-Through", "Router1:GigabitEthernet0/1", "Green", "Server0:FastEthernet0", "Green"]]
        self.list_open = False
        self.list_height = 600
        self.selected_link: int | None = None
        self.windows: dict[str, dict[str, Any]] = {}
        self.console = "C:\\>"
        self.url = ""
        self.posted: list[tuple[Any, ...]] = []
        self.visible_rows: int | None = None  # rows of the Event List that fit on screen

    # -- traffic
    def _round_trip(self, protocol: str, start: float) -> list[Event]:
        out = [Event(f"{start:.3f}", "--", self.route[0], protocol)]
        legs = list(zip(self.route, self.route[1:])) + list(zip(self.route[::-1], self.route[-2::-1]))
        out += [Event(f"{start + 0.001 * (i + 1):.3f}", a, b, protocol) for i, (a, b) in enumerate(legs)]
        return out

    def start(self, protocols: list[str]) -> None:
        self.script = [e for i, p in enumerate(protocols) for e in self._round_trip(p, i * 1.0)]
        self.script.insert(2, Event("0.0015", "PC0", "Switch0", "ARP"))  # invisible when ARP is filtered out

    def step(self) -> None:
        while self.script:
            event = self.script.pop(0)
            if event.type in self.filters:
                self.events.append(event)
                return

    # -- element trees
    def main_tree(self) -> El:
        kids = [El("Simulation Mode", "CheckBox", (2420, 1278, 2560, 1312), on_click=lambda: setattr(self, "mode", "simulation")),
                El("Realtime Mode", "CheckBox", (2300, 1278, 2420, 1312), on_click=lambda: setattr(self, "mode", "realtime")),
                El("Undo", "Button", (290, 60, 321, 91)), El("Select (Esc)", "CheckBox", (2, 95, 33, 126)),
                El(WORKSPACE_LIST, "Button", (485, 60, 516, 91), on_click=lambda: setattr(self, "list_open", True)),
                El("Workspace Description", "Group", (653, 162, self.dock_left - 6, 1277), class_name="CWorkspace")]
        if self.mode == "simulation":
            kids.append(self._panel())
        if self.menu is not None:
            kids.append(self._menu())
        return El("Cisco Packet Tracer - lab.pka", "Window", (0, 34, 2560, 1440), "CAppWindow", kids)

    def _panel(self) -> El:
        left = self.dock_left + 4
        wide = 2560 - left > 1000
        heads = ["Vis.", "Time(sec)", "Last Device", "At Device", "Type"]
        x, headers = left, []
        for name in heads:
            headers.append(El(name, "Header", (x, 227, x + 200, 258)))
            x += 200
        cells = []
        for row, event in enumerate(self.events):
            if self.visible_rows is not None and row >= self.visible_rows:
                continue
            values = ["Visible" if row == len(self.events) - 1 else "", event.time, event.last, event.at, event.type]
            top = 258 + 24 * row
            cells += [El(v, "TreeItem", (left + 200 * i, top, left + 200 * (i + 1), top + 24)) for i, v in enumerate(values)
                      if wide or i < 3]
        tree = El(f"Event List {len(self.events)} visible events.", "Tree", (left, 226, 2556, 1071), children=headers + cells)
        label = ", ".join(sorted(self.filters, key=str.casefold)) or "None."
        panel = El("", "Group", (left, 202, 2560, 1277), "CSimulationPanel", [
            tree, El("Reset Simulation", "Button", (left, 1073, left + 130, 1110), on_click=self._reset),
            El(STEP_FORWARD, "Button", (2387, 1138, 2423, 1170), on_click=self.step),
            El("Event List Filters - Visible Events", "Text", (left, 1202, 2556, 1220)), El(label, "Text", (left, 1222, 2556, 1241)),
            El("Edit Filters", "Button", (left, 1243, left + 190, 1273), on_click=self._open_menu),
            El("Enable or disable all filters.", "Button", (2368, 1243, 2556, 1273), on_click=self._all_or_none)])
        return El("Simulation Panel", "Window", (self.dock_left, 162, 2560, 1277), "QDockWidget", [panel])

    def _reset(self) -> None:
        self.events, self.script = [], []

    def _all_or_none(self) -> None:
        everything = {p for names in PROTOCOLS.values() for p in names}
        self.filters = set() if self.filters == everything else everything

    def _open_menu(self) -> None:
        self.menu = {"tab": "IPv4", "pending": set(self.filters), "width": 316}

    def _menu(self) -> El:
        assert self.menu is not None
        x0, right = 1113, 1113 + self.menu["width"]
        tabs = [El(t, "TabItem", (x0 + 55 * i, 393, x0 + 55 * (i + 1), 421)) for i, t in enumerate(PROTOCOLS)]
        tables = []
        for tab, names in PROTOCOLS.items():
            showing = tab == self.menu["tab"]
            items = [El(n, "DataItem", (x0 + 1 + 150 * (i % 3), 422 + 31 * (i // 3), x0 + 151 + 150 * (i % 3), 453 + 31 * (i // 3)))
                     for i, n in enumerate(names)]
            tables.append(El("", "Table", (x0, 421, right, 1057) if showing else (0, 0, 0, 0), children=items))
        return El("Cisco Packet Tracer", "Window", (x0, 393, right, 1091), "CFilterMenu",
                  [El("", "Tab", (x0, 393, x0 + 165, 421), children=tabs), *tables])

    def list_tree(self) -> El:
        rows_fit = max(1, (self.list_height - 1100) // 50)  # 1250 px (first resize) shows 3 rows
        def table(title: str, heads: list[str], rows: list[list[str]], top: int) -> El:
            kids = [El(h, "Header", (30 + 150 * i, top, 180 + 150 * i, top + 31)) for i, h in enumerate(heads)]
            for r, row in enumerate(rows):
                y = top + 31 + 45 * r
                kids.append(El(str(r + 1), "Header", (5, y, 26, y + 45)))
                if r < rows_fit:
                    kids += [El(v, "DataItem", (30 + 150 * i, y, 180 + 150 * i, y + 44)) for i, v in enumerate(row)]
            return El(title, "Table", (5, top, 800, top + 300), children=kids)
        devices = [[n, "PT", "On", str(x), str(y)] for n, (x, y) in self.devices.items()]
        return El("Workspace List", "Window", (974, 359, 1772, 359 + self.list_height), "CWorkspaceList", [
            table("Devices", ["Name", "Model", "Power", "X", "Y"], devices, 416),
            table("Link table" if self.selected_link is not None else "Links",
                  ["Type", "Origination Port", "Origination Port Status", "Destination Port", "Destination Port Status"],
                  self.links, 879),
            El("Remove Link", "Button", (1630, 1017, 1742, 1051), on_click=self._remove_link)])

    def _remove_link(self) -> None:
        if self.selected_link is not None:
            self.links.pop(self.selected_link)
            self.selected_link = None

    def device_tree(self, name: str) -> El:
        state = self.windows[name]
        kids = [El(t, "TabItem", (1004 + 82 * i, 431, 1086 + 82 * i, 459)) for i, t in enumerate(("Physical", "Config", "Desktop"))]
        if state["tab"] == "Desktop":
            if state["applet"] == "browser":
                kids += [El("close", "Button", (1990, 469, 2020, 503), on_click=lambda: state.update(applet="")),
                         El("URL", "Text", (1096, 503, 1127, 537)),
                         El("", "Edit", (1133, 503, 1784, 537), "QLineEdit", text=self.url),
                         El("Go", "Button", (1790, 503, 1902, 537), on_click=lambda: self.start(["DNS", "HTTP"]))]
            elif state["applet"] == "prompt":
                kids += [El("X", "Button", (1990, 469, 2020, 503), on_click=lambda: state.update(applet="")),
                         El("Control+F6 to exit CLI focus.", "Edit", (1016, 502, 2018, 1387), "CCommandLine", text=self.console)]
            else:
                kids += [El("Web Browser", "Button", (1862, 473, 1975, 582), on_click=lambda: state.update(applet="browser")),
                         El("Command\nPrompt", "Button", (1661, 473, 1774, 582), on_click=lambda: state.update(applet="prompt"))]
        return El(name, "Window", (992, 419, 2042, 1439), "CWorkstationDialog", kids)

    def tops(self) -> list[El]:
        trees = [self.main_tree()] + ([self.list_tree()] if self.list_open else [])
        return trees + [self.device_tree(n) for n, s in self.windows.items() if s["open"]]

    # -- posted input
    def post_click(self, window: El, x: int, y: int) -> None:
        self.posted.append(("click", window.name, x, y))
        tree = next((top for top in self.tops() if (top.name, top.class_name) == (window.name, window.class_name)), None)
        if tree is None:  # the filter dialog lives inside the main window's tree
            tree = next((e for e in walk(self.main_tree()) if e.class_name == window.class_name), window)
        hit = [e for e in walk(tree) if e.on_click and e.rect[0] <= x <= e.rect[2] and e.rect[1] <= y <= e.rect[3]]
        if hit:  # a button: Packet Tracer reacts to the click itself
            hit[-1].on_click()
            return
        if window.class_name == "CFilterMenu":
            assert self.menu is not None
            for tab in PROTOCOLS:
                left = 1113 + 55 * list(PROTOCOLS).index(tab)
                if left <= x < left + 55 and 393 <= y <= 421:
                    self.menu["tab"] = tab
            for element in walk(self._menu()):
                r = element.rect
                on_box = element.control_type == "DataItem" and r[0] <= x <= r[0] + 20 and r[1] <= y <= r[3]
                if on_box and x < 1113 + self.menu["width"] and element.name in PROTOCOLS[self.menu["tab"]]:
                    self.menu["pending"] ^= {element.name}
        elif window.class_name == "CWorkspaceList":
            for index in range(len(self.links)):
                if 879 + 31 + 45 * index <= y <= 879 + 31 + 45 * index + 44:
                    self.selected_link = index
        elif window.class_name == "CAppWindow":
            for name, (dx, dy) in self.devices.items():
                if abs(653 + dx - x) <= 20 and abs(162 + dy - y) <= 20:
                    self.windows.setdefault(name, {"tab": "Physical", "applet": ""})["open"] = True
        else:
            state = self.windows[window.name]
            for element in walk(self.device_tree(window.name)):
                r = element.rect
                if not (r[0] <= x <= r[2] and r[1] <= y <= r[3]):
                    continue
                if element.control_type == "TabItem":
                    state["tab"] = element.name
                elif element.control_type == "Edit":
                    self.focus = "url" if element.class_name == "QLineEdit" else "console"

    def post_drag(self, window: El, start: tuple[int, int], end: tuple[int, int]) -> None:
        self.posted.append(("drag", start, end))
        if abs(start[0] - (self.dock_left - 3)) <= 4:
            self.dock_left = max(700, min(2400, self.dock_left + end[0] - start[0]))

    def post_type(self, window: El, text: str) -> None:
        if getattr(self, "focus", "") == "url":
            self.url += text
        else:
            self.typed = getattr(self, "typed", "") + text

    def post_keys(self, window: El, *keys: str) -> None:
        if getattr(self, "focus", "") == "url":
            self.url = self.url[: max(0, len(self.url) - keys.count("backspace"))]
            return
        if "enter" in keys:
            line, self.typed = getattr(self, "typed", ""), ""
            self.console += line + "\n"
            if line.startswith("tracert "):
                self.console += (f"Tracing route to {line.split()[1]} over a maximum of 30 hops: \n\n"
                                 "  1   0 ms      0 ms      0 ms      192.168.1.1\n  2   1 ms      0 ms      0 ms      10.0.0.9\n\n"
                                 "Trace complete.\n\nC:\\>")
            elif line.startswith("ping ") and self.mode == "simulation":
                self.start(["ICMP"])
                self.console += f"\nPinging {line.split()[1]} with 32 bytes of data:\n"

    def post_close(self, window: El) -> None:
        if window.class_name == "CFilterMenu" and self.menu is not None:
            self.filters, self.menu = set(self.menu["pending"]), None
        elif window.class_name == "CWorkspaceList":
            self.list_open = False

    def post_resize(self, window: El, width: int, height: int) -> None:
        if window.class_name == "CFilterMenu" and self.menu is not None:
            self.menu["width"] = width
        if window.class_name == "CWorkspaceList":
            self.list_height = height


def walk(element: El, depth: int = 0) -> list[El]:
    found = [element]
    for child in element.children:
        found += walk(child, depth + 1)
    return found


class FakeSimDriver:
    """UIDriver over :class:`FakeSimPT` trees, rebuilt on every query like a live UIA tree."""

    def __init__(self, pt: FakeSimPT) -> None:
        self.pt = pt

    def _fresh(self, element: El) -> El:
        for top in self.pt.tops():
            for candidate in walk(top):
                if (candidate.name, candidate.control_type, candidate.class_name) == (element.name, element.control_type, element.class_name):
                    return candidate
        return element

    def list_windows(self) -> list[dict[str, Any]]:
        return [{**w.info(), "visible": True} for w in self.pt.tops()]

    def find_window(self, selector: dict[str, Any], timeout: float = 10) -> El | None:
        return next((w for w in self.pt.tops() if element_matches(w.info(), selector)), None)

    def find_control(self, window: El, selector: dict[str, Any], timeout: float = 10) -> El | None:
        wanted, seen = int(selector.get("found_index", 0)), 0
        for element in walk(self._fresh(window))[1:]:
            if element_matches(element.info(), selector):
                if seen == wanted:
                    return element
                seen += 1
        return None

    def snapshot(self, window: El, max_depth: int = 6, limit: int = 400) -> list[dict[str, Any]]:
        return [e.info() for e in walk(self._fresh(window))][:limit]

    def click(self, control: El, *, double: bool = False) -> None:
        raise AssertionError(f"UIA Invoke would bring Packet Tracer to the front ({control.name!r}); post a click")

    def type_text(self, control: El, text: str, *, replace: bool = True) -> None:
        raise AssertionError("Setting a UIA value would bring the device window to the front; post the keys")

    def read_value(self, control: El) -> str:
        return self._fresh(control).text

    def read_text(self, control: El) -> str:
        return self._fresh(control).text

    def read_lines(self, control: El) -> list[str]:
        return self.read_text(control).split("\n")

    def close(self, window: El) -> None:
        if window.class_name == "CWorkspaceList":
            self.pt.list_open = False
        elif window.name in self.pt.windows:
            self.pt.windows[window.name]["open"] = False

    def window_title(self, window: El) -> str:
        return window.name

    def rectangle(self, element: El) -> tuple[int, int, int, int]:
        return self._fresh(element).rect


class FakePoster:
    def __init__(self, pt: FakeSimPT) -> None:
        self.pt = pt

    def click(self, window: El, x: int, y: int) -> None:
        self.pt.post_click(window, x, y)

    def drag(self, window: El, start: tuple[int, int], end: tuple[int, int]) -> None:
        self.pt.post_drag(window, start, end)

    def type_text(self, window: El, text: str) -> None:
        self.pt.post_type(window, text)

    def press(self, window: El, *keys: str) -> None:
        self.pt.post_keys(window, *keys)

    def close(self, window: El) -> None:
        self.pt.post_close(window)

    def resize(self, window: El, width: int, height: int) -> None:
        self.pt.post_resize(window, width, height)


@pytest.fixture
def sim() -> tuple[FakeSimPT, PTSimulation]:
    pt = FakeSimPT()
    driver = FakeSimDriver(pt)
    return pt, PTSimulation(driver, driver.find_window({"class_name": "CAppWindow"}), FakePoster(pt), sleep=lambda s: None)


# ---------------------------------------------------------------------------- PTSimulation
def test_filters_are_set_exactly_and_checked_by_the_visible_events_label(sim) -> None:  # type: ignore[no-untyped-def]
    pt, simulation = sim
    simulation.set_mode("simulation")
    assert simulation.set_filters(["dns", "HTTP"]) == ["DNS", "HTTP"]
    assert pt.filters == {"DNS", "HTTP"} and pt.menu is None  # closed again; HTTP sits in the third, cut-off column
    with pytest.raises(SimulationError, match="no event filter SMB"):
        simulation.set_filters(["DNS", "SMB"])


def test_a_web_request_is_stepped_until_the_answer_is_back(sim) -> None:  # type: ignore[no-untyped-def]
    pt, simulation = sim
    simulation.set_mode("simulation")
    simulation.set_filters(["DNS", "HTTP"])
    simulation.reset()
    pt.url = "old.page"
    simulation.browse("PC0", "www.lab.local")
    assert pt.url == "www.lab.local" and pt.windows["PC0"]["applet"] == "browser"
    original = pt.dock_left
    with simulation.wide_panel():
        assert pt.dock_left < original  # widened so At Device and Type are exposed
        events, _, stopped = simulation.run(lambda found: trace_path(found, "PC0", "HTTP")["complete"])
    assert pt.dock_left == original and stopped == "done"
    assert all(e.type in {"DNS", "HTTP"} for e in events)  # the ARP frame stayed hidden
    assert path_text(trace_path(events, "PC0", "HTTP")["request"]) == "PC0 > Switch0 > Router1 > Server0"


def test_links_are_listed_and_removed_through_the_workspace_list(sim) -> None:  # type: ignore[no-untyped-def]
    pt, simulation = sim
    topology = simulation.topology()
    assert [d["name"] for d in topology["devices"]] == ["PC0", "Switch0", "Router1", "Server0"]
    assert topology["links"][1] == {"type": "Copper Straight-Through", "a": "Switch0", "a_port": "GigabitEthernet0/1",
                                    "a_status": "Green", "b": "Router1", "b_port": "GigabitEthernet0/0", "b_status": "Green"}
    assert pt.list_height > 1250  # grown past the first size until every row was exposed
    result = simulation.remove_link("Router1:Gig0/0", "Switch0")
    assert result["links_after"] == 2 and all("Router1:GigabitEthernet0/0" not in row for row in pt.links)
    with pytest.raises(SimulationError, match="No link between PC0 and Server0; the links are"):
        simulation.remove_link("PC0", "Server0")


def test_tracert_reads_only_its_own_run_when_the_same_command_is_on_screen(sim) -> None:  # type: ignore[no-untyped-def]
    pt, simulation = sim
    pt.console = ("C:\\>tracert 10.0.0.9\nTracing route to 10.0.0.9 over a maximum of 30 hops: \n\n"
                  "  1   9 ms      9 ms      9 ms      172.16.0.1\n\nTrace complete.\n\nC:\\>")
    trace = simulation.traceroute("PC0", "10.0.0.9")
    assert [h["address"] for h in trace["hops"]] == ["192.168.1.1", "10.0.0.9"]  # not the stale 172.16.0.1 run
    assert pt.windows["PC0"]["applet"] == "prompt"


# ---------------------------------------------------------------------------- adapter and CLI
@pytest.fixture
def adapter_pt(registry, monkeypatch):  # type: ignore[no-untyped-def]
    pt = FakeSimPT()
    driver = FakeSimDriver(pt)
    monkeypatch.setattr("lab_agent.applications.default_driver", lambda: driver)
    monkeypatch.setattr(ExecutionContext, "sleep", lambda self, seconds: None)
    registry.adapter("packet_tracer").poster_factory = lambda: FakePoster(pt)
    return pt


def test_trace_traffic_records_paths_events_and_a_screenshot(adapter_pt, registry, tmp_path: Path) -> None:  # type: ignore[no-untyped-def]
    context = ExecutionContext(tmp_path / "ws", "week2", step_id=5, screenshot_fn=fake_screenshot)
    result = registry.execute("packet_tracer.trace_traffic", {"source": "PC0", "url": "www.lab.local"}, context)
    assert result.verified, result.reason
    assert result.details["paths"]["HTTP"] == "PC0 > Switch0 > Router1 > Server0"
    assert result.details["replies"]["DNS"] == "Server0 > Router1 > Switch0 > PC0"
    record = json.loads((tmp_path / "ws" / "results" / "pt_events_05.json").read_text(encoding="utf-8"))
    assert record["visible_events"] == ["DNS", "HTTP"] and len(record["events"]) == 14
    assert any(item["type"] == "screenshot" for item in result.evidence)

    ping = registry.execute("packet_tracer.trace_traffic", {"source": "PC0", "command": "ping 10.0.0.9"}, context)
    assert ping.verified and ping.details["visible_events"] == ["ICMP"]


def test_a_broken_path_is_reported_not_invented(adapter_pt, registry, tmp_path: Path) -> None:  # type: ignore[no-untyped-def]
    adapter_pt.route = ["PC0", "Switch0"]  # frames die at the switch: nothing comes back
    adapter_pt._round_trip = lambda protocol, start: [Event(f"{start:.3f}", "--", "PC0", protocol),  # type: ignore[method-assign]
                                                      Event(f"{start + 0.001:.3f}", "PC0", "Switch0", protocol)]
    context = ExecutionContext(tmp_path / "ws", "week2", step_id=6, screenshot_fn=fake_screenshot)
    result = registry.execute("packet_tracer.trace_traffic", {"source": "PC0", "url": "www.lab.local", "max_steps": 10}, context)
    assert not result.verified and "no complete DNS, HTTP exchange" in result.reason
    assert result.details["paths"]["DNS"] == "PC0 > Switch0" and result.details["stopped"] == "no new events"


def test_lab_agent_do_runs_one_capability_and_registers_evidence(adapter_pt, tmp_path: Path, monkeypatch, capsys) -> None:  # type: ignore[no-untyped-def]
    from lab_agent.integrations.registry import build_registry

    workspace = tmp_path / "ws"
    (workspace / "state").mkdir(parents=True)
    (workspace / "state" / "state.json").write_text("{}", encoding="utf-8")
    registry = build_registry(fake_screenshot)
    registry.adapter("packet_tracer").poster_factory = lambda: FakePoster(adapter_pt)
    monkeypatch.setattr(cli, "_registry", lambda: registry)
    monkeypatch.setattr(cli, "take_screenshot", fake_screenshot)
    assert cli.main(["do", str(workspace), "packet_tracer.delete_link", "-p", "a=Switch0", "-p", "b=Router1"]) == 0
    output = json.loads(capsys.readouterr().out)
    assert output["verified"] and output["details"]["link"] == "Switch0:GigabitEthernet0/1 - Router1:GigabitEthernet0/0"
    assert any(path.startswith("results/pt_delete_link_") for path in output["evidence"])
    assert len(adapter_pt.links) == 2
    assert cli.main(["do", str(workspace), "packet_tracer.traceroute", "-p", "source=PC0"]) == 2  # target is required


def test_posted_pointer_places_with_two_clicks_and_sends_menu_clicks_to_the_menu() -> None:
    from fakes import FakeDriver, FakeWindow

    from lab_agent.desktop.messages import PostedPointer

    class Recorder:
        def __init__(self) -> None:
            self.calls: list[tuple[Any, ...]] = []

        def click(self, window: Any, x: int, y: int) -> None:
            self.calls.append(("click", window.class_name, x, y))

        def type_text(self, window: Any, text: str) -> None:
            self.calls.append(("type", window.class_name, text))

        def press(self, window: Any, *keys: str) -> None:
            self.calls.append(("press", window.class_name, *keys))

    driver = FakeDriver()
    main = driver.add_window(FakeWindow("Cisco Packet Tracer - lab.pka", class_name="CAppWindow", rect=(0, 0, 1000, 800)))
    driver.add_window(FakeWindow("Cisco Packet Tracer", class_name="QMenu", rect=(500, 500, 650, 600)))  # a port menu
    recorder = Recorder()
    pointer = PostedPointer(driver, recorder, pause=0)
    pointer.click(520, 510, window=main)
    pointer.click(100, 100, window=main)
    pointer.drag((10, 900), (300, 300), window=main)
    pointer.type_text("PC", window=main)
    pointer.press("end", "backspace", window=main)
    assert recorder.calls == [("click", "QMenu", 520, 510), ("click", "CAppWindow", 100, 100),
                              ("click", "CAppWindow", 10, 900), ("click", "CAppWindow", 300, 300),
                              ("type", "CAppWindow", "PC"), ("press", "CAppWindow", "end", "backspace")]


def test_events_below_the_visible_list_are_not_silently_dropped(adapter_pt, registry, tmp_path: Path) -> None:  # type: ignore[no-untyped-def]
    adapter_pt.visible_rows = 5  # Packet Tracer would not scroll to the newest rows
    context = ExecutionContext(tmp_path / "ws", "week2", step_id=7, screenshot_fn=fake_screenshot)
    result = registry.execute("packet_tracer.trace_traffic", {"source": "PC0", "url": "www.lab.local"}, context)
    assert not result.verified and "holds 8 events but only 5 could be read" in result.reason
