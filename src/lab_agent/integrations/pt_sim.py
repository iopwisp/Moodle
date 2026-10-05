"""Packet Tracer Simulation mode, topology list and device consoles - driven without focus or the real mouse.

UI Automation finds every control and reads every result; all input is posted (see :mod:`lab_agent.desktop.messages`)
because UIA *Invoke* and *SetValue* bring Packet Tracer (or the device window) to the front.  What Packet Tracer 8.2.2
shows and how each piece is used (recorded on the real program):

* ``Realtime Mode`` / ``Simulation Mode`` - check-box buttons at the bottom right.
* Simulation Panel (dock "Simulation Panel"): the Event List is a ``QTreeWidget`` named "Event List N visible
  events." whose rows are ``TreeItem`` cells (Vis., Time(sec), Last Device, At Device, Type).  Qt exposes only the
  cells of columns that are on screen, so the dock is widened (posted drag of its separator) while the list is read
  and the screenshot is taken, then put back.
* ``Step forward packets to the next step`` (Capture / Forward) and ``Reset Simulation``.
* ``Edit Filters`` opens ``CFilterMenu`` (tabs IPv4 / IPv6 / Misc, one check box per protocol as a ``DataItem``).
  Neither the Toggle pattern nor the keyboard reaches Packet Tracer's filter model, only a click does, so boxes are
  clicked with posted messages after "Show All/None" has cleared them all.  The label under "Event List Filters -
  Visible Events" is the check.  At 150 % the dialog cuts its third column off, so it is widened first.
* Workspace List (toolbar "View the workspace as a tabular list of devices and links."): window ``CWorkspaceList``
  with the tables Devices (Name, Model, Power, X, Y) and Links (Type, ports and their status) and "Remove Link".
  Device X/Y are canvas pixels from the workspace's top-left corner at 100 % zoom - where a device is clicked.
* PC Desktop > Web Browser: URL ``QLineEdit`` (typed, then its UIA value read back) and Go.  Desktop > Command
  Prompt and the IOS CLI tab: ``CCommandLine``, typed into with posted ``WM_CHAR``; its text lines are read whole
  (the UIA value keeps only the last thousand characters or so).
"""

from __future__ import annotations

import re
import time
from collections.abc import Callable, Iterable, Iterator
from contextlib import contextmanager
from dataclasses import asdict, dataclass
from typing import Any

STEP_FORWARD = "Step forward packets to the next step"
SHOW_ALL_NONE = "Enable or disable all filters."
WORKSPACE_LIST = "View the workspace as a tabular list of devices and links."
COLUMNS = {"time(sec)": "time", "last device": "last", "at device": "at", "type": "type"}

Rect = tuple[int, int, int, int]


class SimulationError(RuntimeError):
    """Packet Tracer did not show what was expected; the message says what to check."""


def centre(rect: Iterable[int]) -> tuple[int, int]:
    left, top, right, bottom = list(rect)[:4]
    return (left + right) // 2, (top + bottom) // 2


# ---------------------------------------------------------------------------- pure helpers
@dataclass(frozen=True)
class Event:
    time: str
    last: str
    at: str
    type: str

    @property
    def seconds(self) -> float:
        try:
            return float(self.time)
        except ValueError:
            return 0.0


def table_rows(elements: list[dict[str, Any]], cell_type: str) -> tuple[list[str], list[list[str]], int]:
    """Column names, rows and the number of row headers of a Qt table/tree from a UIA snapshot of it.

    Cells are grouped into rows by their top edge.  Column headers share the topmost header row; numbered row
    headers ("1", "2", ...) sit lower and only count the rows - Qt lists them even for rows scrolled out of view,
    whose cells it does not expose.
    """
    headers = [e for e in elements if e.get("control_type") == "Header"]
    top = min((e["rect"][1] for e in headers), default=None)
    names = [str(e["name"]) for e in headers if e["rect"][1] == top]
    numbered = sum(1 for e in headers if e["rect"][1] != top and str(e["name"]).isdigit())
    rows: list[list[str]] = []
    current: list[str] = []
    row_top = None
    for element in elements:
        if element.get("control_type") != cell_type:
            continue
        if row_top is not None and element["rect"][1] != row_top:
            rows.append(current)
            current = []
        current.append(str(element.get("name", "")))
        row_top = element["rect"][1]
    if current:
        rows.append(current)
    return names, rows, numbered


def parse_events(elements: list[dict[str, Any]]) -> list[Event]:
    names, rows, _ = table_rows(elements, "TreeItem")
    index = {COLUMNS[name.casefold()]: i for i, name in enumerate(names) if name.casefold() in COLUMNS}
    if set(index) != set(COLUMNS.values()):
        raise SimulationError(f"The Event List does not show the columns Time, Last Device, At Device and Type (it shows {names}).")
    width = max(index.values()) + 1
    return [Event(row[index["time"]], row[index["last"]], row[index["at"]], row[index["type"]]) for row in rows if len(row) >= width]


def merge_events(known: list[Event], fresh: Iterable[Event]) -> int:
    """Append events not seen before (the list may scroll; Packet Tracer only ever adds rows).  Returns how many."""
    seen = set(known)
    added = 0
    for event in fresh:
        if event not in seen:
            known.append(event)
            seen.add(event)
            added += 1
    return added


def _forward_chain(hops: list[Event], source: str) -> list[Event]:
    start = next((i for i in range(len(hops) - 1, -1, -1) if hops[i].last == source), None)  # the last attempt
    if start is None:
        return []
    chain = [hops[start]]
    for hop in hops[start + 1:]:
        if hop.last == chain[-1].at and hop.seconds >= chain[-1].seconds:
            chain.append(hop)
    return chain


def trace_path(events: list[Event], source: str, protocol: str, destination: str = "") -> dict[str, Any]:
    """Device-by-device path of one protocol's exchange as the Event List recorded it.

    The answer that finally reaches ``source`` is followed backwards - each hop came from the latest earlier hop
    that arrived where it left - so retries and frames a switch flooded to dead ends drop out.  The request ends
    where the packet turned back (or at ``destination`` when given); without an answer the furthest forward chain
    from the source is reported as incomplete.
    """
    hops = [e for e in events if e.type.casefold() == protocol.casefold() and e.last not in {"", "--"}]
    end = next((i for i in range(len(hops) - 1, -1, -1) if hops[i].at == source), None)
    if end is None:
        chain, complete = _forward_chain(hops, source), False
    else:
        chain = [hops[end]]
        for hop in reversed(hops[:end]):
            if chain[0].last == source:
                break
            if hop.at == chain[0].last and hop.seconds <= chain[0].seconds:
                chain.insert(0, hop)
        complete = chain[0].last == source
    result: dict[str, Any] = {"protocol": protocol.upper(), "complete": complete, "devices": [], "request": [], "reply": [],
                              "turnaround": ""}
    if not chain:
        return result
    devices = [chain[0].last] + [hop.at for hop in chain]
    split = None
    if destination and destination in devices[1:]:
        split = devices.index(destination, 1)
    elif complete:
        split = next((k for k in range(1, len(devices) - 1) if devices[k + 1] == devices[k - 1]), None)
    if split is None:
        request, reply = devices, []
    else:
        request, reply = devices[: split + 1], devices[split:] if complete else []
    result.update(devices=devices, request=request, reply=reply, turnaround=devices[split] if split is not None else "")
    return result


def path_text(devices: list[str]) -> str:
    return " > ".join(devices)


def parse_tracert(text: str) -> dict[str, Any]:
    """Hops of a Packet Tracer / Windows ``tracert`` (the last run in ``text``)."""
    start = text.rfind("Tracing route to")
    body = text[start:] if start >= 0 else text
    target = re.search(r"Tracing route to\s+(\S+)", body)
    hops = []
    for line in body.splitlines():
        match = re.match(r"^\s*(\d{1,2})\s+(.*?)\s*$", line)
        if not match:
            continue
        times = re.findall(r"<?\d+\s*ms|\*", match.group(2))
        address = re.search(r"(\d{1,3}(?:\.\d{1,3}){3})\s*$", match.group(2))
        if not times:
            continue
        hops.append({"hop": int(match.group(1)), "times": [re.sub(r"\s+", " ", t) for t in times],
                     "address": address.group(1) if address else "", "timed_out": address is None})
    return {"target": target.group(1).rstrip(":") if target else "", "hops": hops, "complete": "Trace complete" in body}


def split_end(value: str) -> tuple[str, str]:
    """``"Router1:GigabitEthernet0/1"`` -> ``("Router1", "GigabitEthernet0/1")``; wireless ends have no port."""
    device, _, port = value.partition(":")
    return device.strip(), port.strip()


def _same_port(wanted: str, actual: str) -> bool:
    """``Gig0/1`` names ``GigabitEthernet0/1``; an empty wish matches any port."""
    if not wanted:
        return True
    want, have = (re.sub(r"\s+", "", value.casefold()) for value in (wanted, actual))
    if want == have:
        return True
    w_name, w_number = re.match(r"([a-z-]*)(.*)", want).groups()  # type: ignore[union-attr]
    h_name, h_number = re.match(r"([a-z-]*)(.*)", have).groups()  # type: ignore[union-attr]
    return bool(w_name) and w_number == h_number and h_name.startswith(w_name)


# ---------------------------------------------------------------------------- driving Packet Tracer
class PTSimulation:
    """Drives one Packet Tracer main window through UI Automation plus posted window messages."""

    def __init__(self, driver: Any, window: Any, poster: Any, *, sleep: Callable[[float], None] = time.sleep,
                 wait: float = 0.6) -> None:
        self.driver, self.window, self.poster = driver, window, poster
        self.sleep = sleep
        self.wait = wait

    # ------------------------------------------------------------------ helpers
    def _find(self, selector: dict[str, Any], window: Any = None, timeout: float = 0) -> Any:
        return self.driver.find_control(window if window is not None else self.window, selector, timeout=timeout)

    def _control(self, selector: dict[str, Any], what: str, window: Any = None, timeout: float = 3) -> Any:
        control = self._find(selector, window, timeout)
        if control is None:
            raise SimulationError(f"{what} is not visible in Packet Tracer ({selector}).")
        return control

    def _rect(self, element: Any) -> Rect:
        return self.driver.rectangle(element)

    def _press(self, control: Any, window: Any = None) -> None:
        """Click a button with a posted message: UIA Invoke would also bring Packet Tracer to the front."""
        self.poster.click(window if window is not None else self.window, *centre(self._rect(control)))

    # ------------------------------------------------------------------ mode
    def mode(self) -> str:
        return "simulation" if self._find({"title": STEP_FORWARD, "control_type": "Button"}) is not None else "realtime"

    def set_mode(self, mode: str) -> str:
        wanted = mode.strip().casefold()
        if wanted not in {"realtime", "simulation"}:
            raise ValueError("mode must be 'realtime' or 'simulation'")
        if self.mode() != wanted:
            button = "Simulation Mode" if wanted == "simulation" else "Realtime Mode"
            self._press(self._control({"title": button, "control_type": "CheckBox"}, f"The {button} button"))
            self.sleep(self.wait)
        if self.mode() != wanted:
            raise SimulationError(f"Packet Tracer did not switch to {wanted} mode.")
        return wanted

    # ------------------------------------------------------------------ event filters
    def visible_filters(self) -> list[str]:
        panel = self._control({"class_name": "CSimulationPanel", "control_type": "Group"}, "The Simulation Panel")
        texts = [e for e in self.driver.snapshot(panel, max_depth=4, limit=400) if e.get("control_type") == "Text"]
        for index, element in enumerate(texts):
            if str(element.get("name", "")).startswith("Event List Filters"):
                label = str(texts[index + 1].get("name", "")) if index + 1 < len(texts) else ""
                return [] if label.strip().rstrip(".") in {"", "None"} else [p.strip() for p in label.split(",") if p.strip()]
        raise SimulationError("The 'Event List Filters - Visible Events' label is not in the Simulation Panel.")

    def set_filters(self, protocols: Iterable[str]) -> list[str]:
        wanted = {p.strip().upper(): p.strip() for p in protocols if p.strip()}
        if not wanted:
            raise ValueError("Name at least one protocol to show, e.g. DNS and HTTP.")
        if {p.upper() for p in self.visible_filters()} == set(wanted):
            return self.visible_filters()
        for _ in range(3):  # Show All/None: partial -> all -> none
            if not self.visible_filters():
                break
            self._press(self._control({"title": SHOW_ALL_NONE, "control_type": "Button"}, "The Show All/None button"))
            self.sleep(self.wait / 2)
        if self.visible_filters():
            raise SimulationError("Show All/None did not clear the event filters.")
        self._press(self._control({"title": "Edit Filters", "control_type": "Button"}, "The Edit Filters button"))
        menu = self._control({"class_name": "CFilterMenu", "control_type": "Window"}, "The event filter dialog", timeout=4)
        clicked: set[str] = set()
        offered: set[str] = set()
        try:
            left, top, right, bottom = self._rect(menu)
            self.poster.resize(menu, int((right - left) * 1.7), bottom - top)  # the third column is cut off at 150 %
            menu = self._control({"class_name": "CFilterMenu", "control_type": "Window"}, "The event filter dialog")
            for tab in ("IPv4", "IPv6", "Misc"):
                tab_item = self._find({"title": tab, "control_type": "TabItem"}, menu, timeout=1)
                if tab_item is None:
                    continue
                self.poster.click(menu, *centre(self._rect(tab_item)))
                self.sleep(self.wait / 2)
                for name, rect in self._visible_filter_cells(menu):
                    offered.add(name.upper())
                    if name.upper() in wanted and name.upper() not in clicked:
                        self.poster.click(menu, rect[0] + max(8, (rect[3] - rect[1]) // 2), (rect[1] + rect[3]) // 2)
                        clicked.add(name.upper())
                        self.sleep(0.2)
        finally:
            self.poster.close(menu)
            self.sleep(self.wait)
        unknown = sorted(set(wanted) - offered)
        if unknown:
            raise SimulationError(f"Packet Tracer has no event filter {', '.join(unknown)}; it offers {', '.join(sorted(offered))}.")
        shown = self.visible_filters()
        if {p.upper() for p in shown} != set(wanted):
            raise SimulationError(f"Visible events are {shown or 'none'} instead of {sorted(wanted.values())}.")
        return shown

    def _visible_filter_cells(self, menu: Any) -> list[tuple[str, Rect]]:
        """Check boxes of the tab on top: Qt lists the boxes of hidden tabs too, at the same screen positions."""
        cells: list[tuple[str, Rect]] = []
        showing = False
        for element in self.driver.snapshot(menu, max_depth=6, limit=600):
            if element.get("control_type") == "Table":
                rect = element["rect"]
                showing = rect[2] > rect[0] and rect[3] > rect[1]
            elif showing and element.get("control_type") == "DataItem" and element.get("name"):
                cells.append((str(element["name"]), tuple(element["rect"])))  # type: ignore[arg-type]
        return cells

    # ------------------------------------------------------------------ event list
    def reset(self) -> None:
        self._press(self._control({"title": "Reset Simulation", "control_type": "Button"}, "The Reset Simulation button"))
        self.sleep(self.wait)

    def step(self) -> None:
        self._press(self._control({"title": STEP_FORWARD, "control_type": "Button"}, "The Capture / Forward button"))

    def _event_tree(self) -> Any:
        return self._control({"title_re": r"^Event List", "control_type": "Tree"}, "The Event List")

    def read_events(self) -> list[Event]:
        return parse_events(self.driver.snapshot(self._event_tree(), max_depth=1, limit=5000))

    def columns_visible(self) -> bool:
        tree = self._event_tree()
        right = self._rect(tree)[2]
        headers = [e for e in self.driver.snapshot(tree, max_depth=1, limit=50) if e.get("control_type") == "Header"]
        kind = next((h for h in headers if str(h.get("name", "")).casefold() == "type"), None)
        return kind is not None and kind["rect"][0] < right - 10

    @contextmanager
    def wide_panel(self, width: int = 1300) -> Iterator[None]:
        """Widen the docked Simulation Panel so every Event List column is on screen; restore it afterwards."""
        if self.columns_visible():
            yield
            return
        dock = self._control({"title": "Simulation Panel", "class_name": "QDockWidget"}, "The Simulation Panel")
        original = self._rect(dock)
        main = self._rect(self.window)
        on_right = (original[0] + original[2]) / 2 > (main[0] + main[2]) / 2
        middle = (original[1] + original[3]) // 2
        edge = original[0] - 3 if on_right else original[2] + 3
        grow = max(0, min(width - (original[2] - original[0]), (main[2] - main[0]) // 2))
        self.poster.drag(self.window, (edge, middle), (edge - grow if on_right else edge + grow, middle))
        self.sleep(self.wait)
        try:
            yield
        finally:
            for _ in range(3):  # Qt may stop the separator a little short; correct by the remaining distance
                now = self._rect(self._control({"title": "Simulation Panel", "class_name": "QDockWidget"}, "The Simulation Panel"))
                current, target = (now[0], original[0]) if on_right else (now[2], original[2])
                if abs(current - target) <= 6:
                    break
                start = current - 3 if on_right else current + 3
                self.poster.drag(self.window, (start, middle), (start + target - current, middle))
                self.sleep(self.wait)

    def run(self, done: Callable[[list[Event]], bool], *, max_steps: int = 80, idle_steps: int = 3,
            step_wait: float = 0.7) -> tuple[list[Event], int, str]:
        """Capture / Forward until ``done(events)``, nothing new for ``idle_steps`` steps, or ``max_steps``."""
        events: list[Event] = []
        merge_events(events, self.read_events())
        steps = idle = 0
        while True:
            if done(events):
                return events, steps, "done"
            if steps >= max_steps:
                return events, steps, "step limit"
            self.step()
            steps += 1
            self.sleep(step_wait)
            idle = 0 if merge_events(events, self.read_events()) else idle + 1
            if idle >= idle_steps:
                listed = self.event_count()
                if listed is not None and listed > len(events):  # rows below the visible part of the list
                    raise SimulationError(f"The Event List holds {listed} events but only {len(events)} could be read; "
                                          "make the Simulation Panel taller and run again.")
                return events, steps, "no new events"

    def event_count(self) -> int | None:
        """What the list itself says ("Event List 19 visible events.")."""
        own = self.driver.snapshot(self._event_tree(), max_depth=0, limit=1)
        match = re.search(r"(\d+)\s+visible events", str(own[0].get("name", ""))) if own else None
        return int(match.group(1)) if match else None

    # ------------------------------------------------------------------ workspace list
    def workspace_list(self) -> Any:
        selector = {"title": "Workspace List", "class_name": "CWorkspaceList"}
        window = self.driver.find_window(selector, timeout=0)
        if window is None:
            self._press(self._control({"title": WORKSPACE_LIST, "control_type": "Button"}, "The Workspace List button"))
            window = self.driver.find_window(selector, timeout=5)
            if window is None:
                raise SimulationError("The Workspace List window did not open.")
            self.poster.resize(window, 1400, 1250)  # Qt exposes only the cells of rows on screen
            self.sleep(self.wait)
        return window

    def _table(self, window: Any, title_re: str, what: str) -> tuple[list[str], list[list[str]], list[list[Rect]]]:
        for attempt in range(4):
            table = self._control({"title_re": title_re, "control_type": "Table"}, what, window)
            elements = self.driver.snapshot(table, max_depth=1, limit=5000)
            names, rows, numbered = table_rows(elements, "DataItem")
            if numbered <= len(rows):
                break
            if attempt == 3:
                raise SimulationError(f"{what} has {numbered} rows but only {len(rows)} fit on screen; enlarge the Workspace List window.")
            left, top, right, bottom = self._rect(window)  # Qt exposes only the rows on screen: make the window taller
            self.poster.resize(window, right - left, int((bottom - top) * 1.4))
            self.sleep(self.wait)
        rects: list[list[Rect]] = []
        row_top = None
        for element in elements:
            if element.get("control_type") != "DataItem":
                continue
            if row_top != element["rect"][1]:
                rects.append([])
                row_top = element["rect"][1]
            rects[-1].append(tuple(element["rect"]))  # type: ignore[arg-type]
        return names, rows, rects

    def topology(self) -> dict[str, Any]:
        window = self.workspace_list()
        _, device_rows, _ = self._table(window, r"^Devices$", "The Devices table")
        _, link_rows, _ = self._table(window, r"^Link", "The Links table")
        devices = [{"name": row[0], "model": row[1], "power": row[2] if len(row) > 2 else "",
                    "x": int(row[3]) if len(row) > 3 and row[3].lstrip("-").isdigit() else None,
                    "y": int(row[4]) if len(row) > 4 and row[4].lstrip("-").isdigit() else None} for row in device_rows if row]
        links = []
        for row in link_rows:
            if len(row) < 4:
                continue
            (a, a_port), (b, b_port) = split_end(row[1]), split_end(row[3])
            links.append({"type": row[0], "a": a, "a_port": a_port, "a_status": row[2], "b": b, "b_port": b_port,
                          "b_status": row[4] if len(row) > 4 else ""})
        return {"devices": devices, "links": links}

    def remove_link(self, first: str, second: str) -> dict[str, Any]:
        window = self.workspace_list()
        ends = [split_end(first), split_end(second)]
        _, rows, rects = self._table(window, r"^Link", "The Links table")
        match = None
        for index, row in enumerate(rows):
            if len(row) < 4:
                continue
            (a, a_port), (b, b_port) = split_end(row[1]), split_end(row[3])
            for (d1, p1), (d2, p2) in (ends, ends[::-1]):
                if (d1.casefold(), d2.casefold()) == (a.casefold(), b.casefold()) and _same_port(p1, a_port) and _same_port(p2, b_port):
                    match = index
        if match is None:
            listed = "; ".join(f"{row[1]} - {row[3]}" for row in rows if len(row) >= 4)
            raise SimulationError(f"No link between {first} and {second}; the links are: {listed or 'none'}.")
        removed = {"type": rows[match][0], "a": rows[match][1], "b": rows[match][3]}
        self.poster.click(window, *centre(rects[match][0]))  # select the row
        self.sleep(self.wait / 2)
        self._press(self._control({"title": "Remove Link", "control_type": "Button"}, "The Remove Link button", window), window)
        self.sleep(self.wait)
        _, after, _ = self._table(window, r"^Link", "The Links table")
        still = [row for row in after if len(row) >= 4 and {row[1], row[3]} == {removed["a"], removed["b"]}]
        if still or len(after) != len(rows) - 1:
            raise SimulationError(f"The link {removed['a']} - {removed['b']} is still listed after Remove Link.")
        return {"removed": removed, "links_before": len(rows), "links_after": len(after)}

    def close_workspace_list(self) -> None:
        window = self.driver.find_window({"title": "Workspace List", "class_name": "CWorkspaceList"}, timeout=0)
        if window is not None:
            self.poster.close(window)

    # ------------------------------------------------------------------ device windows
    def open_device(self, name: str, hints: Iterable[tuple[int, int]] = ()) -> Any:
        """The device's window; opened with a posted click where the Workspace List (or a survey) puts the device."""
        window = self.driver.find_window({"title": name}, timeout=0)
        if window is not None:
            return window
        points = list(hints)
        try:
            device = next((d for d in self.topology()["devices"] if d["name"] == name), None)
        finally:
            self.close_workspace_list()
        if device is None:
            raise SimulationError(f"There is no device named {name!r} in this Packet Tracer file.")
        if device.get("x") is not None and device.get("y") is not None:
            area = self._rect(self._control({"class_name": "CWorkspace", "control_type": "Group"}, "The logical workspace"))
            points.insert(0, (area[0] + int(device["x"]), area[1] + int(device["y"])))
        select = self._find({"title": "Select (Esc)", "control_type": "CheckBox"})
        if select is not None:
            self._press(select)  # leave the delete / inspect / cable tools
        for point in points:
            self.poster.click(self.window, *point)
            window = self.driver.find_window({"title": name}, timeout=4)
            if window is not None:
                return window
        raise SimulationError(f"Clicking {name} on the canvas did not open its window (zoomed or scrolled view?); "
                              f"click {name} once in Packet Tracer, then resume.")

    def _desktop(self, window: Any) -> None:
        tab = self._find({"title": "Desktop", "control_type": "TabItem"}, window, timeout=3)
        if tab is None:
            raise SimulationError(f"{self.driver.window_title(window)} has no Desktop tab; is it a PC, laptop or server?")
        self.poster.click(window, *centre(self._rect(tab)))
        self.sleep(self.wait / 2)

    def _launch_applet(self, window: Any, button: dict[str, Any], ready: dict[str, Any]) -> Any:
        """Desktop > applet; another applet that is open is closed first (its launcher grid is hidden then)."""
        control = self._find(ready, window, timeout=0.5)
        if control is not None:
            return control
        launcher = self._find(button, window, timeout=1)
        if launcher is None:
            closer = self._find({"title_re": "(?i)^(close|x)$", "control_type": "Button"}, window, timeout=0.5)
            if closer is not None:
                self._press(closer, window)
                self.sleep(self.wait / 2)
            launcher = self._find(button, window, timeout=2)
        if launcher is None:
            raise SimulationError(f"{self.driver.window_title(window)} shows no {button.get('title') or button.get('title_re')} button.")
        self._press(launcher, window)
        self.sleep(self.wait)
        return self._control(ready, f"The applet of {self.driver.window_title(window)}", window, timeout=4)

    def browse(self, device: str, url: str, hints: Iterable[tuple[int, int]] = ()) -> None:
        window = self.open_device(device, hints)
        self._desktop(window)
        self._launch_applet(window, {"title": "Web Browser", "control_type": "Button"}, {"title": "Go", "control_type": "Button"})
        field = self._url_field(window)
        current = str(self.driver.read_value(field) or "")
        self.poster.click(window, *centre(self._rect(field)))  # setting the UIA value would bring the window to the front
        self.poster.press(window, "end", *(["backspace"] * (len(current) + 2)))
        self.poster.type_text(window, url)
        self.sleep(self.wait / 2)
        shown = str(self.driver.read_value(self._url_field(window)) or "")
        if shown != url:
            raise SimulationError(f"The URL field of {device} shows {shown!r} instead of {url!r}.")
        self._press(self._control({"title": "Go", "control_type": "Button"}, "The browser's Go button", window), window)
        self.sleep(self.wait / 2)

    def _url_field(self, window: Any) -> Any:
        elements = self.driver.snapshot(window, max_depth=16, limit=2000)
        label = next((e for e in elements if e.get("control_type") == "Text" and e.get("name") == "URL"), None)
        edits = [e for e in elements if e.get("control_type") == "Edit" and e.get("class_name") == "QLineEdit"]
        for index, edit in enumerate(edits):
            middle = (edit["rect"][1] + edit["rect"][3]) / 2
            if label is None or (label["rect"][1] <= middle <= label["rect"][3] and edit["rect"][0] >= label["rect"][0]):
                return self._control({"control_type": "Edit", "class_name": "QLineEdit", "found_index": index}, "The URL field", window)
        raise SimulationError("The web browser's URL field was not found.")

    def console(self, device: str, *, cli: bool = False, hints: Iterable[tuple[int, int]] = ()) -> tuple[Any, Any]:
        window = self.open_device(device, hints)
        ready = {"class_name": "CCommandLine"}
        if cli:
            tab = self._control({"title": "CLI", "control_type": "TabItem"}, f"The CLI tab of {device}", window)
            self.poster.click(window, *centre(self._rect(tab)))
            self.sleep(self.wait / 2)
            return window, self._control(ready, f"The CLI of {device}", window)
        self._desktop(window)
        return window, self._launch_applet(window, {"title_re": r"^Command\s+Prompt$", "control_type": "Button"}, ready)

    def command(self, device: str, command: str, *, cli: bool = False, timeout: float = 60, poll: float = 1.5,
                wait: bool = True, hints: Iterable[tuple[int, int]] = ()) -> str:
        """Type one command into the device console (posted keys) and return its output once the prompt is back.

        ``wait=False`` returns as soon as the command is echoed: in Simulation mode a ping only advances when the
        simulation is stepped.
        """
        window, console = self.console(device, cli=cli, hints=hints)
        self.poster.click(window, *centre(self._rect(console)))  # focus the console inside its own window
        self.sleep(self.wait)  # typed right after the previous prompt, Packet Tracer drops the first character
        waited = 0.0  # counted, not clocked: tests pass a sleep that returns at once
        while not re.search(r"[>#]\s*$", self._console_text(console)):  # an earlier command is still running
            if waited >= timeout:
                raise SimulationError(f"{device}'s console is still busy with an earlier command; nothing was typed.")
            self.sleep(poll)
            waited += poll
        earlier = self._console_text(console).count(command)  # the same command may be on screen from before
        self.poster.type_text(window, command)
        self.poster.press(window, "enter")
        waited = 0.0
        while True:
            self.sleep(poll)
            waited += poll
            text = self._console_text(console)
            position = text.rfind(command) if text.count(command) > earlier else -1
            if position < 0:
                if waited >= min(10.0, timeout):
                    raise SimulationError(f"{device}'s console did not echo {command!r}; nothing was run.")
                continue
            output = text[position + len(command):]
            if not wait or re.search(r"\n[^\n]*[>#]\s*$", output) or waited >= timeout:
                return output.strip("\n")

    def _console_text(self, console: Any) -> str:
        """The whole console: its UIA value is cut to roughly the last thousand characters, its text lines are not."""
        reader = getattr(self.driver, "read_lines", None)
        lines = reader(console) if callable(reader) else []
        return "\n".join(lines) if any(lines) else str(self.driver.read_text(console))

    def traceroute(self, device: str, target: str, *, timeout: float = 120, hints: Iterable[tuple[int, int]] = ()) -> dict[str, Any]:
        output = self.command(device, f"tracert {target}", timeout=timeout, hints=hints)
        return {**parse_tracert(output), "output": output}


def events_as_rows(events: list[Event]) -> list[dict[str, Any]]:
    return [asdict(event) for event in events]
