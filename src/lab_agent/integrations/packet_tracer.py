"""Cisco Packet Tracer integration.

What is automated, and how it is verified:

* **Topology design** (``create_topology``/``validate_addressing``): a topology
  spec (devices, interfaces, links, routes) is validated with ``ipaddress``;
  per-device IOS configuration scripts are generated and a *model-based*
  reachability check is computed.  Reports label this clearly as a model check.
* **Device configuration** (``configure_router``/``configure_switch``/
  ``enter_command``): commands are typed into the device's *CLI tab* through UI
  Automation and the console text is read back; any ``% Invalid``/``% Incomplete``
  response fails the step.  ``show running-config`` output is saved as evidence.
* **PCs** (``configure_pc``/``verify_connectivity``): the Desktop > Command
  Prompt is used (``ipconfig <ip> <mask> <gw>``, ``ping``); ping statistics are
  parsed from the real console output.
* **Save** (``save_project``): the .pkt must exist afterwards with a newer
  modification time and non-JSON binary content.

* **Canvas** (``add_device``/``connect_devices``/``rename_device``/
  ``survey_canvas``): see :mod:`.pt_canvas` - panel buttons and port menus are
  found through UI Automation by name, devices on the canvas by clicking icon
  blobs and reading the device window each one opens.  These steps move the
  real mouse, so they are marked interactive.
"""

from __future__ import annotations

import ipaddress
import json
import re
from pathlib import Path
from typing import Any

from .base import (
    AppSpec,
    BaseIntegration,
    Capability,
    CapabilityBlocked,
    ExecutionContext,
    IntegrationResult,
    Param,
    evidence,
    param_bool,
    param_dict,
    param_int,
    param_list,
    param_str,
)

PT_SPEC = AppSpec("packet_tracer", "Cisco Packet Tracer", env_var="LAB_AGENT_PACKET_TRACER_PATH",
                  executables=("PacketTracer.exe", "PacketTracer8.exe", "packettracer"),
                  install_globs=("Cisco Packet Tracer*/bin/PacketTracer.exe",),
                  registry_name_re=r"Cisco Packet Tracer", capabilities=("packet_tracer.*",))
CLI_ERRORS = ("% Invalid input", "% Incomplete command", "% Ambiguous command", "% Unknown command", "Invalid input detected")
DEVICE = Param("device", "str", True, "device name as shown in Packet Tracer, e.g. R1")
TOPOLOGY = Param("topology", "dict", False, "topology spec {devices, links, routes}; or topology_file")
TOPOLOGY_FILE = Param("topology_file", "path", False, "JSON/YAML topology spec inside the workspace")


def _load_topology(parameters: dict[str, Any], context: ExecutionContext) -> dict[str, Any]:
    spec = param_dict(parameters, "topology")
    if not spec and param_str(parameters, "topology_file"):
        path = context.resolve(param_str(parameters, "topology_file"), base="input")
        text = path.read_text(encoding="utf-8")
        if path.suffix.lower() in {".yaml", ".yml"}:
            import yaml

            spec = yaml.safe_load(text) or {}
        else:
            spec = json.loads(text)
    if not spec:
        stored = context.workspace / "working" / "packet_tracer" / "topology.json"
        if stored.is_file():
            spec = json.loads(stored.read_text(encoding="utf-8"))
    if not spec:
        raise ValueError("A topology spec is required (parameters.topology or topology_file).")
    return spec


def _interface_networks(spec: dict[str, Any]) -> dict[tuple[str, str], ipaddress.IPv4Interface]:
    result: dict[tuple[str, str], ipaddress.IPv4Interface] = {}
    for name, device in (spec.get("devices") or {}).items():
        for interface, address in (device.get("interfaces") or {}).items():
            if address:
                result[(name, interface)] = ipaddress.IPv4Interface(str(address))
        if device.get("ip"):
            result[(name, device.get("interface", "FastEthernet0"))] = ipaddress.IPv4Interface(str(device["ip"]))
    return result


def validate_topology(spec: dict[str, Any]) -> dict[str, Any]:
    """Static addressing checks plus a model-based reachability matrix."""
    problems: list[str] = []
    devices = spec.get("devices") or {}
    try:
        addresses = _interface_networks(spec)
    except ValueError as exc:
        return {"valid": False, "problems": [f"invalid address: {exc}"], "reachability": {}}
    seen: dict[ipaddress.IPv4Address, tuple[str, str]] = {}
    for key, iface in addresses.items():
        if iface.ip in seen:
            problems.append(f"duplicate IP {iface.ip} on {key[0]}:{key[1]} and {seen[iface.ip][0]}:{seen[iface.ip][1]}")
        seen[iface.ip] = key
        if iface.ip in (iface.network.network_address, iface.network.broadcast_address) and iface.network.prefixlen < 31:
            problems.append(f"{key[0]}:{key[1]} uses the network/broadcast address {iface.ip}")
    for link in spec.get("links") or []:
        ends = [str(end).split(":", 1) for end in link[:2]]
        if any(len(end) != 2 for end in ends):
            problems.append(f"link {link} must be written as DEVICE:INTERFACE")
            continue
        for device, _ in ends:
            if device not in devices:
                problems.append(f"link {link} references unknown device {device}")
        a, b = (addresses.get((d, i)) for d, i in ends)
        if a and b and a.network != b.network:
            problems.append(f"link {link[0]} <-> {link[1]} joins different subnets {a.network} and {b.network}")
    for name, device in devices.items():
        gateway = device.get("gateway")
        if gateway:
            own = [iface for (dev, _), iface in addresses.items() if dev == name]
            if own and not any(ipaddress.IPv4Address(gateway) in iface.network for iface in own):
                problems.append(f"{name} gateway {gateway} is outside its subnet {own[0].network}")
            if ipaddress.IPv4Address(gateway) not in seen:
                problems.append(f"{name} gateway {gateway} is not configured on any device")
    reachability = _reachability(spec, addresses)
    return {"valid": not problems, "problems": problems, "reachability": reachability,
            "note": "model-based check from the topology spec, not a packet test"}


def _reachability(spec: dict[str, Any], addresses: dict[tuple[str, str], ipaddress.IPv4Interface]) -> dict[str, dict[str, bool]]:
    devices = spec.get("devices") or {}
    routers = {n for n, d in devices.items() if str(d.get("type", "")).lower() in {"router", "l3switch", "multilayer"}}
    networks_of: dict[str, set[ipaddress.IPv4Network]] = {}
    for (device, _), iface in addresses.items():
        networks_of.setdefault(device, set()).add(iface.network)
    routes = {n: [(ipaddress.IPv4Network(str(r[0])), ipaddress.IPv4Address(str(r[1]))) for r in (spec.get("routes") or {}).get(n, [])]
              for n in routers}

    def forward(router: str, destination: ipaddress.IPv4Address, hops: int = 0) -> bool:
        if hops > 16:
            return False
        if any(destination in net for net in networks_of.get(router, set())):
            return True
        for network, next_hop in routes.get(router, []):
            if destination in network:
                owner = next((dev for (dev, _), iface in addresses.items() if iface.ip == next_hop), None)
                return owner in routers and forward(owner, destination, hops + 1) if owner else False
        return False

    hosts = [n for n in devices if n not in routers and any(dev == n for dev, _ in addresses)]
    matrix: dict[str, dict[str, bool]] = {}
    for source in hosts:
        src_ifaces = [iface for (dev, _), iface in addresses.items() if dev == source]
        gateway = devices[source].get("gateway")
        matrix[source] = {}
        for target in hosts:
            if target == source:
                continue
            dst = next(iface for (dev, _), iface in addresses.items() if dev == target)
            if any(dst.ip in iface.network for iface in src_ifaces):
                matrix[source][target] = True
                continue
            gw_owner = next((dev for (dev, _), iface in addresses.items() if gateway and str(iface.ip) == str(gateway)), None)
            back_gw = devices[target].get("gateway")
            back_owner = next((dev for (dev, _), iface in addresses.items() if back_gw and str(iface.ip) == str(back_gw)), None)
            there = bool(gw_owner is not None and gw_owner in routers and forward(gw_owner, dst.ip))
            back = bool(back_owner is not None and back_owner in routers and forward(back_owner, src_ifaces[0].ip))
            matrix[source][target] = there and back
    return matrix


def generate_configs(spec: dict[str, Any]) -> dict[str, list[str]]:
    configs: dict[str, list[str]] = {}
    for name, device in (spec.get("devices") or {}).items():
        kind = str(device.get("type", "")).lower()
        if kind in {"pc", "server", "laptop", "host"}:
            iface = ipaddress.IPv4Interface(str(device["ip"])) if device.get("ip") else None
            if iface:
                configs[name] = [f"ipconfig {iface.ip} {iface.netmask}" + (f" {device['gateway']}" if device.get("gateway") else "")]
            continue
        lines = ["enable", "configure terminal", f"hostname {name}"]
        for vlan in device.get("vlans") or []:
            lines += [f"vlan {vlan['id']}", f" name {vlan.get('name', 'VLAN' + str(vlan['id']))}", " exit"]
        for interface, address in (device.get("interfaces") or {}).items():
            lines.append(f"interface {interface}")
            if address:
                iface = ipaddress.IPv4Interface(str(address))
                lines.append(f" ip address {iface.ip} {iface.netmask}")
            lines += [" no shutdown", " exit"]
        for network, next_hop in (spec.get("routes") or {}).get(name, []):
            net = ipaddress.IPv4Network(str(network))
            lines.append(f"ip route {net.network_address} {net.netmask} {next_hop}")
        lines += ["end", "write memory"]
        configs[name] = lines
    return configs


def parse_ping(text: str) -> dict[str, Any] | None:
    """Parse Packet Tracer / Windows style ping statistics (last occurrence)."""
    matches = list(re.finditer(r"Sent\s*=\s*(\d+),\s*Received\s*=\s*(\d+),\s*Lost\s*=\s*(\d+)", text))
    if matches:
        sent, received, lost = (int(v) for v in matches[-1].groups())
        return {"sent": sent, "received": received, "lost": lost}
    ios = list(re.finditer(r"Success rate is (\d+) percent \((\d+)/(\d+)\)", text))
    if ios:
        percent, received, sent = (int(v) for v in ios[-1].groups())
        return {"sent": sent, "received": received, "lost": sent - received, "percent": percent}
    return None


class PacketTracerAdapter(BaseIntegration):
    name = "packet_tracer"
    APPLICATIONS = (PT_SPEC,)
    INTERACTIVE = frozenset({"packet_tracer.open_project", "packet_tracer.add_device", "packet_tracer.connect_devices",
                             "packet_tracer.rename_device", "packet_tracer.survey_canvas", "packet_tracer.open_cli", "packet_tracer.enter_command", "packet_tracer.configure_router", "packet_tracer.configure_switch", "packet_tracer.configure_pc", "packet_tracer.verify_connectivity", "packet_tracer.save_project"})
    CAPABILITIES = (
        Capability("packet_tracer.launch", "packet_tracer", "Start Packet Tracer and wait for the main window", (), ("screenshot",),
                   "main window visible (login walls are reported as BLOCKED)", requires=("app:packet_tracer",),
                   keywords=("packet tracer", "cisco")),
        Capability("packet_tracer.open_project", "packet_tracer", "Open a .pkt/.pka file", (Param("file", "path", True),),
                   ("screenshot",), "window title shows the opened file", requires=("app:packet_tracer",), keywords=(".pkt", ".pka")),
        Capability("packet_tracer.create_topology", "packet_tracer",
                   "Validate a topology spec and generate per-device IOS/PC configuration scripts", (TOPOLOGY, TOPOLOGY_FILE),
                   ("json", "file"), "addressing is consistent; configs generated", keywords=("topology", "топологи")),
        Capability("packet_tracer.validate_addressing", "packet_tracer",
                   "Static addressing check + model-based reachability matrix for the topology", (TOPOLOGY, TOPOLOGY_FILE),
                   ("json",), "no duplicate IPs, links share subnets, gateways valid"),
        Capability("packet_tracer.add_device", "packet_tracer", "Drag a device model onto the canvas and give it a display name",
                   (Param("device", "str", False, "display name to give it, e.g. PC; empty keeps Packet Tracer's name"),
                    Param("model", "str", True, "panel model or everyday name: PC, Laptop, Cable Modem, 2911, 2960 ..."),
                    Param("near", "str", False, "place it below this existing device"),
                    Param("at", "list", False, "[x, y] as fractions of the visible canvas")),
                   ("screenshot",), "the new device's window opens with the requested name", requires=("app:packet_tracer",),
                   keywords=("add device", "drag and drop", "device-type selection")),
        Capability("packet_tracer.connect_devices", "packet_tracer", "Cable two device ports",
                   (Param("a", "str", True, "device:port, e.g. PC:FastEthernet0"), Param("b", "str", True, "Wireless Router:Ethernet 1"),
                    Param("cable", "str", False, "straight | cross | coaxial | console | serial-dce | serial-dte | fiber | auto")),
                   ("screenshot",), "both ports were chosen from Packet Tracer's own port menus", requires=("app:packet_tracer",),
                   keywords=("cable", "cabling", "кабель", "straight-through")),
        Capability("packet_tracer.rename_device", "packet_tracer", "Change a device's display name (Config tab)",
                   (DEVICE, Param("name", "str", True, "new display name")), ("screenshot",),
                   "the device window is titled with the new name", requires=("app:packet_tracer",), keywords=("display name",)),
        Capability("packet_tracer.survey_canvas", "packet_tracer", "Map every device on the visible canvas by clicking it",
                   (), ("json",), "every icon opened a named device window", requires=("app:packet_tracer",)),
        Capability("packet_tracer.open_cli", "packet_tracer", "Bring the device window to the CLI tab", (DEVICE,), (),
                   "CLI console of the device is visible", requires=("app:packet_tracer",)),
        Capability("packet_tracer.enter_command", "packet_tracer", "Type one IOS command in the device CLI and record the output",
                   (DEVICE, Param("command", "str", True)), ("command_output",), "no IOS error in the console output",
                   requires=("app:packet_tracer",)),
        Capability("packet_tracer.configure_router", "packet_tracer", "Apply IOS configuration lines to a router via its CLI tab",
                   (DEVICE, Param("commands", "list", False), Param("from_topology", "bool", False)), ("command_output",),
                   "no IOS errors; show running-config contains the configured lines", requires=("app:packet_tracer",),
                   keywords=("router", "маршрутизатор", "роутер")),
        Capability("packet_tracer.configure_switch", "packet_tracer", "Apply IOS configuration lines to a switch via its CLI tab",
                   (DEVICE, Param("commands", "list", False), Param("from_topology", "bool", False)), ("command_output",),
                   "no IOS errors; show running-config contains the configured lines", requires=("app:packet_tracer",),
                   keywords=("switch", "коммутатор", "vlan")),
        Capability("packet_tracer.configure_pc", "packet_tracer", "Set a PC's address via Command Prompt (static ipconfig or DHCP)",
                   (DEVICE, Param("ip", "str", False, "192.168.1.10/24; omit with dhcp=true"), Param("gateway", "str"),
                    Param("dhcp", "bool", False, "ipconfig /renew-style DHCP request instead of a static address")),
                   ("command_output",),
                   "ipconfig output shows the address", requires=("app:packet_tracer",)),
        Capability("packet_tracer.verify_connectivity", "packet_tracer", "Ping from a PC/device and parse the statistics",
                   (Param("source", "str", True), Param("target", "str", True, "IP address or host name"), Param("min_received", "int")),
                   ("command_output", "screenshot"), "received replies >= min_received (default 1)", requires=("app:packet_tracer",),
                   keywords=("ping", "пинг", "connectivity", "связност")),
        Capability("packet_tracer.capture_topology", "packet_tracer", "Screenshot of the Packet Tracer main window",
                   (Param("name", "str"),), ("screenshot",), "valid window screenshot", requires=("app:packet_tracer",)),
        Capability("packet_tracer.save_project", "packet_tracer", "Save the project (.pkt) to results/",
                   (Param("filename", "str"),), ("file",), ".pkt exists, is newer than before and is binary",
                   requires=("app:packet_tracer",), keywords=("save", "сохран")),
    )

    def __init__(self) -> None:
        self._launched: dict[str, Any] = {}  # project path -> ManagedApplication started by open_project

    def _app(self, context: ExecutionContext) -> Any:
        from ..applications import ManagedApplication

        app = ManagedApplication("packet_tracer", context, spec=PT_SPEC)
        for project in reversed(list(self._launched)):  # the newest project window opened by this run wins
            selector = self._project_window(project)
            if app.driver.find_window(selector, timeout=0) is not None:
                app.selector_override = selector
                break
        return app

    @staticmethod
    def _project_window(project: str) -> dict[str, Any]:
        return {"title_re": re.escape(project)}

    def shutdown(self) -> None:
        # Packet Tracer stays open after the run on purpose: the student continues the activity in it.
        self._launched.clear()

    def _folder(self, context: ExecutionContext) -> Path:
        return context.folder("working/packet_tracer")

    # ------------------------------------------------------------------ design
    def create_topology(self, parameters: dict[str, Any], context: ExecutionContext) -> IntegrationResult:
        spec = _load_topology(parameters, context)
        report = validate_topology(spec)
        folder = self._folder(context)
        (folder / "topology.json").write_text(json.dumps(spec, indent=2, ensure_ascii=False), encoding="utf-8")
        configs = generate_configs(spec)
        items = []
        for device, lines in configs.items():
            path = context.save_result(f"pt_config_{device}.txt", "\n".join(lines) + "\n")
            items.append(evidence(path, f"Generated configuration for {device}", "file"))
        record = context.save_result("pt_topology_validation.json", report)
        items.insert(0, evidence(record, "Topology validation (model check)", "json"))
        return IntegrationResult(report["valid"], {**report, "devices": list(spec.get("devices", {})),
                                                   **({} if report["valid"] else {"reason": "; ".join(report["problems"][:5])})},
                                 items, checks=[{"type": "json_value", "path": "results/pt_topology_validation.json", "key": "valid",
                                                 "equals": True}],
                                 report_sections=[{"title": "Topology addressing (model check)",
                                                   "paragraphs": report["problems"] or ["No addressing problems found."]}])

    def validate_addressing(self, parameters: dict[str, Any], context: ExecutionContext) -> IntegrationResult:
        spec = _load_topology(parameters, context)
        report = validate_topology(spec)
        record = context.save_result("pt_addressing_check.json", report)
        return IntegrationResult(report["valid"], {**report, **({} if report["valid"] else {"reason": "; ".join(report["problems"][:5])})},
                                 [evidence(record, "Addressing check (model)", "json")])

    # ------------------------------------------------------------------ GUI
    def launch(self, parameters: dict[str, Any], context: ExecutionContext) -> IntegrationResult:
        app = self._app(context)
        app.launch()
        picture = app.screenshot(f"packet_tracer_{context.stamp()}.png")
        return IntegrationResult(True, {}, [evidence(picture, "Packet Tracer main window", "screenshot")],
                                 checks=[{"type": "image_valid", "path": str(picture)}])

    def open_project(self, parameters: dict[str, Any], context: ExecutionContext) -> IntegrationResult:
        project = context.resolve(param_str(parameters, "file"), base="input")
        app = self._app(context)
        # A retry must not start a second Packet Tracer: attach to the window that already shows this file,
        # otherwise close the instance this adapter started before and open the file again.
        selector = self._project_window(str(project))
        app.selector_override = selector  # this file's window, not a Packet Tracer the student already has open
        showing = app.driver.find_window(selector, timeout=0)
        if showing is not None:
            app.window = showing
            app.check_blockers()
        else:
            previous = self._launched.pop(str(project), None)
            if previous is not None:
                previous.close()
            app.launch([str(project)], reuse=False)
        self._launched[str(project)] = app
        title = app.driver.window_title(app.window) if app.window is not None else ""
        picture = app.screenshot(f"packet_tracer_open_{context.stamp()}.png")
        ok = project.stem.casefold() in title.casefold()
        return IntegrationResult(ok, {"title": title, "file": project.name,
                                      **({} if ok else {"reason": f"window title {title!r} does not show {project.name}"})},
                                 [evidence(picture, f"{project.name} opened in Packet Tracer", "screenshot")],
                                 checks=[{"type": "window_exists", "title_re": re.escape(project.stem)}])

    def _open_from_canvas(self, app: Any, device: str, context: ExecutionContext) -> None:
        """Open a device's window by clicking it on the canvas when it is not open yet (real Packet Tracer only)."""
        if app.driver.find_window({"title_re": f"^{re.escape(device)}$"}, timeout=0) is not None:
            return
        window = app.running_window()
        if self.pointer_factory is None and not getattr(window, "handle", None):
            return  # no real window: _device_window asks the student
        from ..desktop.pointer import InputRefused
        from .pt_canvas import CanvasError

        canvas, _ = self._canvas(context)
        try:
            canvas.open_device(device)
        except InputRefused as exc:
            raise CapabilityBlocked(str(exc)) from exc
        except CanvasError:
            return  # _device_window reports it

    def _device_window(self, app: Any, device: str) -> Any:
        selector = {"title_re": f"^{re.escape(device)}$"}
        window = app.driver.find_window(selector, timeout=2)
        if window is None and app.has_operation("open_device"):
            app.run_operation("open_device", {"device": device})
            window = app.driver.find_window(selector, timeout=10)
        if window is None:
            raise CapabilityBlocked(f"Open the {device} window in Packet Tracer (click {device} once on the canvas), then resume.")
        return window

    def _console(self, app: Any, device: str, tab: str) -> tuple[Any, Any]:
        window = self._device_window(app, device)
        driver = app.driver
        driver.focus(window)
        tabs = app.profile.get("device_tabs", {})
        path = tabs.get(tab, {"title": tab, "control_type": "TabItem"})
        console_selector = app.profile.get("console", {"control_type": "Edit"})
        for index, selector in enumerate(path if isinstance(path, list) else [path]):
            control = driver.find_control(window, selector, timeout=5 if index == 0 else 2)
            if control is None:
                # Desktop > Command Prompt: once the app is open its launcher button is gone and the console shows
                if index > 0 and driver.find_control(window, console_selector, timeout=1) is not None:
                    break
                raise CapabilityBlocked(f"{device} has no '{tab}' view ({selector}); is it the right device type?")
            driver.click(control)
        console = driver.find_control(window, console_selector, timeout=5)
        if console is None:
            raise RuntimeError(f"The {tab} console of {device} was not found; update profiles/packet_tracer.yaml selectors")
        return window, console

    def _type_lines(self, app: Any, console: Any, lines: list[str], context: ExecutionContext) -> str:
        driver = app.driver
        before = driver.read_text(console)
        for line in lines:
            driver.type_text(console, line, replace=False)
            driver.hotkey("{ENTER}")
            context.sleep(float(app.profile.get("command_delay_seconds", 0.4)))
        context.sleep(float(app.profile.get("output_settle_seconds", 1.0)))
        after = driver.read_text(console)
        return after.removeprefix(before)

    def _run_cli(self, device: str, lines: list[str], context: ExecutionContext, tab: str = "CLI") -> tuple[str, list[str]]:
        app = self._app(context)
        if app.running_window() is None:
            raise CapabilityBlocked("Packet Tracer is not running; run packet_tracer.launch/open_project first.")
        self._open_from_canvas(app, device, context)
        _, console = self._console(app, device, tab)
        output = self._type_lines(app, console, ["", *lines], context)
        errors = [line for line in output.splitlines() if any(marker in line for marker in CLI_ERRORS)]
        return output, errors

    def open_cli(self, parameters: dict[str, Any], context: ExecutionContext) -> IntegrationResult:
        app = self._app(context)
        self._console(app, param_str(parameters, "device"), "CLI")
        return IntegrationResult(True, {"device": param_str(parameters, "device")})

    def enter_command(self, parameters: dict[str, Any], context: ExecutionContext) -> IntegrationResult:
        device, command = param_str(parameters, "device"), param_str(parameters, "command")
        output, errors = self._run_cli(device, [command], context)
        path = context.save_result(f"pt_{device}_{context.stamp()}.txt", f"{device}# {command}\n{output}")
        return IntegrationResult(not errors, {"device": device, "errors": errors, **({"reason": errors[0]} if errors else {})},
                                 [evidence(path, f"{device}: {command}", "command_output")])

    def _configure(self, parameters: dict[str, Any], context: ExecutionContext) -> IntegrationResult:
        device = param_str(parameters, "device")
        commands = [str(c) for c in param_list(parameters, "commands")]
        if not commands and parameters.get("from_topology"):
            commands = generate_configs(_load_topology({}, context)).get(device, [])
        if not commands:
            raise ValueError("commands (or from_topology=true with a stored topology) are required")
        body = commands if commands[:1] == ["enable"] else ["enable", "configure terminal", *commands, "end"]
        output, errors = self._run_cli(device, body, context)
        running, run_errors = self._run_cli(device, ["terminal length 0", "show running-config"], context)
        transcript = context.save_result(f"pt_{device}_configuration.txt", output)
        running_file = context.save_result(f"pt_{device}_running_config.txt", running)
        expected = [c.strip() for c in commands if re.match(r"^\s*(ip address|hostname|ip route|vlan|switchport|router)\b", c.strip())]
        missing = [line for line in expected if line not in running]
        ok = not errors and not run_errors and not missing
        reason = errors[:1] or run_errors[:1] or ([f"not in running-config: {missing[:3]}"] if missing else [])
        return IntegrationResult(ok, {"device": device, "errors": errors, "missing": missing, **({"reason": reason[0]} if reason else {})},
                                 [evidence(transcript, f"{device} configuration session", "command_output"),
                                  evidence(running_file, f"{device} show running-config", "command_output")],
                                 checks=[{"type": "text_not_contains", "path": f"results/{transcript.name}", "value": "% Invalid"}]
                                 + [{"type": "text_contains", "path": f"results/{running_file.name}", "value": line} for line in expected[:15]])

    def configure_router(self, parameters: dict[str, Any], context: ExecutionContext) -> IntegrationResult:
        return self._configure(parameters, context)

    def configure_switch(self, parameters: dict[str, Any], context: ExecutionContext) -> IntegrationResult:
        return self._configure(parameters, context)

    def configure_pc(self, parameters: dict[str, Any], context: ExecutionContext) -> IntegrationResult:
        device = param_str(parameters, "device")
        if param_bool(parameters, "dhcp"):
            output, _ = self._run_cli(device, ["ipconfig /renew", "ipconfig"], context, tab="Command Prompt")
            leased = re.findall(r"IP(?:v4)? Address[ .]*: *(\d+\.\d+\.\d+\.\d+)", output)
            address = next((ip for ip in reversed(leased) if not ip.startswith(("0.", "169.254."))), "")
            path = context.save_result(f"pt_{device}_ipconfig.txt", output)
            return IntegrationResult(bool(address), {"device": device, "ip": address, "dhcp": True,
                                                     **({} if address else {"reason": "no DHCP lease shown by ipconfig"})},
                                     [evidence(path, f"{device} ipconfig (DHCP)", "command_output")],
                                     checks=[{"type": "text_contains", "path": f"results/{path.name}", "value": address or "no lease"}])
        if not param_str(parameters, "ip"):
            raise ValueError("ip is required unless dhcp is true")
        iface = ipaddress.IPv4Interface(param_str(parameters, "ip"))
        gateway = param_str(parameters, "gateway")
        command = f"ipconfig {iface.ip} {iface.netmask}" + (f" {gateway}" if gateway else "")
        output, _ = self._run_cli(device, [command, "ipconfig"], context, tab="Command Prompt")
        path = context.save_result(f"pt_{device}_ipconfig.txt", output)
        ok = str(iface.ip) in output
        return IntegrationResult(ok, {"device": device, "ip": str(iface.ip), **({} if ok else {"reason": "address not shown by ipconfig"})},
                                 [evidence(path, f"{device} ipconfig", "command_output")],
                                 checks=[{"type": "text_contains", "path": f"results/{path.name}", "value": str(iface.ip)}])

    def verify_connectivity(self, parameters: dict[str, Any], context: ExecutionContext) -> IntegrationResult:
        source, target = param_str(parameters, "source"), param_str(parameters, "target")
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.-]{0,252}", target):  # an IPv4 address or a name such as cisco.srv
            raise ValueError(f"target must be an IP address or host name, not {target!r}")
        minimum = param_int(parameters, "min_received", 1)
        app = self._app(context)
        devices = (_load_topology({}, context).get("devices", {}) if (self._folder(context) / "topology.json").is_file() else {})
        kind = str(devices.get(source, {}).get("type", "pc")).lower()
        tab = "CLI" if kind in {"router", "switch", "l3switch"} else "Command Prompt"
        output, _ = self._run_cli(source, [f"ping {target}"], context, tab=tab)
        _, console = self._console(app, source, tab)
        # A PT ping takes 20-35 s in realtime mode: poll the console until this ping's statistics appear.
        interval = float(app.profile.get("ping_poll_seconds", 2))
        polls = max(1, int(float(app.profile.get("ping_timeout_seconds", 60)) / interval))
        stats = None
        full = ""
        for _ in range(polls):
            full = app.driver.read_text(console)
            latest = full.rfind(f"ping {target}")
            stats = parse_ping(full[latest:] if latest >= 0 else full[-4000:])
            if stats is not None:
                break
            context.sleep(interval)
        stats = stats or parse_ping(output)
        path = context.save_result(f"pt_ping_{source}_{target.replace('.', '_')}.txt", full[-4000:])
        items = [evidence(path, f"ping {target} from {source}", "command_output")]
        try:
            items.append(evidence(app.screenshot(f"pt_ping_{source}_{context.stamp()}.png"), f"Ping from {source}", "screenshot"))
        except Exception:  # noqa: BLE001, S110 - screenshot optional here; text is the proof
            pass
        ok = stats is not None and stats["received"] >= minimum
        reason = {} if ok else {"reason": f"ping statistics {stats or 'not found'} (need {minimum} replies)"}
        return IntegrationResult(ok, {"source": source, "target": target, "stats": stats, **reason}, items,
                                 checks=[{"type": "details_value", "key": "stats.received", "min": minimum}])

    # ------------------------------------------------------------------ canvas
    pointer_factory: Any = None  # tests inject a fake; default: lab_agent.desktop.pointer.RealPointer

    def _canvas(self, context: ExecutionContext) -> Any:
        from .pt_canvas import CanvasState, PTCanvas

        app = self._app(context)
        window = app.running_window()
        if window is None:
            raise CapabilityBlocked("Packet Tracer is not open; run packet_tracer.open_project first.")
        if self.pointer_factory is None:
            if not getattr(window, "handle", None):
                raise CapabilityBlocked("Canvas automation needs a real Packet Tracer window on Windows.")
            from ..desktop.pointer import RealPointer

            try:
                pointer = RealPointer()
            except RuntimeError as exc:
                raise CapabilityBlocked(str(exc)) from exc
        else:
            pointer = self.pointer_factory()
        state = CanvasState.load(context.folder("working") / "pt_canvas.json")
        return PTCanvas(app.driver, window, pointer, app.profile, state=state, sleep=context.sleep), app

    def _canvas_step(self, context: ExecutionContext, work: Any, label: str) -> IntegrationResult:
        from ..desktop.pointer import InputRefused
        from .pt_canvas import CanvasError

        canvas, app = self._canvas(context)
        try:
            details = work(canvas)
        except InputRefused as exc:
            raise CapabilityBlocked(str(exc)) from exc
        except (CanvasError, ValueError) as exc:
            picture = app.screenshot(f"pt_{label}_failed_{context.stamp()}.png")
            return IntegrationResult(False, {"reason": str(exc)}, [evidence(picture, f"Canvas when {label} failed", "screenshot")])
        picture = app.screenshot(f"pt_{label}_{context.stamp()}.png")
        record = context.save_result(f"pt_{label}_{context.step_id or 0:02d}.json", details)
        return IntegrationResult(True, details, [evidence(picture, f"Packet Tracer after {label}", "screenshot"),
                                                 evidence(record, f"{label} details", "json")],
                                 checks=[{"type": "image_valid", "path": f"screenshots/{picture.name}"}])

    def add_device(self, parameters: dict[str, Any], context: ExecutionContext) -> IntegrationResult:
        model, wanted = param_str(parameters, "model"), param_str(parameters, "device")
        spot = [float(v) for v in param_list(parameters, "at")]
        if spot and (len(spot) != 2 or not all(0 <= v <= 1 for v in spot)):
            raise ValueError("at must be [x, y] fractions between 0 and 1")

        def work(canvas: Any) -> dict[str, Any]:
            created, point = canvas.place(model, at=tuple(spot) if spot else None, near=param_str(parameters, "near") or None)
            if wanted and wanted != created:
                canvas.rename(created, wanted)
            return {"model": model, "created_as": created, "device": wanted or created, "point": list(point)}

        return self._canvas_step(context, work, "add_device")

    def connect_devices(self, parameters: dict[str, Any], context: ExecutionContext) -> IntegrationResult:
        ends = []
        for key in ("a", "b"):
            device, _, port = param_str(parameters, key).partition(":")
            if not device.strip():
                raise ValueError(f"{key} must be 'device:port', e.g. PC:FastEthernet0")
            ends.append((device.strip(), port.strip()))
        cable = param_str(parameters, "cable", "straight") or "straight"
        return self._canvas_step(context, lambda canvas: canvas.connect(ends[0][0], ends[0][1], ends[1][0], ends[1][1], cable),
                                 "connect")

    def rename_device(self, parameters: dict[str, Any], context: ExecutionContext) -> IntegrationResult:
        device, name = param_str(parameters, "device"), param_str(parameters, "name")

        def work(canvas: Any) -> dict[str, Any]:
            canvas.rename(device, name)
            return {"device": device, "name": name}

        return self._canvas_step(context, work, "rename")

    def survey_canvas(self, parameters: dict[str, Any], context: ExecutionContext) -> IntegrationResult:
        def work(canvas: Any) -> dict[str, Any]:
            devices = canvas.survey()
            if not devices:
                raise ValueError("No device window opened from any icon on the visible canvas.")
            return {"devices": devices}

        return self._canvas_step(context, work, "survey")

    def capture_topology(self, parameters: dict[str, Any], context: ExecutionContext) -> IntegrationResult:
        app = self._app(context)
        if app.running_window() is None:
            return IntegrationResult.failed("Packet Tracer is not open.")
        picture = app.screenshot(param_str(parameters, "name") or f"pt_topology_{context.stamp()}.png")
        return IntegrationResult(True, {}, [evidence(picture, "Packet Tracer topology", "screenshot")],
                                 checks=[{"type": "image_valid", "path": str(picture)}])

    def save_project(self, parameters: dict[str, Any], context: ExecutionContext) -> IntegrationResult:
        app = self._app(context)
        if app.running_window() is None:
            return IntegrationResult.failed("Packet Tracer is not open.")
        name = Path(param_str(parameters, "filename") or f"{context.assignment}.pkt").name
        target = context.folder("results") / (name if name.lower().endswith((".pkt", ".pka")) else name + ".pkt")
        before = target.stat().st_mtime if target.exists() else 0.0
        if not app.has_operation("save_as"):
            return IntegrationResult.blocked_result("The Packet Tracer profile has no verified 'save_as' operation.")
        app.run_operation("save_as", {"path": str(target)})
        exists = target.is_file() and target.stat().st_mtime > before and target.stat().st_size > 0
        binary = exists and not target.read_bytes()[:1] in (b"{", b"[")
        ok = exists and binary
        return IntegrationResult(ok, {"file": f"results/{target.name}", **({} if ok else {"reason": "project file was not written"})},
                                 [evidence(target, "Saved Packet Tracer project", "file")] if exists else [],
                                 checks=[{"type": "file_exists", "path": f"results/{target.name}", "min_size": 1024}])

    def plan_templates(self, analysis: Any, registry: Any) -> list[dict[str, Any]]:
        projects = [f for f in getattr(analysis, "files", []) if f.role == "project" and f.path.lower().endswith((".pkt", ".pka", ".pksz"))]
        topology = [f for f in getattr(analysis, "files", []) if Path(f.path).stem.lower().startswith("topology")
                    and f.path.lower().endswith((".json", ".yaml", ".yml"))]
        corpus = "\n".join(analysis.extracted_text_files.values()).lower()
        if not projects and "packet tracer" not in corpus:
            return []
        steps: list[dict[str, Any]] = []
        if topology:
            steps.append({"title": "Validate topology and generate device configurations", "action": "packet_tracer.create_topology",
                          "parameters": {"topology_file": f"input/{Path(topology[0].path).name}"}, "evidence_type": "json"})
        if projects:
            steps.append({"title": f"Open {Path(projects[0].path).name}", "action": "packet_tracer.open_project",
                          "parameters": {"file": f"input/{Path(projects[0].path).name}"}, "evidence_type": "screenshot"})
        else:
            steps.append({"title": "Start Packet Tracer", "action": "packet_tracer.launch", "parameters": {},
                          "evidence_type": "screenshot"})
        steps.append({"title": "Capture the topology", "action": "packet_tracer.capture_topology", "parameters": {},
                      "depends_on": [len(steps)], "evidence_type": "screenshot"})
        return steps


def create_adapters(services: Any) -> list[PacketTracerAdapter]:
    return [PacketTracerAdapter()]
