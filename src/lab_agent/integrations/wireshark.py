"""Wireshark integration.

Packet analysis uses Wireshark's own command-line engines (``tshark``,
``capinfos``) so results are exact and reproducible; the GUI is opened with the
same file and display filter for window screenshots.  Verification checks the
packets that were actually matched, never just the exit code.
"""

from __future__ import annotations

import csv
import re
import shutil
from pathlib import Path
from typing import Any

from ..tools.process import run_command
from .base import (
    AppSpec,
    BaseIntegration,
    Capability,
    CapabilityBlocked,
    ExecutionContext,
    IntegrationResult,
    Param,
    evidence,
    param_int,
    param_list,
    param_str,
)

CAPTURE_EXTENSIONS = {".pcap", ".pcapng", ".cap", ".pcap.gz"}
WIRESHARK_SPEC = AppSpec("wireshark", "Wireshark", env_var="LAB_AGENT_WIRESHARK_PATH",
                         executables=("Wireshark.exe", "wireshark"), install_globs=("Wireshark/Wireshark.exe",),
                         registry_name_re=r"^Wireshark", capabilities=("wireshark.launch", "wireshark.capture_evidence"))
TSHARK_SPEC = AppSpec("tshark", "TShark", env_var="LAB_AGENT_TSHARK_PATH", executables=("tshark.exe", "tshark"),
                      install_globs=("Wireshark/tshark.exe",), version_args=("--version",),
                      capabilities=("wireshark.open_capture", "wireshark.apply_filter", "wireshark.inspect_packets",
                                    "wireshark.follow_stream", "wireshark.export"))
FILTER_RE = re.compile(r"^[\w\s.=!<>&|()\[\]:\"',/~-]*$")
FILE = Param("file", "path", False, "capture file (default: first .pcap/.pcapng input)")
FILTER = Param("filter", "str", False, "Wireshark display filter, e.g. http.request")


class WiresharkAdapter(BaseIntegration):
    name = "wireshark"
    APPLICATIONS = (WIRESHARK_SPEC, TSHARK_SPEC)
    CAPABILITIES = (
        Capability("wireshark.open_capture", "wireshark", "Load a capture and record packet count, duration and protocols (capinfos)",
                   (FILE,), ("json",), "capture has at least one packet", keywords=("pcap", "wireshark", "трафик", "capture")),
        Capability("wireshark.apply_filter", "wireshark", "Apply a display filter and count/save the matching packets",
                   (FILE, Param("filter", "str", True), Param("min_matches", "int")), ("csv",),
                   "number of matching packets >= min_matches (default 1)", keywords=("filter", "фильтр")),
        Capability("wireshark.inspect_packets", "wireshark", "Extract selected fields of matching packets to CSV",
                   (FILE, FILTER, Param("fields", "list", True, "e.g. ip.src,ip.dst,http.host"), Param("limit", "int")), ("csv",),
                   "CSV rows extracted from real packets"),
        Capability("wireshark.follow_stream", "wireshark", "Reconstruct a TCP/UDP/HTTP stream as text",
                   (FILE, Param("protocol", "str", False, choices=("tcp", "udp", "http", "tls")), Param("stream", "int")), ("file",),
                   "stream text is not empty"),
        Capability("wireshark.export", "wireshark", "Write the packets matching a filter to a new capture file",
                   (FILE, FILTER, Param("output", "str")), ("file",), "exported capture packet count equals the match count"),
        Capability("wireshark.launch", "wireshark", "Open the capture in the Wireshark GUI with the display filter applied",
                   (FILE, FILTER), ("screenshot",), "Wireshark window with the capture is visible", requires=("app:wireshark",)),
        Capability("wireshark.capture_evidence", "wireshark", "Screenshot of the Wireshark window", (Param("name", "str"),),
                   ("screenshot",), "valid window screenshot", requires=("app:wireshark",)),
    )

    # ------------------------------------------------------------------ helpers
    def _binary(self, name: str, context: ExecutionContext) -> str:
        path = context.app_path(name) or shutil.which(name)
        if not path:
            wireshark = context.app_path("wireshark")
            candidate = Path(wireshark).with_name(f"{name}.exe") if wireshark else None
            if candidate is not None and candidate.is_file():
                path = str(candidate)
        if not path:
            from ..environment import discover_app

            spec = TSHARK_SPEC if name == "tshark" else AppSpec(name, name, executables=(f"{name}.exe", name),
                                                                install_globs=(f"Wireshark/{name}.exe",))
            info = discover_app(spec, context.config)
            path = info.path if info.available else None
        if not path:
            raise CapabilityBlocked(f"{name} (part of Wireshark) is not installed; set LAB_AGENT_TSHARK_PATH or install Wireshark.")
        return path

    def _capture(self, parameters: dict[str, Any], context: ExecutionContext) -> Path:
        value = param_str(parameters, "file")
        if value:
            return context.resolve(value, base="input")
        for root in (context.workspace / "input", context.workspace / "working", context.workspace / "results"):
            for path in sorted(root.rglob("*")) if root.is_dir() else []:
                if path.is_file() and (path.suffix.lower() in CAPTURE_EXTENSIONS or path.name.lower().endswith(".pcap.gz")):
                    return path
        raise FileNotFoundError("No capture file (.pcap/.pcapng/.cap) found in the workspace.")

    @staticmethod
    def _filter(parameters: dict[str, Any], required: bool = False) -> str:
        value = param_str(parameters, "filter")
        if required and not value:
            raise ValueError("A display filter is required")
        if value and not FILTER_RE.fullmatch(value):
            raise ValueError(f"Display filter contains unsupported characters: {value!r}")
        return value

    def _tshark(self, context: ExecutionContext, args: list[str], timeout: float = 600) -> Any:
        return run_command([self._binary("tshark", context), *args], cwd=context.workspace, timeout=timeout,
                           log_file=context.folder("logs") / "commands.jsonl")

    def _rel(self, path: Path, context: ExecutionContext) -> str:
        return path.resolve().relative_to(context.workspace.resolve()).as_posix()

    def _count(self, capture: Path, display_filter: str, context: ExecutionContext) -> tuple[int, Any]:
        args = ["-r", str(capture), "-T", "fields", "-e", "frame.number"] + (["-Y", display_filter] if display_filter else [])
        result = self._tshark(context, args)
        if result.exit_code != 0:
            raise RuntimeError(f"tshark failed ({result.exit_code}): {result.stderr.strip()[:300]}")
        return len([line for line in result.stdout.splitlines() if line.strip()]), result

    # ------------------------------------------------------------------ capabilities
    def open_capture(self, parameters: dict[str, Any], context: ExecutionContext) -> IntegrationResult:
        capture = self._capture(parameters, context)
        info = run_command([self._binary("capinfos", context), "-M", str(capture)], cwd=context.workspace, timeout=120,
                           log_file=context.folder("logs") / "commands.jsonl")
        packets, _ = self._count(capture, "", context)
        hierarchy = self._tshark(context, ["-r", str(capture), "-q", "-z", "io,phs"])
        text = f"$ capinfos -M {capture.name}\n{info.stdout}\n$ tshark -q -z io,phs\n{hierarchy.stdout}"
        output = context.save_result(f"capture_info_{capture.stem}.txt", text)
        ok = packets > 0
        return IntegrationResult(ok, {"file": self._rel(capture, context), "packets": packets,
                                      **({} if ok else {"reason": "capture contains no packets"})},
                                 [evidence(output, f"Capture summary for {capture.name}", "command_output")],
                                 checks=[{"type": "details_value", "key": "packets", "min": 1},
                                         {"type": "text_contains", "path": self._rel(output, context), "value": "Number of packets"}],
                                 report_sections=[{"title": f"Capture {capture.name}", "code": text[:6000]}])

    def apply_filter(self, parameters: dict[str, Any], context: ExecutionContext) -> IntegrationResult:
        capture = self._capture(parameters, context)
        display_filter = self._filter(parameters, required=True)
        minimum = param_int(parameters, "min_matches", 1)
        count, _ = self._count(capture, display_filter, context)
        listing = self._tshark(context, ["-r", str(capture), "-Y", display_filter])
        safe = re.sub(r"[^A-Za-z0-9_.-]+", "_", display_filter)[:60]
        output = context.save_result(f"filter_{safe}.txt", f"filter: {display_filter}\nmatches: {count}\n\n{listing.stdout}")
        ok = count >= minimum
        return IntegrationResult(ok, {"filter": display_filter, "matches": count, "file": self._rel(capture, context),
                                      **({} if ok else {"reason": f"only {count} packet(s) match {display_filter!r} (need {minimum})"})},
                                 [evidence(output, f"Packets matching {display_filter!r}", "command_output")],
                                 checks=[{"type": "details_value", "key": "matches", "min": minimum}],
                                 report_sections=[{"title": f"Filter {display_filter}", "code": listing.stdout[:5000]}])

    def inspect_packets(self, parameters: dict[str, Any], context: ExecutionContext) -> IntegrationResult:
        capture = self._capture(parameters, context)
        display_filter = self._filter(parameters)
        fields = [str(f) for f in param_list(parameters, "fields")]
        if not fields or any(not re.fullmatch(r"[a-z0-9_.]+", f) for f in fields):
            raise ValueError("fields must be Wireshark field names like ip.src,http.host")
        limit = param_int(parameters, "limit", 5000)
        args = ["-r", str(capture), "-T", "fields", "-E", "header=y", "-E", "separator=,", "-E", "quote=d", "-c", str(limit)]
        for name in ["frame.number", *fields]:
            args += ["-e", name]
        if display_filter:
            args += ["-Y", display_filter]
        result = self._tshark(context, args)
        if result.exit_code != 0:
            return IntegrationResult.failed(f"tshark failed: {result.stderr.strip()[:300]}")
        output = context.folder("results") / f"packets_{re.sub(r'[^A-Za-z0-9]+', '_', display_filter or 'all')[:40]}.csv"
        output.write_text(result.stdout, encoding="utf-8")
        with output.open(encoding="utf-8") as stream:
            rows = list(csv.DictReader(stream))
        ok = bool(rows)
        return IntegrationResult(ok, {"rows": len(rows), "fields": fields, **({} if ok else {"reason": "no packets matched"})},
                                 [evidence(output, f"Packet fields {fields}", "csv")],
                                 checks=[{"type": "csv_rows", "path": self._rel(output, context), "min": 1}],
                                 report_sections=[{"title": "Packet fields", "table": rows[:40]}])

    def follow_stream(self, parameters: dict[str, Any], context: ExecutionContext) -> IntegrationResult:
        capture = self._capture(parameters, context)
        protocol = param_str(parameters, "protocol", "tcp") or "tcp"
        stream = param_int(parameters, "stream", 0)
        result = self._tshark(context, ["-r", str(capture), "-q", "-z", f"follow,{protocol},ascii,{stream}"])
        body = result.stdout
        payload = "\n".join(line for line in body.splitlines() if line and not line.startswith(("=", "Follow:", "Filter:", "Node")))
        output = context.save_result(f"stream_{protocol}_{stream}.txt", body)
        ok = result.exit_code == 0 and bool(payload.strip())
        return IntegrationResult(ok, {"protocol": protocol, "stream": stream, "chars": len(payload),
                                      **({} if ok else {"reason": "stream is empty or does not exist"})},
                                 [evidence(output, f"{protocol.upper()} stream {stream}", "command_output")],
                                 report_sections=[{"title": f"{protocol.upper()} stream {stream}", "code": body[:5000]}])

    def export(self, parameters: dict[str, Any], context: ExecutionContext) -> IntegrationResult:
        capture = self._capture(parameters, context)
        display_filter = self._filter(parameters)
        name = Path(param_str(parameters, "output") or f"{capture.stem}_filtered.pcapng").name
        target = context.folder("results") / name
        args = ["-r", str(capture), "-w", str(target)] + (["-Y", display_filter] if display_filter else [])
        result = self._tshark(context, args)
        if result.exit_code != 0 or not target.is_file():
            return IntegrationResult.failed(f"export failed: {result.stderr.strip()[:300]}")
        expected, _ = self._count(capture, display_filter, context)
        written, _ = self._count(target, "", context)
        ok = expected == written and written > 0
        return IntegrationResult(ok, {"file": f"results/{name}", "packets": written, "expected": expected,
                                      **({} if ok else {"reason": f"exported {written} packets, expected {expected}"})},
                                 [evidence(target, f"Exported packets ({display_filter or 'all'})", "file")],
                                 checks=[{"type": "file_exists", "path": f"results/{name}"},
                                         {"type": "details_value", "key": "packets", "equals": expected}])

    def launch(self, parameters: dict[str, Any], context: ExecutionContext) -> IntegrationResult:
        from ..applications import ManagedApplication

        capture = self._capture(parameters, context)
        display_filter = self._filter(parameters)
        app = ManagedApplication("wireshark", context, spec=WIRESHARK_SPEC)
        args = ["-r", str(capture)] + (["-Y", display_filter] if display_filter else [])
        app.launch(args, reuse=False)
        picture = app.screenshot(f"wireshark_{context.stamp()}.png")
        return IntegrationResult(True, {"file": self._rel(capture, context), "filter": display_filter},
                                 [evidence(picture, f"Wireshark: {capture.name} {display_filter}".strip(), "screenshot")],
                                 checks=[{"type": "image_valid", "path": str(picture)},
                                         {"type": "window_exists", "title_re": re.escape(capture.stem)}])

    def capture_evidence(self, parameters: dict[str, Any], context: ExecutionContext) -> IntegrationResult:
        from ..applications import ManagedApplication

        app = ManagedApplication("wireshark", context, spec=WIRESHARK_SPEC)
        if app.running_window() is None:
            return IntegrationResult.failed("The Wireshark window is not open.")
        picture = app.screenshot(param_str(parameters, "name") or f"wireshark_{context.stamp()}.png")
        return IntegrationResult(True, {}, [evidence(picture, "Wireshark window", "screenshot")],
                                 checks=[{"type": "image_valid", "path": str(picture)}])

    def plan_templates(self, analysis: Any, registry: Any) -> list[dict[str, Any]]:
        captures = [f for f in getattr(analysis, "files", []) if f.role == "capture"]
        if not captures:
            return []
        name = Path(captures[0].path).name
        corpus = "\n".join(analysis.extracted_text_files.values())
        filters = re.findall(r"(?:filter|фильтр)\w*\s*[:=]?\s*[`'\"]([^`'\"]{2,80})[`'\"]", corpus, re.IGNORECASE)
        steps: list[dict[str, Any]] = [
            {"title": f"Open capture {name}", "action": "wireshark.open_capture", "parameters": {"file": f"input/{name}"},
             "evidence_type": "command_output"}]
        for display_filter in filters[:5]:
            steps.append({"title": f"Apply display filter {display_filter}", "action": "wireshark.apply_filter",
                          "parameters": {"file": f"input/{name}", "filter": display_filter}, "depends_on": [1],
                          "evidence_type": "command_output"})
        if registry.has("wireshark.launch"):
            steps.append({"title": "Show the capture in Wireshark and capture the window", "action": "wireshark.launch",
                          "parameters": {"file": f"input/{name}", **({"filter": filters[0]} if filters else {})},
                          "depends_on": [1], "evidence_type": "screenshot", "required": False})
        return steps


def create_adapters(services: Any) -> list[WiresharkAdapter]:
    return [WiresharkAdapter()]
