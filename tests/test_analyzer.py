from pathlib import Path

from lab_agent.analyzer import analyze, build_plan


def test_analyze_extracts_requirements_and_builds_plan(tmp_path: Path) -> None:
    source = tmp_path / "lab.txt"
    source.write_text("Digital forensic investigation\n1. Calculate SHA256 hash\n2. Capture a screenshot of Autopsy results\n", encoding="utf-8")
    result = analyze([source])
    plan = build_plan(result)
    assert "Autopsy" in result.tools
    assert len(plan.steps) == 2
    assert plan.steps[1].evidence_required
    assert plan.steps[1].evidence_type_required == "screenshot"


def test_unsupported_format_is_not_silently_planned(tmp_path: Path) -> None:
    source = tmp_path / "lab.doc"
    source.write_bytes(b"old word")
    try:
        analyze([source])
    except ValueError as error:
        assert "No supported assignment files" in str(error)
    else:
        raise AssertionError("unsupported .doc should fail")


def test_capture_request_is_evidence_but_not_automatically_a_screenshot(tmp_path: Path) -> None:
    source = tmp_path / "lab.txt"
    source.write_text("1. Capture the HTTP request in the results file\n", encoding="utf-8")
    analysis = analyze([source])
    step = build_plan(analysis).steps[0]
    assert step.evidence_required
    assert step.evidence_type_required is None
    assert not analysis.screenshot_requirements


def test_binary_evidence_is_kept_with_the_assignment_inputs(tmp_path: Path) -> None:
    assignment = tmp_path / "instructions.txt"
    image = tmp_path / "evidence.dd"
    assignment.write_text("1. Calculate SHA256 hash", encoding="utf-8")
    image.write_bytes(b"forensic-image")
    analysis = analyze([tmp_path])
    assert str(image.resolve()) in analysis.source_files


def test_html_instructions_are_read_and_name_the_work(tmp_path: Path) -> None:
    """Cisco activities come as Word pages saved to .htm (windows-1252) next to the .pka, often straight in Downloads."""
    downloads = tmp_path / "Downloads"
    downloads.mkdir()
    page = ('<html><head><meta charset="windows-1252"><style>p {color: red}</style></head><body>'
            "<h1>Packet Tracer - Create a Simple Network</h1><p>Objectives</p>"
            "<p>Part 1: Build a Simple Network</p><p>Step 1: Add network devices&nbsp;to the workspace.</p>"
            "<p>Test connectivity – ping cisco.srv</p></body></html>")  # the en dash is byte 0x96 in cp1252
    (downloads / "Create_a_Simple_Network.htm").write_bytes(page.encode("cp1252"))
    (downloads / "Create_a_Simple_Network_pka.pka").write_bytes(b"\x00binary activity")
    result = analyze([downloads / "Create_a_Simple_Network.htm", downloads / "Create_a_Simple_Network_pka.pka"])
    assert result.assignment == "Create_a_Simple_Network"  # not "Downloads"
    roles = {Path(f.path).suffix: f.role for f in result.files}
    assert roles == {".htm": "assignment", ".pka": "project"}
    text = next(iter(result.extracted_text_files.values()))
    assert "Step 1: Add network devices to the workspace." in text and "\u2013 ping cisco.srv" in text
    assert "color: red" not in text
