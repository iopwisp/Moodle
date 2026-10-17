from __future__ import annotations

import base64
import gzip
import hashlib
import json
from pathlib import Path

import pytest

from lab_agent.config import AgentConfig
from lab_agent.integrations.base import ExecutionContext, IntegrationResult
from lab_agent.integrations.kali import KaliAdapter
from lab_agent.integrations.kali_labs import KaliLabsAdapter
from lab_agent.integrations.registry import build_registry
from lab_agent.tools import kali_lab_guest as guest


@pytest.fixture
def context(tmp_path):
    return ExecutionContext(tmp_path, "Kali lab", config=AgentConfig())


@pytest.mark.parametrize("url", [
    "https://127.0.0.1", "http://example.com", "http://10.6.6.13",
    "http://127.0.0.1.example.com", "http://127.0.0.1@evil.test", "http://127.0.0.1/?x=1",
    "http://127.0.0.1:0", "http://127.0.0.1:65536", "http://127.0.0.1\\@evil.test",
])
def test_guest_web_jobs_reject_nonlocal_or_ambiguous_targets(url):
    with pytest.raises(ValueError):
        guest.local_url(url)


def test_literal_ipv6_loopback_is_allowed():
    assert guest.local_url("http://[::1]:8088/dvwa") == "http://[::1]:8088/dvwa/"


def test_registry_discovers_jobs_without_core_changes():
    registry = build_registry()
    for action in ("preflight", "nikto", "passwords", "dvwa"):
        assert registry.has("kali_labs." + action)
    assert not registry.validate_parameters("kali_labs.dvwa", {
        "url": "http://127.0.0.1:8088", "case": "reflected_xss", "level": "high"})


def test_invalid_inputs_are_rejected_before_ssh(context, monkeypatch):
    monkeypatch.setattr(KaliAdapter, "run", lambda *a: pytest.fail("Must not start SSH"))
    adapter = KaliLabsAdapter()
    with pytest.raises(ValueError):
        adapter.nikto({"url": "http://example.com"}, context)
    with pytest.raises(ValueError):
        adapter.nikto({"url": "http://127.0.0.1", "seconds": 0}, context)
    with pytest.raises(ValueError):
        adapter.preflight({"execution_id": "../../escape"}, context)
    with pytest.raises(PermissionError):
        adapter.passwords({"hashes": "../outside"}, context)
    (context.workspace / "hashes.txt").write_text("not an MD5\n")
    with pytest.raises(ValueError):
        adapter.passwords({"hashes": "hashes.txt"}, context)


def test_disabled_lab_tool_is_not_bypassed(context, monkeypatch):
    context.config = AgentConfig.model_validate({"policy": {"tools": {"kali_labs": {"allowed": False}}}})
    monkeypatch.setattr(KaliAdapter, "run", lambda *a: pytest.fail("Must not start SSH"))
    with pytest.raises(PermissionError, match="disabled"):
        KaliLabsAdapter().preflight({}, context)


@pytest.mark.parametrize("status", ["partial", "blocked", "failed"])
def test_guest_incomplete_result_cannot_become_verified(context, monkeypatch, status):
    output = {"status": status, "summary": "Observed limitation", "files": {
        "nikto.csv": '"127.0.0.1","8088"\n', "../../outside.txt": "unsafe"}}
    monkeypatch.setattr(KaliAdapter, "run", lambda *a: IntegrationResult(
        True, {"stdout": guest.MARKER + json.dumps(output)}))
    result = KaliLabsAdapter().nikto({"url": "http://127.0.0.1:8088"}, context)
    assert not result.verified
    assert result.blocked == (status == "blocked")
    assert result.details["lab"]["status"] == status
    assert any(Path(e["path"]).suffix == ".csv" for e in result.evidence)
    assert not (context.workspace.parent / "outside.txt").exists()


def test_missing_screenshot_reason_survives_successful_guest_result(context, monkeypatch):
    monkeypatch.setattr(KaliAdapter, "run", lambda *a: IntegrationResult(
        False, {"stdout": guest.MARKER + json.dumps({"status": "completed", "summary": "Done"}),
                "reason": "PrintWindow failed"}, blocked=True))
    result = KaliLabsAdapter().preflight({}, context)
    assert not result.verified and result.blocked
    assert "PrintWindow failed" in result.reason


@pytest.mark.parametrize("stdout", ["", guest.MARKER + "{}", guest.MARKER + "broken",
                                     (guest.MARKER + '{"status":"completed"}\n') * 2])
def test_corrupt_or_duplicate_protocol_is_not_verified(context, monkeypatch, stdout):
    monkeypatch.setattr(KaliAdapter, "run", lambda *a: IntegrationResult(True, {"stdout": stdout}))
    assert not KaliLabsAdapter().preflight({}, context).verified


def test_nikto_time_limit_is_partial_even_when_tool_returns_zero(tmp_path, monkeypatch):
    monkeypatch.setattr(guest.shutil, "which", lambda n: "/usr/bin/nikto")
    def run(argv, timeout, cwd):
        (cwd / "scan.csv.csv").write_text('"finding"\n')
        return {"output": "+ ERROR: Host maximum execution time reached", "exit_code": 0,
                "timed_out": False}
    monkeypatch.setattr(guest, "command", run)
    result = guest.nikto({"url": "http://127.0.0.1:8088", "seconds": 5}, tmp_path)
    assert result["status"] == "partial" and result["files"]["nikto.csv"]


def test_password_candidates_are_rehashed_and_duplicates_counted(tmp_path, monkeypatch):
    digest = hashlib.md5(b"Password").hexdigest()
    dictionary = tmp_path / "words.txt"
    dictionary.write_text("Password\n")
    monkeypatch.setattr(guest.shutil, "which", lambda n: "/usr/bin/john")
    def run(argv, timeout, cwd):
        return {"exit_code": 0, "timed_out": False,
                "output": "?:Password\n?:forged\n" if "--show" in argv else ""}
    monkeypatch.setattr(guest, "command", run)
    job = {"engine": "john", "hashes_b64": base64.b64encode(
        ("admin:" + digest + "\nsmithy:" + digest).encode()).decode(),
        "wordlist": str(dictionary), "seconds": 5}
    result = guest.passwords(job, tmp_path)
    assert result["recovered_count"] == 2 and result["total"] == 2
    assert result["recovered"] == {digest: "Password"}
    assert result["status"] == "completed"
    # An apparent tool success with an unrelated plaintext is not a cracked hash.
    monkeypatch.setattr(guest, "command", lambda *a: {
        "exit_code": 0, "timed_out": False, "output": "?:forged\n"})
    assert guest.passwords(job, tmp_path)["status"] == "partial"


def test_hashcat_backend_error_is_blocked_not_a_cracked_password(tmp_path, monkeypatch):
    dictionary = tmp_path / "words.txt"
    dictionary.write_text("Password\n")
    monkeypatch.setattr(guest.shutil, "which", lambda n: "/usr/bin/hashcat")
    monkeypatch.setattr(guest, "command", lambda *a: {
        "exit_code": 255, "timed_out": False, "output": "CL_PLATFORM_NOT_FOUND_KHR"})
    result = guest.passwords({"engine": "hashcat", "wordlist": str(dictionary), "seconds": 5,
                             "hashes_b64": base64.b64encode(b"0" * 32).decode()}, tmp_path)
    assert result["status"] == "blocked" and result["recovered_count"] == 0


def test_compressed_dictionary_original_survives_and_expansion_is_removed(tmp_path, monkeypatch):
    source = tmp_path / "original.gz"
    original = gzip.compress(b"Password\n")
    source.write_bytes(original)
    job_dir = tmp_path / "job"
    job_dir.mkdir()
    monkeypatch.setattr(guest.shutil, "which", lambda n: "/usr/bin/john")
    monkeypatch.setattr(guest, "command", lambda *a: {
        "exit_code": 0, "timed_out": False, "output": "?:Password\n"})
    result = guest.passwords({"engine": "john", "wordlist": str(source), "seconds": 5,
                             "hashes_b64": base64.b64encode(
                                 hashlib.md5(b"Password").hexdigest().encode()).decode()}, job_dir)
    assert result["status"] == "completed"
    assert source.read_bytes() == original
    assert not (job_dir / "wordlist.txt").exists()
