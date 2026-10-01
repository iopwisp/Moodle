from __future__ import annotations

from pathlib import Path

import pytest
from conftest import EMPTY_ENVIRONMENT
from fakes import fake_screenshot

from lab_agent.analyzer import extract_objective
from lab_agent.integrations.base import Narrative, StepFacts
from lab_agent.narrative import detect_language, human_reason, narrate, plural
from lab_agent.runner import run_assignment
from lab_agent.student_report import build_report, command_line, inline_segments, markdown_blocks


def test_language_plural_and_objective() -> None:
    assert detect_language("Лабораторная работа: перехват трафика в Burp Suite") == "ru"
    assert detect_language("Lab 4: intercepting traffic with Burp Suite") == "en"
    assert [plural(n, ("файл", "файла", "файлов")) for n in (1, 2, 5, 11, 21, 104)] == [
        "1 файл", "2 файла", "5 файлов", "11 файлов", "21 файл", "104 файла"]
    lines = ["Лабораторная работа 4", "Цель работы", "1. Освоить Burp Suite.", "2. Научиться перехватывать запросы.",
             "🔍 Исходный сценарий", "Компания попросила проверить сайт."]
    assert extract_objective(lines) == "Освоить Burp Suite; научиться перехватывать запросы."
    assert extract_objective(["Objective: Learn to use Repeater.", "", "Tasks"]) == "Learn to use Repeater."
    assert extract_objective(["Целевой узел: 10.0.0.1"]) == ""


def test_markdown_blocks_cover_what_students_write() -> None:
    blocks = markdown_blocks("# Answers\n\n## Part 2\n\nText with **bold** and `code`.\n\n| A | B |\n|---|---|\n| 1 | 2 |\n\n"
                             "- one\n- two\n  continued\n\n1. first\n2. second\n\n```\nfls -r image.dd\n```\n---\n")
    kinds = [b.kind for b in blocks]
    assert kinds == ["h1", "h2", "p", "table", "list", "list", "code"]
    assert blocks[3].rows == [["A", "B"], ["1", "2"]]
    assert blocks[4].items == ["one", "two continued"] and not blocks[4].ordered and blocks[5].ordered
    assert blocks[6].text == "fls -r image.dd"
    assert inline_segments("a **b** `c` *d*") == [("a ", ""), ("b", "b"), (" ", ""), ("c", "code"), (" ", ""), ("d", "i")]


def test_commands_and_reasons_read_like_a_student_wrote_them(tmp_path: Path) -> None:
    workspace = tmp_path / "ws"
    argv = ["wsl.exe", "-d", "Ubuntu", "-e", "foremost", "-t", "pdf", "-i",
            f"/mnt/c/Users/x/DoneAsik/workspace/{workspace.name}/working/evidence.dd", "-o", f"{workspace}\\results\\out"]
    assert command_line(argv, workspace) == "foremost -t pdf -i working/evidence.dd -o results\\out"
    assert command_line(["C:/Program Files/Autopsy-4.23.1/bin/autopsy64.exe", "--nosplash"], workspace) == "autopsy64.exe --nosplash"
    assert human_reason("not started: dependency step 3 is BLOCKED", "ru").startswith("шаг не запускался")
    assert human_reason("Burp Suite is not installed or not configured. Set X", "ru") == "программа Burp Suite не установлена на этом компьютере"
    assert human_reason("odd failure; 0/1 checks passed: x", "en") == "the program reported “odd failure”"


def test_every_description_survives_missing_details(registry) -> None:
    """Integrations describe steps from recorded details; a missing key must never break the report."""
    checked = 0
    for capability in registry.capabilities():
        adapter = registry.adapter_for(capability.name)
        if not callable(getattr(adapter, "narrate_" + capability.name.split(".", 1)[1], None)):
            continue
        for status in ("COMPLETED", "BLOCKED"):
            for language in ("ru", "en"):
                facts = StepFacts(capability.name, "Step title", status, reason="something went wrong")
                story = narrate(adapter, facts, language)
                assert isinstance(story, Narrative) and story.heading, capability.name
                if status != "COMPLETED":
                    assert not story.finding and story.paragraphs, capability.name
                checked += 1
    assert checked >= 100  # forensics, autopsy, burp, browser and core all describe their steps


def test_attached_answers_are_rendered_into_the_report(tmp_path: Path, config, registry, monkeypatch) -> None:
    source = tmp_path / "lab.txt"
    source.write_text("Цель работы: научиться считать хеши.\n1. Вычислить SHA-256 файлов\n"
                      "2. Как отличить MD5 от SHA-256 по длине значения?\n", encoding="utf-8")
    workspace, state, _ = run_assignment([source], tmp_path / "ws", "deterministic", config=config, registry=registry,
                                         screenshot_fn=fake_screenshot, environment=EMPTY_ENVIRONMENT)
    manual = next(t for t in state.plan.steps if t.action == "core.manual_review")
    answers = tmp_path / "answers.md"
    answers.write_text("# Ответы\n\n## Вопрос 2\n\nMD5 занимает 32 hex-символа, SHA-256 — **64**.\n\n"
                       "| Алгоритм | Длина |\n|---|---|\n| MD5 | 32 |\n| SHA-256 | 64 |\n", encoding="utf-8")
    from lab_agent import cli

    monkeypatch.setattr("sys.argv", ["lab-agent", "complete-step", str(workspace), str(manual.id), "--verification",
                                     "answers written", "--attach", str(answers)])
    cli.main()
    assert (workspace / "results" / "answers.md").is_file()
    report = build_report(workspace, registry)
    assert report.language == "ru"
    kinds = [(b.kind, b.text) for b in report.blocks]
    assert ("h1", "1. Цель работы") in kinds and ("p", "научиться считать хеши.") not in kinds
    assert any(b.kind == "table" and b.rows[0] == ["Алгоритм", "Длина"] for b in report.blocks)
    assert any(b.kind == "p" and "**64**" in b.text for b in report.blocks)
    start = next(i for i, b in enumerate(report.blocks) if b.kind == "h1" and b.text.endswith("Вывод"))
    conclusion = [b.text for b in report.blocks[start + 1:]]
    assert conclusion[0] == "Все задания лабораторной работы выполнены."


@pytest.mark.parametrize("language", ["ru", "en"])
def test_unfinished_step_never_claims_a_result(language: str, registry) -> None:
    adapter = registry.adapter_for("autopsy.inspect_results")
    facts = StepFacts("autopsy.inspect_results", "Inspect", "BLOCKED", details={"files": 0},
                      reason="not started: dependency step 3 is BLOCKED")
    story = narrate(adapter, facts, language)
    assert len(story.paragraphs) == 1 and story.tables == []
    assert ("не запускался" if language == "ru" else "was not started") in story.paragraphs[0]
