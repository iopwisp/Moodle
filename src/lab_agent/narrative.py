"""Plain-language description of steps for the student report.

Integrations describe their own capabilities through ``narrate_<action>``
(see :class:`lab_agent.integrations.base.BaseIntegration`).  This module holds
what they share - language detection, Russian plurals, path shortening, table
column names - and the generic description used when an integration has none.

Style rules for every text produced here (the report must read like a student
wrote it, not like a log or a chatbot):

* past tense, impersonal or "we" in Russian (no gendered first-person verbs);
* concrete values (file names, offsets, counts) instead of adjectives;
* no tool identifiers (``forensics.carve``), no JSON, no "checks passed";
* no filler such as "It is important to note" / "Важно отметить" / "Таким образом".
"""

from __future__ import annotations

import re
from pathlib import PurePosixPath, PureWindowsPath
from typing import Any

from .integrations.base import Narrative, StepFacts

CYRILLIC = re.compile(r"[А-Яа-яЁё]")
LATIN = re.compile(r"[A-Za-z]")


def detect_language(*texts: str) -> str:
    """``"ru"`` when the assignment text is mostly Cyrillic, otherwise ``"en"``."""
    sample = " ".join(t for t in texts if t)[:20000]
    cyrillic, latin = len(CYRILLIC.findall(sample)), len(LATIN.findall(sample))
    return "ru" if cyrillic > 0 and cyrillic >= latin * 0.6 else "en"


def is_language(text: str, language: str) -> bool:
    return bool(text) and detect_language(text) == language


def plural(n: int, forms: tuple[str, str, str]) -> str:
    """Russian plural: plural(5, ("файл", "файла", "файлов")) -> "5 файлов"."""
    tail, tens = n % 10, n % 100
    form = forms[0] if tail == 1 and tens != 11 else forms[1] if 2 <= tail <= 4 and not 12 <= tens <= 14 else forms[2]
    return f"{n} {form}"


def count(n: int, language: str, ru: tuple[str, str, str], en: tuple[str, str]) -> str:
    return plural(n, ru) if language == "ru" else f"{n} {en[0] if n == 1 else en[1]}"


def name(path: Any) -> str:
    """Last path component for Windows, POSIX and workspace-relative paths alike."""
    text = str(path or "")
    return (PureWindowsPath(text).name if "\\" in text else PurePosixPath(text).name) or text


def short_hash(value: Any, length: int = 16) -> str:
    text = str(value or "")
    return text if len(text) <= length else text[:length] + "…"


def hex_offset(value: Any) -> str:
    if isinstance(value, str) and value.lower().startswith("0x"):
        return "0x" + value[2:].upper().rjust(8, "0")
    try:
        return f"0x{int(value):08X}"
    except (TypeError, ValueError):
        return str(value)


def join(items: list[str], language: str) -> str:
    items = [i for i in items if i]
    if len(items) <= 1:
        return "".join(items)
    last = " и " if language == "ru" else " and "
    return ", ".join(items[:-1]) + last + items[-1]


def shorten_paths(text: str, workspace: Any = None) -> str:
    """Commands as a reader wants to see them: workspace paths become relative, WSL mounts disappear."""
    if workspace is not None:
        root = str(workspace)
        for variant in {root, root.replace("\\", "/"), root.replace("/", "\\")}:
            text = text.replace(variant + "\\", "").replace(variant + "/", "").replace(variant, ".")
    text = re.sub(r"/mnt/[a-z]/(?:[^ /]+/)*?workspace/[^ /]+/", "", text)
    return text


# ---------------------------------------------------------------------------- tables
COLUMNS = {
    "ru": {
        "file": "Файл", "name": "Имя", "path": "Путь", "size": "Размер, байт", "sha256": "SHA-256", "md5": "MD5",
        "type": "Тип", "role": "Роль", "offset": "Смещение", "offset_hex": "Смещение", "estimated_offset": "Смещение",
        "bytes": "Байты", "status": "Состояние", "tool": "Инструмент", "valid": "Корректен", "explanation": "Пояснение",
        "files": "Файлы", "declared_extension": "Расширение", "detected_type": "Фактический тип",
        "description": "Описание", "signature_hex": "Первые байты (hex)", "header_offset": "Смещение заголовка",
        "match": "Совпадает", "conclusion": "Вывод", "url": "URL", "method": "Метод", "count": "Количество",
        "parameter": "Параметр", "value": "Значение", "time": "Время", "source": "Источник", "destination": "Назначение",
        "protocol": "Протокол", "length": "Длина", "info": "Информация", "packets": "Пакетов", "artifact": "Артефакт",
        "builtin": "Скрипт", "foremost": "Foremost", "scalpel": "Scalpel", "autopsy": "Autopsy",
    },
    "en": {
        "file": "File", "size": "Size, bytes", "sha256": "SHA-256", "offset": "Offset", "offset_hex": "Offset",
        "estimated_offset": "Offset", "type": "Type", "status": "Status", "tool": "Tool", "explanation": "Note",
        "builtin": "Script", "declared_extension": "Extension", "detected_type": "Actual type",
        "signature_hex": "First bytes (hex)", "header_offset": "Header offset", "match": "Matches", "conclusion": "Conclusion",
    },
}
VALUES = {
    "ru": {"yes": "да", "no": "нет", "unknown": "не определено", "True": "да", "False": "нет", "valid": "корректен",
           "invalid/partial": "повреждён / неполный", "header": "заголовок", "footer": "подвал", "structure": "структура"},
    "en": {"True": "yes", "False": "no"},
}


def localize_rows(rows: list[dict[str, Any]], language: str, keep: list[str] | None = None) -> list[list[str]]:
    """Table rows -> header + cells with localized column names and yes/no values."""
    if not rows:
        return []
    keys = keep or list(rows[0].keys())
    columns, values = COLUMNS.get(language, {}), VALUES.get(language, {})
    header = [columns.get(k, k.replace("_", " ").capitalize()) for k in keys]
    body = [[values.get(str(row.get(k, "")), str(row.get(k, ""))) for k in keys] for row in rows]
    return [header, *body]


# ---------------------------------------------------------------------------- generic text
# Typical reasons recorded by the runner and the integrations, said the way a student would say them.
# Anything not listed is quoted as the program's own message.
REASONS = [
    (r"^not started: dependency step \d+ is \w+",
     {"ru": "шаг не запускался, так как не выполнен предыдущий шаг, результаты которого он использует",
      "en": "it was not started because an earlier step it depends on did not finish"}),
    (r"^waiting for confirmation",
     {"ru": "шаг ждёт подтверждения студента", "en": "the step is waiting for the student's confirmation"}),
    (r"^(?P<app>[\w .\-]+?) is not installed or not configured",
     {"ru": "программа {app} не установлена на этом компьютере", "en": "{app} is not installed on this computer"}),
    (r"^(?P<app>[\w\-]+) is not installed natively or in WSL",
     {"ru": "утилита {app} не установлена (ни в Windows, ни в WSL)", "en": "{app} is not installed (neither in Windows nor in WSL)"}),
    (r"^The Sleuth Kit '(?P<app>\w+)' is not installed",
     {"ru": "утилита {app} из The Sleuth Kit не установлена", "en": "The Sleuth Kit tool {app} is not installed"}),
    (r"proxy on 127\.0\.0\.1:(?P<port>\d+) is not listening",
     {"ru": "Burp запущен, но его прокси на порту {port} ещё не включён (в окне Burp нужно выбрать Temporary project → "
            "Next → Start Burp)",
      "en": "Burp is open but its proxy on port {port} is not running yet (choose Temporary project → Next → Start Burp)"}),
    (r"No registered capability can perform",
     {"ru": "автоматически этот пункт не выполняется, его нужно сделать вручную",
      "en": "it cannot be automated and has to be done by hand"}),
    (r"require the student's own|Manual verification required|cannot be automated",
     {"ru": "эту часть студент выполняет сам", "en": "this part is done by the student"}),
    (r"is not an authorized target",
     {"ru": "адрес не входит в список разрешённых учебных целей", "en": "the address is not an authorised lab target"}),
]


def human_reason(reason: str, language: str) -> str:
    text = re.sub(r";?\s*\d+/\d+ checks passed.*$", "", reason or "", flags=re.DOTALL).strip().rstrip(".")
    for pattern, phrases in REASONS:
        match = re.search(pattern, text, re.IGNORECASE)
        if match:
            return phrases[language].format(**match.groupdict())
    if not text:
        return ""
    return f"программа сообщила «{text}»" if language == "ru" else f"the program reported “{text}”"


def not_done(facts: StepFacts, language: str) -> str:
    """Honest sentence for a step that did not produce a verified result."""
    reason = human_reason(facts.reason, language)
    if language == "ru":
        lead = {"BLOCKED": "Этот шаг выполнить не удалось", "FAILED": "Этот шаг завершился ошибкой",
                "SKIPPED": "Этот шаг был пропущен"}.get(facts.status, "Этот шаг не выполнялся")
        return f"{lead}: {reason}." if reason else f"{lead}."
    lead = {"BLOCKED": "This step could not be carried out", "FAILED": "This step failed",
            "SKIPPED": "This step was skipped"}.get(facts.status, "This step was not run")
    return f"{lead}: {reason}." if reason else f"{lead}."


def heading_for(facts: StepFacts, language: str) -> str:
    """The assignment's own wording when it is in the report language, otherwise the plan title."""
    for ref in facts.requirement_refs:
        if is_language(ref, language) and len(ref) <= 120:
            return ref.rstrip(".:")
    return facts.title


def generic(facts: StepFacts, language: str, description: str = "") -> Narrative:
    heading = heading_for(facts, language)
    if not facts.completed:
        return Narrative(heading, [not_done(facts, language)], tables=None)
    paragraphs = [str(p) for s in facts.sections for p in s.get("paragraphs", [])]
    if not paragraphs:
        files = [name(p) for p in facts.evidence][:6]
        if language == "ru":
            text = f"Шаг «{facts.title}» выполнен."
            if files:
                text += " Результат сохранён в " + ("файле " if len(files) == 1 else "файлах ") + join(files, language) + "."
        else:
            text = description.rstrip(".") + "." if description else f"The step “{facts.title}” was carried out."
            if files:
                text += " The result is saved in " + join(files, language) + "."
        paragraphs = [text]
    return Narrative(heading, paragraphs)


def narrate(adapter: Any, facts: StepFacts, language: str, description: str = "") -> Narrative:
    """The integration's own description, or the generic one when it has none or it fails."""
    hook = getattr(adapter, "narrate", None)
    if callable(hook):
        try:
            result = hook(facts, language)
        except Exception:  # noqa: BLE001 - a broken description must never break the report
            result = None
        if isinstance(result, Narrative):
            if not facts.completed:
                # Descriptions are written for finished steps; for an unfinished one only the heading is kept
                # (no claims about results that do not exist), unless the integration explained the outcome itself.
                if not result.outcome_explained:
                    result.paragraphs = [not_done(facts, language)]
                result.finding = ""
                result.tables = []
            return result
    return generic(facts, language, description)
