"""How forensic steps read in the student report (see :mod:`lab_agent.narrative`)."""

from __future__ import annotations

import re
from collections import Counter
from typing import Any

from ..narrative import count, hex_offset, join, localize_rows, name
from .base import Narrative, StepFacts

KNOWN_BYTES = (
    ("89 50 4e 47", {"ru": "сигнатура PNG", "en": "the PNG signature"}),
    ("ff d8 ff", {"ru": "сигнатура JPEG", "en": "the JPEG signature"}),
    ("25 50 44 46", {"ru": "сигнатура PDF (%PDF)", "en": "the PDF signature (%PDF)"}),
    ("50 4b 03 04", {"ru": "локальный заголовок файла ZIP", "en": "a ZIP local file header"}),
    ("50 4b 01 02", {"ru": "запись центрального каталога ZIP", "en": "a ZIP central directory record"}),
    ("50 4b 05 06", {"ru": "запись End of Central Directory архива ZIP", "en": "a ZIP End of Central Directory record"}),
    ("eb 3c 90", {"ru": "загрузочный сектор FAT", "en": "a FAT boot sector"}),
)


def _bytes_meaning(first_bytes: str, language: str) -> str:
    text = first_bytes.lower()
    return next((meaning[language] for prefix, meaning in KNOWN_BYTES if text.startswith(prefix)), "")


def _upper_hex(text: Any, limit: int = 8) -> str:
    return " ".join(str(text).upper().split()[:limit])


def _audit_counts(facts: StepFacts) -> dict[str, int]:
    """Per-type counts from a Foremost audit file ("pdf:= 2") or from the carved file names."""
    counts: Counter[str] = Counter()
    if facts.workspace is not None:
        for path in facts.evidence:
            if path.endswith("_audit.txt"):
                try:
                    text = (facts.workspace / path).read_text(encoding="utf-8", errors="replace")
                except OSError:
                    continue
                for kind, value in re.findall(r"^(\w+):=\s*(\d+)", text, re.MULTILINE):
                    counts[kind] += int(value)
    if not counts:
        counts.update(path.rsplit(".", 1)[-1].lower() for path in facts.evidence
                      if "." in name(path) and not path.endswith((".txt", ".conf")))
    return dict(counts)


def _tool_name(tool: str, language: str) -> str:
    if tool == "builtin":
        return "скрипт" if language == "ru" else "script"
    return {"foremost": "Foremost", "scalpel": "Scalpel", "autopsy": "Autopsy"}.get(tool, tool)


def _audit_version(facts: StepFacts, tool: str) -> str:
    if facts.workspace is None:
        return "—"
    for path in facts.evidence:
        if path.endswith("_audit.txt"):
            try:
                text = (facts.workspace / path).read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            found = re.search(rf"{tool}\s+version\s+([\w.\-]+)", text, re.IGNORECASE)
            if found:
                return found.group(1)
    return "—"


def _types_phrase(counts: dict[str, int], language: str) -> str:
    if language == "ru":
        return join([f"{kind.upper()} — {n}" for kind, n in sorted(counts.items())], language)
    return join([f"{n} {kind.upper()}" for kind, n in sorted(counts.items())], language)


class ForensicsNarration:
    """Mixin for :class:`ForensicsAdapter`: one ``narrate_<action>`` per capability."""

    def narrate_verify_image_hash(self, facts: StepFacts, language: str) -> Narrative:
        details, after = facts.details, facts.parameters.get("label") == "after"
        image = name(details.get("image") or facts.parameters.get("image") or "образ")
        reference = name(facts.parameters.get("expected_file") or f"{image}.sha256")
        sha = details.get("sha256", "")
        if language == "ru":
            heading = "Повторная проверка целостности образа" if after else "Проверка целостности исходного образа"
            if not facts.completed:
                return Narrative(heading, [f"Вычислили SHA-256 образа {image} для сравнения с контрольным значением."])
            if after:
                text = (f"После всех операций SHA-256 оригинального образа {image} вычислили ещё раз. Он по-прежнему "
                        f"равен {sha}, то есть за время работы исходный образ не изменился: все действия выполнялись "
                        "с рабочей копией.")
                return Narrative(heading, [text], finding=f"Хеш образа {image} до и после исследования совпадает, "
                                                         "целостность доказательства сохранена.")
            text = (f"Перед началом работы вычислили SHA-256 образа {image} и сравнили его с контрольным значением "
                    f"из файла {reference}. Значения совпали ({sha}), значит образ получен без искажений.")
            return Narrative(heading, [text])
        heading = "Integrity check after the examination" if after else "Integrity check of the source image"
        if not facts.completed:
            return Narrative(heading, [f"The SHA-256 of {image} was computed for comparison with the reference value."])
        if after:
            return Narrative(heading, [(f"After all operations the SHA-256 of the original {image} was computed again. It is "
                                       f"still {sha}, so the source image was not modified; all work used the working copy.")],
                             finding=f"The hash of {image} is identical before and after the examination.")
        return Narrative(heading, [(f"Before the examination the SHA-256 of {image} was computed and compared with the "
                                   f"reference value in {reference}. Both values match ({sha}).")])

    def narrate_working_copy(self, facts: StepFacts, language: str) -> Narrative:
        copy = facts.details.get("copy", "working/evidence_copy")
        if language == "ru":
            return Narrative("Создание рабочей копии", [
                (f"Все дальнейшие операции выполнялись не с оригиналом, а с копией образа ({copy}). SHA-256 копии "
                "совпал с хешем оригинала, то есть копия побитово идентична исходному образу.")])
        return Narrative("Working copy", [(f"All further operations used a copy of the image ({copy}). Its SHA-256 equals "
                                          "the original's, so the copy is bit-for-bit identical.")])

    def narrate_signature_scan(self, facts: StepFacts, language: str) -> Narrative:
        rows = facts.details.get("rows") or facts.section_rows()
        mismatched = [r for r in rows if r.get("match") == "no"]
        keep = ["file", "declared_extension", "detected_type", "signature_hex", "match"]
        table_rows = [{**r, "file": name(r.get("file")), "signature_hex": _upper_hex(r.get("signature_hex"))} for r in rows]
        if language == "ru":
            heading = "Анализ сигнатур файлов"
            paragraphs = [f"Для выданных файлов (кроме самого образа) сравнили расширение с сигнатурой — первыми байтами "
                          f"файла. Проверено {count(len(rows), language, ('файл', 'файла', 'файлов'), ('file', 'files'))}, "
                          + ("расхождений не найдено." if not mismatched else
                             f"расхождение найдено в {count(len(mismatched), language, ('файле', 'файлах', 'файлах'), ('', ''))}.")]
            findings = []
            for row in mismatched:
                kind = str(row.get("detected_type", "")).rstrip("?").upper()
                paragraphs.append(
                    f"Файл {name(row.get('file'))} имеет расширение .{row.get('declared_extension')}, но начинается с байтов "
                    f"{_upper_hex(row.get('signature_hex'))} — это сигнатура {kind}. На самом деле это {kind}-файл, "
                    "а расширение изменено, чтобы скрыть его настоящий тип.")
                findings.append(f"{name(row.get('file'))} — это {kind}, замаскированный под .{row.get('declared_extension')}")
            finding = ("Анализ сигнатур показал подмену расширения: " + "; ".join(findings) + ".") if findings else ""
            return Narrative(heading, paragraphs, finding=finding,
                             tables=[{"caption": "Сравнение расширений и сигнатур файлов",
                                      "rows": localize_rows(table_rows, language, keep)}])
        paragraphs = [(f"For every supplied file except the image the extension was compared with the signature (the first "
                      f"bytes). {len(rows)} files were checked; {len(mismatched) or 'no'} mismatch(es) found.")]
        for row in mismatched:
            kind = str(row.get("detected_type", "")).rstrip("?").upper()
            paragraphs.append(f"{name(row.get('file'))} has the extension .{row.get('declared_extension')} but starts with "
                              f"{_upper_hex(row.get('signature_hex'))}, the {kind} signature: the extension hides its real type.")
        finding = "; ".join(f"{name(r.get('file'))} is really {str(r.get('detected_type', '')).upper()}" for r in mismatched)
        return Narrative("File signature analysis", paragraphs, finding=finding + "." if finding else "",
                         tables=[{"caption": "Extensions versus file signatures", "rows": localize_rows(table_rows, language, keep)}])

    def narrate_image_signatures(self, facts: StepFacts, language: str) -> Narrative:
        rows = facts.section_rows()
        image = name(facts.details.get("image") or "образ")
        headers = Counter(str(r.get("type")) for r in rows if r.get("role") == "header")
        table = localize_rows([{**r, "type": str(r.get("type")).upper()} for r in rows[:40]], language,
                              ["type", "role", "offset_hex", "bytes"])
        if language == "ru":
            text = (f"Чтобы понять, что лежит внутри образа {image}, нашли в нём все известные заголовки и подвалы файлов. "
                    f"Всего найдено {count(len(rows), language, ('сигнатура', 'сигнатуры', 'сигнатур'), ('', ''))}"
                    + (f", из них заголовков: {_types_phrase(dict(headers), language)}." if headers else "."))
            return Narrative(f"Поиск сигнатур внутри образа {image}", [text],
                             tables=[{"caption": f"Сигнатуры, найденные в {image}", "rows": table}])
        return Narrative(f"File signatures inside {image}", [
            f"All known file headers and footers were located inside {image}: {len(rows)} in total"
            + (f", including headers of {_types_phrase(dict(headers), language)}." if headers else ".")],
            tables=[{"caption": f"Signatures found in {image}", "rows": table}])

    def narrate_hex_view(self, facts: StepFacts, language: str) -> Narrative:
        details = facts.details
        target = name(details.get("file") or facts.parameters.get("path"))
        offset = hex_offset(details.get("offset", facts.parameters.get("offset", 0)))
        first = _upper_hex(details.get("first_bytes", ""))
        meaning = _bytes_meaning(str(details.get("first_bytes", "")), language)
        if language == "ru":
            text = f"Открыли {target} в hex-представлении со смещения {offset}. Первые байты: {first}"
            text += f" — {meaning}." if meaning else "; известной сигнатуры здесь нет."
            if str(details.get("first_bytes", "")).lower().startswith("41 42 43 44"):
                text += (" Байты 41 42 43 44 (ASCII «ABCD») стоят на месте сигнатуры локального заголовка ZIP "
                         "50 4B 03 04: заголовок затёрт, при этом дальше по смещению 0x1E читается имя файла.")
            return Narrative(f"Hex-просмотр {target} со смещения {offset}", [text], show_figures=False)
        text = f"{target} was opened in a hex view at offset {offset}. The first bytes are {first}"
        text += f": {meaning}." if meaning else "; they match no known signature."
        return Narrative(f"Hex view of {target} at {offset}", [text], show_figures=False)

    def narrate_carve(self, facts: StepFacts, language: str) -> Narrative:
        tool = str(facts.parameters.get("tool") or facts.details.get("tool") or "builtin")
        types = facts.parameters.get("types") or facts.parameters.get("enable_types") or ""
        types_text = ", ".join(str(t).upper() for t in (types if isinstance(types, list) else str(types).split(",")) if t)
        title = {"builtin": "собственным скриптом" if language == "ru" else "with a Python script",
                 "foremost": "в Foremost" if language == "ru" else "with Foremost",
                 "scalpel": "в Scalpel" if language == "ru" else "with Scalpel"}.get(tool, tool)
        heading = f"Карвинг {title}" if language == "ru" else f"File carving {title}"
        if tool == "builtin":
            listed = facts.details.get("files")
            carved: list[dict[str, Any]] = listed if isinstance(listed, list) else facts.section_rows()
            valid = [c for c in carved if c.get("valid") in (True, "True", "valid")]
            table = localize_rows([{"name": name(c.get("name")), "offset": hex_offset(c.get("offset")), "size": c.get("size"),
                                    "valid": c.get("valid")} for c in carved], language)
            if language == "ru":
                text = ("Для проверки результатов внешних утилит образ сначала обработали собственным скриптом на Python. "
                        f"Он ищет пары «заголовок — подвал» для типов {types_text or 'PDF, JPG, PNG, ZIP'} и вырезает данные "
                        f"между ними. Извлечено {count(len(carved), language, ('файл', 'файла', 'файлов'), ('', ''))}, "
                        f"корректно открываются {len(valid)}.")
                if len(valid) < len(carved):
                    text += (" Остальные обрываются или содержат чужие данные — типичный результат карвинга по сигнатурам "
                             "на фрагментированном образе.")
                return Narrative(heading, [text], tables=[{"caption": "Файлы, извлечённые скриптом", "rows": table}])
            return Narrative(heading, [(f"As a reference the image was first processed by a Python script that cuts data "
                                       f"between header/footer pairs for {types_text or 'PDF, JPG, PNG, ZIP'}: {len(carved)} "
                                       f"files extracted, {len(valid)} of them open correctly.")],
                             tables=[{"caption": "Files extracted by the script", "rows": table}])
        program = _tool_name(tool, language) + (" (WSL)" if facts.details.get("mode") == "wsl" else "")
        software = [(program, _audit_version(facts, tool))] if facts.completed else []
        counts = _audit_counts(facts)
        reported = facts.details.get("files")
        total = sum(counts.values()) or (reported if isinstance(reported, int) else 0)
        if language == "ru":
            if tool == "scalpel":
                intro = ("В конфигурационном файле Scalpel раскомментировали правило для PNG (my_scalpel.conf) и запустили "
                         "утилиту на рабочей копии образа.")
            else:
                intro = f"Foremost запустили на рабочей копии образа с ограничением по типам: {types_text}."
            if not facts.completed:
                return Narrative(heading, [intro])
            result = f" Утилита извлекла {count(int(total), language, ('файл', 'файла', 'файлов'), ('', ''))}"
            result += f" ({_types_phrase(counts, language)})." if counts else "."
            result += " Подробный отчёт о найденных файлах со смещениями записан в audit.txt."
            return Narrative(heading, [intro + result], software=software,
                             finding=(f"{_tool_name(tool, language)} извлёк "
                                      f"{count(int(total), language, ('файл', 'файла', 'файлов'), ('', ''))}"
                                      + (f" ({_types_phrase(counts, language)})." if counts else ".")))
        intro = ("Scalpel was run on the working copy with the PNG rule enabled in my_scalpel.conf." if tool == "scalpel"
                 else f"Foremost was run on the working copy for the types {types_text}.")
        if not facts.completed:
            return Narrative(heading, [intro])
        return Narrative(heading, [intro + f" It extracted {total} files" + (f" ({_types_phrase(counts, language)})." if counts else ".")
                                   + " The audit.txt file lists every file with its offset."], software=software)

    def narrate_hash_directory(self, facts: StepFacts, language: str) -> Narrative:
        rows = facts.section_rows()
        valid = [r for r in rows if r.get("status") == "valid"]
        table = localize_rows([{"tool": _tool_name(str(r.get("tool")), language), "file": name(r.get("file")),
                                "size": r.get("size"), "sha256": r.get("sha256"), "status": r.get("status")} for r in rows],
                              language)
        tools = [_tool_name(t, language) for t in dict.fromkeys(str(r.get("tool")) for r in rows)]
        if language == "ru":
            return Narrative("Хеширование восстановленных файлов", [
                (f"Для каждого восстановленного файла ({join(tools, language)}) вычислили SHA-256 и проверили, открывается "
                f"ли он. Всего {count(len(rows), language, ('файл', 'файла', 'файлов'), ('', ''))}, "
                f"из них корректных — {len(valid)}. Хеши сохранены в recovered_files_sha256.csv.")],
                tables=[{"caption": "SHA-256 восстановленных файлов", "rows": table}])
        return Narrative("Hashes of recovered files", [
            (f"Every recovered file ({join(tools, language)}) was hashed with SHA-256 and checked for validity: "
            f"{len(rows)} files, {len(valid)} valid. The hashes are in recovered_files_sha256.csv.")],
            tables=[{"caption": "SHA-256 of recovered files", "rows": table}])

    def narrate_compare_results(self, facts: StepFacts, language: str) -> Narrative:
        rows = facts.section_rows()
        tools = list(facts.details.get("tools") or [k for k in (rows[0] if rows else {})
                                                      if k not in {"sha256", "type", "size", "explanation", "files"}])
        table_rows = [{"type": str(r.get("type")).upper(), "size": r.get("size"), **{t: r.get(t) for t in tools},
                       "sha256": str(r.get("sha256"))[:16] + "…"} for r in rows]
        sentences = []
        for row in rows:
            found = [t for t in tools if str(row.get(t, "0")) not in {"0", ""}]
            missing = [t for t in tools if t not in found]
            label = f"{str(row.get('type')).upper()} ({row.get('size')} " + ("байт)" if language == "ru" else "bytes)")
            pretty = {"builtin": "скрипт" if language == "ru" else "the script"}
            names = [pretty.get(t, t.capitalize()) for t in found]
            if language == "ru":
                sentences.append(f"{label} нашли все инструменты" if not missing and len(tools) > 1
                                 else f"{label} нашёл только {join(names, language)}" if len(found) == 1
                                 else f"{label} нашли {join(names, language)}")
            else:
                sentences.append(f"{label} was found by " + ("all tools" if not missing and len(tools) > 1 else join(names, language)))
        if language == "ru":
            text = (f"Результаты инструментов сравнили по SHA-256: одинаковый хеш означает один и тот же файл. "
                    f"Уникальных файлов — {len(rows)}. " + "; ".join(sentences) + ".")
            if len(tools) == 1:
                text += " Внешние утилиты к этому моменту результатов не дали, поэтому сравнение неполное."
            return Narrative("Сравнение результатов инструментов", [text],
                             finding=("Все инструменты восстановили одни и те же файлы."
                                      if len(tools) > 1 and all("все" in s for s in sentences) else ""),
                             tables=[{"caption": "Совпадение результатов по SHA-256 (число найденных копий)",
                                      "rows": localize_rows(table_rows, language)}])
        return Narrative("Comparison of the tools", [
            f"The results were compared by SHA-256 (equal hash means the same file): {len(rows)} unique files. "
            + "; ".join(sentences) + "."],
            tables=[{"caption": "Agreement between tools by SHA-256", "rows": localize_rows(table_rows, language)}])

    def narrate_repair_zip_fragments(self, facts: StepFacts, language: str) -> Narrative:
        d, p = facts.details, facts.parameters
        raw = p.get("offsets")
        offsets = [hex_offset(o) for o in (raw if isinstance(raw, list) else str(raw or "").split(",")) if str(o).strip()]
        cluster = p.get("cluster_size", 4096)
        output = name(p.get("output") or "evidence_fixed.zip")
        members = ", ".join(d.get("members") or [])
        dropped = int(d.get("slack_bytes_dropped") or 0)
        original = d.get("original_header_hex", "")
        if language == "ru":
            paragraphs = [
                (f"Архив был разбит на {count(len(offsets), language, ('фрагмент', 'фрагмента', 'фрагментов'), ('', ''))} "
                f"по {cluster} байт, по смещениям {join(offsets, language)}. Оба кластера прочитали из рабочей копии образа."),
            ]
            if not facts.completed:
                return Narrative("Ручная сборка фрагментированного ZIP", paragraphs)
            paragraphs.append(
                f"Первый фрагмент начинается с байтов {original} вместо сигнатуры локального заголовка ZIP 50 4B 03 04. "
                "Эти четыре байта заменили на правильные — остальная структура заголовка не повреждена.")
            paragraphs.append(
                f"В последнем фрагменте нашли запись End of Central Directory (50 4B 05 06) по абсолютному смещению "
                f"{d.get('eocd_absolute_offset')} ({d.get('eocd_offset_in_last_fragment')}-й байт фрагмента). Её длина — 22 байта "
                f"плюс комментарий, поэтому архив логически заканчивается на {d.get('logical_end_in_last_fragment')}-м байте "
                "фрагмента, всё дальше — мусор кластера.")
            if dropped:
                paragraphs.append(
                    f"Между концом центрального каталога и записью EOCD оказалось {dropped} нулевых байт — это остаток "
                    "кластера, а не часть архива. EOCD хранит смещение и длину центрального каталога, и если эти байты "
                    "оставить, архиватор ищет каталог не по тому адресу и не открывает файл. Поэтому их убрали.")
            paragraphs.append(
                f"Собранный файл {output} ({d.get('size')} байт) открывается штатно, контрольные суммы CRC сходятся"
                + (f"; внутри — {members}." if members else ".") + " Сборку выполняет скрипт carve_script_completed.py.")
            return Narrative("Ручная сборка фрагментированного ZIP", paragraphs, show_code=False, tables=[],
                             finding=f"Фрагментированный архив собран вручную: {output} содержит {members or 'исходные файлы'} "
                                     "и проходит проверку CRC.")
        paragraphs = [f"The archive was split into {len(offsets)} fragments of {cluster} bytes at {join(offsets, language)}."]
        if not facts.completed:
            return Narrative("Manual reassembly of the fragmented ZIP", paragraphs)
        paragraphs += [
            (f"The first fragment starts with {original} instead of the ZIP local file header 50 4B 03 04; these four bytes "
            "were restored."),
            (f"The End of Central Directory record (50 4B 05 06) is at {d.get('eocd_absolute_offset')}, so the archive ends at "
            f"byte {d.get('logical_end_in_last_fragment')} of the last fragment."),
            *([(f"{dropped} zero bytes of cluster slack between the central directory and the EOCD were removed; otherwise "
               "readers look for the directory at the wrong offset.")] if dropped else []),
            f"The result {output} ({d.get('size')} bytes) opens and passes the CRC check" + (f"; it contains {members}." if members else ".")]
        return Narrative("Manual reassembly of the fragmented ZIP", paragraphs, show_code=False, tables=[],
                         finding=f"The fragmented archive was rebuilt: {output} passes the CRC check.")

    def narrate_tsk(self, facts: StepFacts, language: str) -> Narrative:
        command = str(facts.parameters.get("command") or facts.details.get("command") or "")
        stdout = str(facts.details.get("stdout") or "")
        fs = re.search(r"File System Type:\s*(\S+)", stdout)
        label = re.search(r"Volume Label \(Boot Sector\):\s*(.+)", stdout)
        oem = re.search(r"OEM Name:\s*(.+)", stdout)
        unknown_fs = "cannot determine file system type" in (str(facts.details.get("stderr") or "") + facts.reason).lower()
        program = "The Sleuth Kit" + (" (WSL)" if facts.details.get("mode") == "wsl" else "")
        software = [(program, "—")] if facts.details.get("exit_code") is not None else []
        if language == "ru":
            heading = f"Анализ файловой системы (The Sleuth Kit, {command})"
            text = f"Структуру файловой системы рабочей копии посмотрели утилитой {command} из The Sleuth Kit."
            if not facts.completed and unknown_fs:
                text += (f" {command} не смог определить тип файловой системы (сообщение «Cannot determine file system "
                         "type»): начиная с нулевого смещения в образе нет файловой системы, которую распознаёт The Sleuth "
                         "Kit. Поэтому метаданные файловой системы этим способом получить нельзя, и файлы восстанавливались "
                         "карвингом.")
                return Narrative(heading, [text], outcome_explained=True, software=software, tables=[])
            finding = ""
            if facts.completed and fs:
                text += f" Образ содержит файловую систему {fs.group(1)}"
                text += f" (OEM-имя {oem.group(1).strip()}" if oem else ""
                text += f", метка тома {label.group(1).strip()})" if label and oem else (")" if oem else "")
                text += "."
                finding = f"Образ содержит файловую систему {fs.group(1)}."
            return Narrative(heading, [text], finding=finding, software=software,
                             tables=[{"caption": f"Вывод {command} (начало)", "code": "\n".join(stdout.splitlines()[:28])}]
                             if facts.completed and stdout else [])
        text = f"The file system of the working copy was examined with {command} from The Sleuth Kit."
        if facts.completed and fs:
            text += f" The image contains a {fs.group(1)} file system."
        if not facts.completed and unknown_fs:
            text += (f" {command} could not determine the file system type: from offset 0 the image holds no file system "
                     "that The Sleuth Kit recognises, so file-system metadata cannot be read this way and files were "
                     "recovered by carving.")
            return Narrative(f"File system analysis (The Sleuth Kit, {command})", [text], outcome_explained=True,
                             software=software, tables=[])
        return Narrative(f"File system analysis (The Sleuth Kit, {command})", [text], software=software,
                         finding=f"The image holds a {fs.group(1)} file system." if fs else "",
                         tables=[{"caption": f"{command} output (beginning)", "code": "\n".join(stdout.splitlines()[:28])}]
                         if facts.completed and stdout else [])

    def narrate_case_records(self, facts: StepFacts, language: str) -> Narrative:
        d = facts.details
        if language == "ru":
            return Narrative("Документирование дела", [
                (f"По итогам работы заполнили документы дела {d.get('case_id', '')}: контекст дела (case_context.csv), "
                f"цепочку хранения доказательств (chain_of_custody.csv, "
                f"{count(int(d.get('custody_rows') or 0), language, ('запись', 'записи', 'записей'), ('', ''))}) и журнал "
                "выполненных команд (commands.txt).")])
        return Narrative("Case documentation", [
            (f"The case records for {d.get('case_id', '')} were written: case_context.csv, chain_of_custody.csv "
            f"({d.get('custody_rows')} entries) and the command log commands.txt.")])
