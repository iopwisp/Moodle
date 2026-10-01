"""How Autopsy steps read in the student report (see :mod:`lab_agent.narrative`)."""

from __future__ import annotations

from ..narrative import count, join, localize_rows, name
from .base import Narrative, StepFacts

ARTIFACTS_RU = {
    "Extension Mismatch Detected": "несоответствие расширения содержимому",
    "Keyword Hits": "совпадения по ключевым словам",
    "Data Source Usage": "сведения об использовании источника данных",
    "EXIF Metadata": "метаданные EXIF",
    "Recent Documents": "недавние документы",
    "Web History": "история браузера",
    "Installed Programs": "установленные программы",
    "Encryption Detected": "обнаруженное шифрование",
    "Interesting Files": "интересные файлы",
}


def _artifacts(details: dict, language: str) -> str:
    artifacts = details.get("artifacts") or {}
    if not isinstance(artifacts, dict) or not artifacts:
        return ""
    if language == "ru":
        return join([f"{ARTIFACTS_RU.get(k, k)} — {v}" for k, v in artifacts.items()], language)
    return join([f"{k}: {v}" for k, v in artifacts.items()], language)


class AutopsyNarration:
    def narrate_ingest(self, facts: StepFacts, language: str) -> Narrative:
        d = facts.details
        source = name(d.get("data_source") or facts.parameters.get("data_source") or "образ")
        files, unalloc = int(d.get("files") or 0), int(d.get("unallocated_or_carved") or 0)
        artifacts = _artifacts(d, language)
        if language == "ru":
            text = (f"В Autopsy создали новое дело, добавили рабочую копию {source} как источник данных (Disk Image) и "
                    "запустили стандартный набор модулей анализа (ingest).")
            if not facts.completed:
                return Narrative("Исследование образа в Autopsy", [text])
            text += (f" Анализ завершился полностью: в базе дела {count(files, language, ('объект', 'объекта', 'объектов'), ('', ''))} "
                     f"файловой системы, из них {unalloc} — в нераспределённом пространстве или восстановлены.")
            if artifacts:
                text += f" Модули анализа добавили результаты: {artifacts}."
            return Narrative("Исследование образа в Autopsy", [text], tables=[],
                             finding=f"Autopsy проиндексировал образ ({files} объектов)"
                                     + (f" и отметил: {artifacts}." if artifacts else "."))
        text = (f"A new Autopsy case was created, the working copy {source} was added as a disk image data source and the "
                "default ingest modules were run.")
        if facts.completed:
            text += f" Ingest finished: the case database lists {files} file-system objects, {unalloc} of them unallocated or carved."
            if artifacts:
                text += f" Ingest results: {artifacts}."
        return Narrative("Examination in Autopsy", [text], tables=[])

    def narrate_inspect_results(self, facts: StepFacts, language: str) -> Narrative:
        d = facts.details
        artifacts = _artifacts(d, language)
        raw = d.get("artifacts")
        found: dict = raw if isinstance(raw, dict) else {}
        rows = localize_rows([{"artifact": ARTIFACTS_RU.get(k, k) if language == "ru" else k, "count": v}
                              for k, v in found.items()], language)
        tables = [{"caption": "Результаты модулей анализа Autopsy" if language == "ru" else "Autopsy ingest results",
                   "rows": rows}] if rows else []
        if language == "ru":
            text = (f"Результаты анализа выгрузили из базы дела: список из "
                    f"{count(int(d.get('files') or 0), language, ('файла', 'файлов', 'файлов'), ('', ''))} сохранён в "
                    "autopsy_files.csv, сводка артефактов — в autopsy_results_summary.json.")
            text += f" Модули анализа отметили: {artifacts}." if artifacts else " Модули анализа артефактов не отметили."
            return Narrative("Результаты Autopsy", [text], tables=tables)
        text = f"The results were exported from the case database: {d.get('files')} files in autopsy_files.csv."
        text += f" Ingest results: {artifacts}." if artifacts else " The ingest modules reported no artifacts."
        return Narrative("Autopsy results", [text], tables=tables)

    def narrate_search_artifacts(self, facts: StepFacts, language: str) -> Narrative:
        query, matches = facts.details.get("query") or facts.parameters.get("query"), facts.details.get("matches", 0)
        if language == "ru":
            return Narrative(f"Поиск «{query}» в деле Autopsy", [
                f"По имени файлов и тексту артефактов выполнили поиск «{query}»: совпадений — {matches}."])
        return Narrative(f"Search for “{query}” in Autopsy", [f"Searching file names and artifact text for “{query}” gave {matches} hits."])

    def narrate_export_artifact(self, facts: StepFacts, language: str) -> Narrative:
        file, size = facts.details.get("name") or facts.parameters.get("name"), facts.details.get("size")
        if language == "ru":
            return Narrative(f"Извлечение файла {file}", [
                (f"Файл {file} извлекли из образа по его размещению в файловой системе (как Extract File в Autopsy); "
                f"размер — {size} байт.")])
        return Narrative(f"Extraction of {file}", [f"{file} was extracted from the image using its file-system layout ({size} bytes)."])

    def narrate_generate_report(self, facts: StepFacts, language: str) -> Narrative:
        if language == "ru":
            return Narrative("Отчёт Autopsy", ["Средствами Autopsy сформировали HTML-отчёт по делу (autopsy_report.html)."])
        return Narrative("Autopsy report", ["Autopsy generated an HTML report for the case (autopsy_report.html)."])

    def narrate_open_case_gui(self, facts: StepFacts, language: str) -> Narrative:
        if language == "ru":
            return Narrative("Дело в интерфейсе Autopsy", ["Открыли дело в графическом интерфейсе Autopsy, окно показано на рисунке."],
                             figure_caption="Дело в Autopsy")
        return Narrative("The case in the Autopsy GUI", ["The case was opened in the Autopsy GUI (see the figure)."],
                         figure_caption="The case in Autopsy")

    narrate_capture_evidence = narrate_open_case_gui
