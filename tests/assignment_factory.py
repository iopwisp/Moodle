"""Builds a synthetic forensic assignment equivalent in structure to Assignment 3."""

from __future__ import annotations

import hashlib
import io
import zipfile
from pathlib import Path

from PIL import Image

CLUSTER_A = 0x8000
CLUSTER_B = 0xC000
CLUSTER = 4096


def _jpeg() -> bytes:
    buffer = io.BytesIO()
    Image.new("RGB", (40, 30), (200, 40, 40)).save(buffer, "JPEG")
    return buffer.getvalue()


def _png() -> bytes:
    buffer = io.BytesIO()
    Image.new("RGB", (8, 8), (10, 200, 10)).save(buffer, "PNG")
    return buffer.getvalue()


def _pdf() -> bytes:
    from reportlab.pdfgen import canvas

    buffer = io.BytesIO()
    page = canvas.Canvas(buffer)
    page.drawString(72, 720, "Confidential network diagram")
    page.save()
    return buffer.getvalue()


def split_zip() -> tuple[bytes, bytes]:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_STORED) as archive:
        archive.writestr("document.txt", "Confidential budget 2026\n")
    data = buffer.getvalue()
    eocd = data.rfind(b"PK\x05\x06")
    cd_offset = int.from_bytes(data[eocd + 16:eocd + 20], "little")
    part1 = bytearray(data[:cd_offset].ljust(CLUSTER, b"\x00"))
    part2 = bytearray(data[cd_offset:])
    eocd2 = part2.rfind(b"PK\x05\x06")
    part2[eocd2 + 16:eocd2 + 20] = CLUSTER.to_bytes(4, "little")
    part1[0:4] = b"ABCD"
    return bytes(part1), bytes(part2).ljust(CLUSTER, b"\x00")


def build_image() -> bytes:
    image = bytearray(CLUSTER_B + CLUSTER)
    for offset, blob in ((0x1000, _jpeg()), (0x3000, _pdf()), (0x6000, _png())):
        image[offset:offset + len(blob)] = blob
    part1, part2 = split_zip()
    image[CLUSTER_A:CLUSTER_A + CLUSTER] = part1
    image[CLUSTER_B:CLUSTER_B + CLUSTER] = part2
    return bytes(image)


ASSIGNMENT_TEXT = [
    "Лабораторная работа: Расследование утечки данных и карвинг файлов",
    "Цель работы",
    "1. Освоить работу с шестнадцатеричными (Hex) сигнатурами файлов.",
    "2. Научиться применять утилиты карвинга (Foremost, Scalpel) и Autopsy.",
    "Часть 1: Теоретический опрос",
    "1. В чем различие между восстановлением по метаданным и Data Carving?",
    "Часть 3: Практический карвинг (Foremost и Scalpel)",
    "Напишите команду foremost для поиска PDF и JPG в образе evidence.dd.",
    "Часть 7: Ручной карвинг ZIP",
    "Фрагмент №1 (Кластер А, смещение 0x00008000), Фрагмент №2 (Кластер Б, смещение 0x0000C000).",
    "Подозреваемый заменил сигнатуру ZIP 50 4B 03 04 на ABCD. Соберите evidence_fixed.zip.",
    "Требования к отчету: comparison_results.csv, recovered_files_sha256.csv, chain_of_custody.csv, commands.txt.",
    "Сделайте скриншот результатов Autopsy.",
]


def assignment_docx() -> bytes:
    from docx import Document

    document = Document()
    for line in ASSIGNMENT_TEXT:
        document.add_paragraph(line)
    buffer = io.BytesIO()
    document.save(buffer)
    return buffer.getvalue()


def build_assignment_zip(folder: Path, name: str = "Assignment_3_Student_Materials") -> Path:
    image = build_image()
    members = {
        f"{name}/Assignment_3_RU.docx": assignment_docx(),
        f"{name}/evidence.dd": image,
        f"{name}/evidence.dd.sha256": f"{hashlib.sha256(image).hexdigest()}  evidence.dd\n".encode(),
        f"{name}/system_log.txt": _png(),
        f"{name}/scalpel.conf": (b"# png y 5000000 \\x89\\x50\\x4e\\x47\\x0d\\x0a\\x1a\\x0a \\x49\\x45\\x4e\\x44\\xae\\x42\\x60\\x82\n"
                                 b"pdf y 10000000 \\x25\\x50\\x44\\x46 \\x25\\x25\\x45\\x4f\\x46\n"),
        f"{name}/README_Student_RU.txt": "Начните с файла Assignment_3_RU.docx.".encode(),
        "__MACOSX/._evidence.dd": b"junk",
    }
    target = folder / f"{name}.zip"
    with zipfile.ZipFile(target, "w", zipfile.ZIP_DEFLATED) as archive:
        for member, data in members.items():
            archive.writestr(member, data)
    return target
