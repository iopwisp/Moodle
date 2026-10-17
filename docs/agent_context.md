# Короткий контекст и повторяемые сценарии

```powershell
py -3.12 -m lab_agent.cli context workspace/MyLab
py -3.12 -m lab_agent.cli context workspace/MyLab --step 2
py -3.12 -m lab_agent.cli context workspace/MyLab --verify --limit 3
```

По умолчанию команда читает checkpoint и реестр evidence, без AI, открытия программ и пересчёта
хешей. Выводит компактный JSON: цель, счётчики статусов, до пяти актуальных шагов, последние ошибки,
ожидающие подтверждения, пути к evidence и отчётам и рекомендуемое действие. Ошибки и строки
ограничены по длине, известные секреты маскируются. Полные логи не включаются.

Это снимок сохранённого состояния, а не проверка текущего окна, сети или целостности файлов.
При наличии [паспорта стенда](lab_passport.md) раздел `lab_scope` содержит его краткую сводку
и результат текущей проверки источника. Это не подтверждение фактического разрешения третьей стороны.
Раздел `screenshots` показывает непокрытые пункты [плана скриншотов](screenshot_checklist.md).
Без `--verify` это сводка по сохранённым отметкам evidence; с флагом хеши проверяются заново.
`recorded_verified` отражает сохранённую отметку. `--verify` заново проверяет зарегистрированные
evidence и их SHA-256; оригиналы этим флагом не перепроверяются. `--step N` раскрывает параметры,
зависимости и проверки выбранного шага. `--limit` принимает 1–50.

## Сценарии

```powershell
# Подготовить план, не выполнять:
py -3.12 -m lab_agent.cli scenario scenarios/hash_inputs.yaml assignment.txt

# Хешировать входные файлы, проверить evidence и сформировать отчёты:
py -3.12 -m lab_agent.cli scenario scenarios/hash_inputs.yaml assignment.txt --execute

# Сверить образ с предоставленным checksum:
py -3.12 -m lab_agent.cli scenario scenarios/verify_image.yaml evidence.dd evidence.dd.sha256 --execute
```

Второй сценарий ожидает именно имена `evidence.dd` и `evidence.dd.sha256`; для других имён
измените пути в YAML. Бинарные входные файлы допустимы без отдельного текста задания.
Каждый запуск создаёт новый workspace с копиями исходных файлов. Существующий план не заменяется.

В YAML задаются `name`, `objective` и `steps`. У шага обязательна `action` из реестра;
допустимы `parameters`, `title`, `description`, `depends_on`, `run_after`, `required`,
`evidence_required`, `evidence_type_required`, `screenshot_required`, `expected_result`,
`verification_checks`, `requirement_refs`. По умолчанию шаг зависит от предыдущего;
`depends_on: []` снимает эту зависимость. Сохранённые статусы и неизвестные поля запрещены.

План проходит штатную валидацию до создания workspace. При выполнении действуют обычные
policy, подтверждения, проверки результата и evidence. Копия YAML и её SHA-256 сохраняются
в `metadata/scenario.yaml` и `metadata/scenario.json`.

AI-планировщик и AI-советы восстановления при `scenario --execute` отключены. Если сам выбранный
инструмент использует AI, это отдельный вызов; сценарии не делают такую операцию бесплатной.
Обычный `resume` использует текущий config, включая настройку AI-советов восстановления.
Готовые примеры выполняют только указанные операции и не заменяют полное задание преподавателя.
