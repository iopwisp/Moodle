# DoneAsik Lab Agent

Локальный агент для учебных лабораторных по кибербезопасности, форензике и сетям.

```text
Задание + материалы + evidence
  → Analyzer (PDF/DOCX/TXT/MD/CSV/JSON/ZIP, роли файлов, шаги, вопросы, deliverables)
  → Planner (AI или детерминированный, только capabilities из реестра, валидация плана)
  → Runner (DAG зависимостей, policy, human-in-the-loop, pause/stop/resume)
  → Integrations (forensics, autopsy, wireshark, burp, browser, packet_tracer, overleaf, powershell, desktop, ...)
  → Verification (независимые проверки post-condition)
  → Evidence (только реальные файлы + SHA-256 + manifest)
  → DOCX + PDF отчёт и web-панель
```

Главные правила: исходники не изменяются (работа только с копиями), шаг становится `COMPLETED`
только при подтверждённом результате, а всё, что нельзя сделать автоматически или безопасно,
получает статус `BLOCKED` или `FAILED` с причиной, без фиктивных результатов.

## Установка

```powershell
py -3.12 -m pip install -e ".[all]"
py -3.12 -m playwright install chromium
copy config.example.yaml config.yaml   # по желанию: ФИО, группа, разрешённые хосты, AI
```

Если `Scripts` не в `PATH`, вместо `lab-agent` используйте `py -3.12 -m lab_agent.cli`.

## Проверка окружения

```powershell
lab-agent doctor              # Python, зависимости, приложения и версии, WSL-инструменты, AI, скриншоты
lab-agent environment --wsl   # environment.json с путями и версиями
lab-agent capabilities        # все capabilities (97 во встроенных интеграциях)
lab-agent plugins             # интеграции, их источник и ошибки загрузки плагинов
```

Приложения ищутся в таком порядке: `applications:` в config.yaml, переменные `LAB_AGENT_*_PATH`,
`PATH`, типовые каталоги установки, реестр Windows. Пример:

```powershell
$env:LAB_AGENT_AUTOPSY_PATH = "C:\Program Files\Autopsy-4.22.1\bin\autopsy64.exe"
```

## Запуск

```powershell
lab-agent run "C:\Users\me\Downloads\Assignment_3_Student_Materials.zip" --ai-provider auto
lab-agent plan  "C:\Assignments\lab4" --allowed-target dvwa.lab.local   # только план, без выполнения
lab-agent status  .\workspace\Assignment_3_Student_Materials
lab-agent resume  .\workspace\Assignment_3_Student_Materials            # продолжить после ошибки/паузы/установки инструмента
lab-agent pause|stop .\workspace\...                                     # из другого терминала
lab-agent approve .\workspace\... 7                                      # подтвердить шаг, ожидающий человека
lab-agent review  .\workspace\...                                        # готовность к сдаче
lab-agent report  .\workspace\...                                        # пересобрать DOCX/PDF
lab-agent serve                                                          # http://127.0.0.1:8765
```

`run` возвращает код 0 только при статусе `COMPLETED` и код 3, если остались FAILED или BLOCKED шаги.

AI-провайдер: `OPENAI_API_KEY` (OpenAI Responses API со strict JSON schema) или `OLLAMA_HOST` (Ollama).
Без них работает детерминированный планировщик: он использует шаблоны процессов, которые
публикуют интеграции, и сопоставляет требования по ключевым словам. Выдуманных capabilities,
shell-команд, координат мыши и сетевых целей нет: план проверяется до выполнения.

## Workspace

```text
workspace/<Assignment>/
  input/        копии оригиналов (MD5/SHA-1/SHA-256 в metadata/input_manifest.json)
  working/      распакованные архивы, рабочие копии образов, кейсы Autopsy
  results/      результаты capabilities (CSV, логи, восстановленные файлы...)
  screenshots/  окна приложений (не весь рабочий стол, если окно найдено)
  evidence/     registry.json (+ metadata/evidence_manifest.json)
  logs/         execution.jsonl, commands.jsonl
  metadata/     анализ, план, environment.json, planner.json
  state/        state.json (checkpoint) и agent.db (SQLite: runs, tasks, events, evidence, verifications, errors)
  reports/      <Assignment>_Report.docx / .pdf
```

## Web-панель

`lab-agent serve` показывает загрузку файлов, анализ и план, текущий шаг и приложение, прогресс,
события в реальном времени (SSE), скриншоты, evidence с хешами, ошибки, кнопки
Start/Resume, Pause, Stop, Retry и Approve/Reject, а также ссылки на DOCX и PDF.

## Документация

* [docs/architecture.md](docs/architecture.md) — компоненты и поток выполнения
* [docs/plugin_development.md](docs/plugin_development.md) — как добавить приложение, не меняя ядро
* [docs/configuration.md](docs/configuration.md) — все настройки и переменные окружения
* [docs/troubleshooting.md](docs/troubleshooting.md) — типовые причины BLOCKED/FAILED
* [docs/verification_status.md](docs/verification_status.md) — что проверено в CI, локально и на реальных приложениях

## Разработка

```powershell
py -3.12 -m ruff check src tests
py -3.12 -m mypy
py -3.12 -m pytest -q -rs
```

Используйте Burp, браузер и сетевые инструменты только на локальных, намеренно уязвимых
или явно разрешённых учебных стендах.
