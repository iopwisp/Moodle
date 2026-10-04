# DoneAsik Lab Agent

Локальный агент для учебных лабораторных по кибербезопасности, форензике и сетям.

```text
Задание + материалы + evidence
  → Analyzer (PDF/DOCX/TXT/MD/CSV/JSON/ZIP, роли файлов, шаги, вопросы, deliverables)
  → Planner (AI или детерминированный, только capabilities из реестра, валидация плана)
  → Runner (DAG зависимостей, policy, human-in-the-loop, pause/stop/resume)
  → Integrations (forensics, autopsy, console, wireshark, burp, browser, packet_tracer, overleaf, powershell, desktop, ...)
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
lab-agent complete-step .\workspace\... 19 --verification "ответы написаны" --attach answers.md   # свои ответы (Markdown) в отчёт
lab-agent report  .\workspace\...                                        # пересобрать DOCX/PDF
lab-agent serve                                                          # http://127.0.0.1:8765
```

`run` возвращает код 0 только при статусе `COMPLETED` и код 3, если остались FAILED или BLOCKED шаги.

Отчётов два: `reports/<Задание>_Report.docx/.pdf` — сам отчёт по лабораторной (титульный лист, цель, исходные данные,
ПО, ход работы обычным текстом на языке задания, ответы, вывод, приложения), и `reports/<Задание>_Audit.docx/.pdf` —
технический журнал (проверки, хеши, ошибки). Скриншоты окон снимаются через `PrintWindow`: окно попадает на снимок,
даже если его что-то перекрывает, а чужие окна — никогда. Шаги, которые нажимают клавиши в окнах программ (Burp,
Packet Tracer, desktop), агент перечисляет перед запуском и объявляет перед каждым: в это время не трогайте мышь и
клавиатуру.

AI-провайдер: `OPENAI_API_KEY` (OpenAI Responses API со strict JSON schema), `OLLAMA_HOST` (Ollama) или
`--ai-provider codex` — Codex CLI (`codex exec --output-schema`) на подписке ChatGPT, под которой вошёл Codex, без
API-ключа. Codex ищется в `PATH`, затем внутри приложения Codex; путь можно задать `LAB_AGENT_CODEX_PATH`. `auto` его не
выбирает: каждый вызов тратит лимит подписки.
Без них работает детерминированный планировщик: он использует шаблоны процессов, которые
публикуют интеграции, и сопоставляет требования по ключевым словам. Выдуманных capabilities,
shell-команд, координат мыши и сетевых целей нет: план проверяется до выполнения.

## Отчёт из Markdown (работа вручную)

Если задание делалось руками, а не через `run`, отчёт собирается из одного Markdown-файла тем же оформлением, что и у
агента (титульник, нумерация рисунков и таблиц, DOCX + PDF):

```markdown
---
title: Анализ и восстановление разделов MBR и GPT
number: 4
course: Introduction to Digital Forensics
output: "{surname}_week4.docx"     # {student} {surname} {group} {student_id} {title}
---
# 1. Цель работы
Обычный текст, **жирный**, *курсив*, `код`.

![Окно TestDisk после анализа](screenshots/testdisk.png)

Таблица: Контрольные суммы образов
![](report_data/hashes.csv)
```

```powershell
lab-agent build-report .\workspace\Assignment4\report.md          # DOCX + PDF рядом с .md
lab-agent build-report report.md --strict                           # не собирать, если проверка стиля нашла проблемы
lab-agent lint-report  .\Surname_week2.docx                         # проверить готовый отчёт
```

ФИО, группа и ID берутся из `report` в config.yaml (их можно переопределить в шапке; `surname:` — если фамилия в
`student_name` стоит не первой). Отсутствующая или битая картинка — ошибка, а не заглушка. `lint-report` ищет шаблонные
фразы, из-за которых текст выглядит сгенерированным («в данной лабораторной работе», «успешно», «таким образом»,
«In conclusion»…), одинаковые начала абзацев, отчёт из одних списков и забытые `TODO` / `[вставить скриншот]`.

## Консольные программы (TestDisk, PhotoRec)

Интеграция `console` запускает текстовую программу в отдельном окне conhost и управляет ею без фокуса: клавиши
пишутся прямо в буфер консоли, экран читается как текст, скриншот снимается с самого окна. Мышь и клавиатуру можно не
отпускать. Каждый шаг сохраняет экран в `results/` и может ждать ожидаемый текст (`wait_for`) — так шаг и проверяется.

```yaml
- console.start:  {program: testdisk, args: ["/log", "case04_work/mbr_working.img"], wait_for: "TestDisk 7"}
- console.keys:   {keys: "{ENTER}", wait_for: "partition table type"}   # {UP} {DOWN} {ESC} {TAB} {F1}..
- console.screenshot: {name: testdisk_types.png}
- console.close:  {}
```

Дисковые утилиты получают только файл образа из workspace (не физический диск); окно с `pwsh`/`cmd` — это произвольные
команды, поэтому оно разрешено только при `policy.powershell.arbitrary: true`.

## Packet Tracer: схема как у студента

Холст Packet Tracer недоступен для UI Automation, но всё вокруг него доступно: кнопки панели устройств и кабелей
(по именам `PC-PT`, `Copper Straight-Through`…), меню свободных портов и окна устройств. Поэтому агент:

- ставит устройство, перетаскивая его модель с панели на свободное место холста (`add_device`), и даёт ему имя
  через Config → Display Name (`rename_device`); можно писать обычные названия: PC, Laptop, Cable Modem, 2911, 2960;
- находит устройства на холсте **обходом** (`survey_canvas`): ищет иконки на снимке окна, кликает каждую и читает
  заголовок открывшегося окна. Каждая координата подтверждена реальным окном устройства, без OCR и угадывания;
- прокладывает кабель (`connect_devices`), выбирая порты по имени в меню Packet Tracer; если порт занят, шаг падает
  со списком свободных портов;
- настраивает PC (`configure_pc` со `dhcp: true` или статикой) и проверяет `ping` по IP или имени (`cisco.srv`).

```yaml
- packet_tracer.open_project:    {file: input/Create_a_Simple_Network_pka.pka}   # .pka открывается в режиме Guest
- packet_tracer.add_device:      {model: PC, device: PC, near: Wireless Router}
- packet_tracer.add_device:      {model: Cable Modem, device: Cable Modem}
- packet_tracer.connect_devices: {a: "PC:FastEthernet0", b: "Wireless Router:Ethernet 1", cable: straight}
- packet_tracer.connect_devices: {a: "Cable Modem:Port 0", b: "Internet:Coaxial7", cable: coaxial}
- packet_tracer.configure_pc:    {device: PC, dhcp: true}
- packet_tracer.verify_connectivity: {source: PC, target: cisco.srv, min_received: 3}
```

Эти шаги двигают настоящую мышь: перед ними агент предупреждает, а ввод отправляется, только если окно Packet Tracer
на переднем плане (иначе шаг BLOCKED). Детерминированный планировщик сам такие шаги из текста лабы не составляет —
их планирует AI-провайдер (`--ai-provider codex`) или пишет человек. Не автоматизировано: замена модулей на вкладке
Physical и подключение к Wi-Fi через PC Wireless.

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
$env:LAB_AGENT_REAL_APPS = "1"; py -3.12 -m pytest -q -k real       # + настоящий TestDisk (и Codex при LAB_AGENT_REAL_CODEX=1)
```

Используйте Burp, браузер и сетевые инструменты только на локальных, намеренно уязвимых
или явно разрешённых учебных стендах.
