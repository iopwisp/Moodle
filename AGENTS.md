# AGENTS.md — инструкции для AI-агента (Codex и др.)

Этот файл читается агентом автоматически. Владелец — студент (Windows 11, Git Bash + PowerShell 7), отвечать ему
**по-русски**, коротко. Проект раньше вёл Claude Code; здесь собрано всё, что важно знать, чтобы продолжить.

## Что это за проект

**DoneAsik Lab Agent** — локальный агент для учебных лабораторных (кибербезопасность, форензика, сети).
Задание → анализ → план (только capabilities из реестра) → выполнение → проверка → evidence (SHA-256) → отчёт DOCX/PDF.
Подробно: `README.md`, `docs/architecture.md`, правила — `LAB_AGENT.md`, история — `SESSION_NOTES.md`,
что проверено вживую — `docs/verification_status.md`.

Рабочая ветка `feature/master-checklist`. Основная ветка — `main`.

## Команды

```powershell
py -3.12 -m pip install -e ".[all]"          # установка
py -3.12 -m lab_agent.cli doctor             # если lab-agent не в PATH
py -3.12 -m ruff check src tests
py -3.12 -m mypy
py -3.12 -m pytest -q -rs                    # все тесты (реальные программы не нужны)
$env:LAB_AGENT_REAL_APPS="1"; py -3.12 -m pytest -q -k real    # + настоящий TestDisk
py -3.12 -m lab_agent.cli build-report <report.md>           # отчёт DOCX+PDF из Markdown (формат — в README)
py -3.12 -m lab_agent.cli lint-report <report.md|.docx>      # проверка на «ИИ-стиль» и забытые TODO
```

Перед коммитом — ruff, mypy и pytest должны быть чистыми. Коммитить и пушить только по просьбе пользователя.

## Главные правила (обязательно)

1. **Никаких выдуманных результатов.** Шаг/ответ/скриншот считается сделанным, только если он реально получен.
   Не удалось — так и написать в отчёте с причиной. Пути пакетов, вывод команд, хеши — только наблюдённые.
2. **Оригиналы не трогать.** Работать с копиями в `workspace/` (папка в `.gitignore`).
3. **Отчётов два:** `<A>_Report.docx/.pdf` — обычная студенческая лабораторная (титульник, цель, ход работы
   связным текстом на языке задания, ответы, вывод, приложения), `<A>_Audit` — технический журнал.
   **Отчёт студента не должен выглядеть как сгенерированный ИИ или как лог** — пользователь на это жаловался.
   Перед сдачей прогонять `lab-agent lint-report` и переписывать найденное своими словами.
4. **Скриншоты — только реальные окна программ**, через `PrintWindow` (окно снимается, даже если перекрыто).
   Не подменять снимком рабочего стола и не рисовать «скриншоты» вручную.
5. **Перед шагами, которые нажимают клавиши в окнах** (Packet Tracer, Burp, HxD, Autopsy) — предупредить
   пользователя: «не трогайте мышь и клавиатуру». Консольная интеграция (`console`) фокус не забирает.
6. Сетевые/веб-инструменты — только на локальных или явно разрешённых учебных стендах.

## Данные для отчётов

ФИО и группа — в `config.yaml` (секция `report`, файл не в git). Группа `cs-2426` подтверждена пользователем.
Student ID оставлять пустым, если пользователь его не дал. Имя файла сдачи — как требует задание
(например `Surname_week2.docx`; в шапке report.md: `output: "{surname}_week2.docx"`).

## Как делались прошлые задания (рабочие приёмы)

- **Assignment 3 (форензика)** через агента: 18/18 шагов, Foremost/Scalpel/TSK в WSL + Autopsy 4.23.1.
  Потом переделан вручную в `C:\Users\iopwisp\Desktop\Assignment3_Konysbek` с настоящими GUI-скриншотами
  (агентская версия выглядела «как ИИ»). Генератор отчёта: `workspace/Assignment3_report/make_report.py`.
  Папку `Desktop\Assignment3` (собственная попытка пользователя) не трогать.
- **Assignment 4 (MBR/GPT, TestDisk)** — вручную в `workspace/Assignment4`, отчёт
  `scripts/make_report.py --pdf` там же.
- **Burp/PortSwigger** — агент запускает Burp и прокси, сами лабы решаются вручную, в отчёт прикладывается
  баннер "Solved": `lab-agent complete-step <ws> <шаг> --verification "..." --attach solved.png`.

Схема для ручного задания теперь такая: папка `workspace/<Задание>/`, скриншоты в `screenshots/`, данные в CSV,
текст отчёта — один `report.md` с YAML-шапкой → `lab-agent build-report report.md` (DOCX + PDF, нумерация рисунков и
таблиц, ФИО и группа из config.yaml). Отдельный `make_report.py` на каждое задание больше не нужен.

## Особенности инструментов на этой машине

- **Консольные программы без фокуса:** интеграция `console` (`src/lab_agent/integrations/console.py`,
  `src/lab_agent/tools/console.py`) — TestDisk/PhotoRec/шеллы в conhost, клавиши `{ENTER}` `{DOWN}` …, экран читается
  как текст, скриншот окна. Проверено на реальном TestDisk 7.2. `workspace/Assignment4/scripts/td.py` — её прототип.
- Если экран заблокирован (LockApp), перевод окна на передний план не работает — попросить разблокировать.
- Ctrl-сочетания требуют **английской раскладки** (переключать через `WM_INPUTLANGCHANGEREQUEST`).
- Autopsy DPI-aware, HxD — нет (учитывать масштаб при координатах).
- **TestDisk 7.2 / PhotoRec:** `C:\Tools\testdisk-7.2` (находятся автоматически). В манифесте requireAdministrator —
  интеграция `console` сама ставит `set __COMPAT_LAYER=RunAsInvoker` *внутри* запускаемого cmd.
- **HxD 2.5** portable: `C:\Tools\HxD`.
- **Autopsy 4.23.1 CLI не знает `--caseDir`.** Существующий кейс открывается через
  `--caseBaseDir=<родительская папка> --caseName=<имя>`, а `--runIngest` для него требует `--dataSourceObjectId=<id>`.
  Исправлено и проверено на настоящем Autopsy 2026-10-05; фейк в тестах принимает только опции из
  `tests/fixtures/autopsy_cli_4.23.1.json`. `--generateReports` требует профиль отчёта, один раз созданный в GUI
  (иначе шаг BLOCKED с инструкцией).
- **Cisco Packet Tracer 8.2.2:** `C:\Program Files\Cisco Packet Tracer 8.2.2\bin\PacketTracer.exe`.
  При запуске показывает окно входа Cisco («Cisco Packet Tracer Login») — войти должен сам пользователь.
  Окна устройств — отдельные top-level окна с именем устройства (вкладки CLI / Desktop → Command Prompt).
  Действия на холсте (кабели, устройства, удаление линка, кнопки Simulation) не имеют accessibility-контролов —
  делать по координатам со скриншотом-проверкой или просить пользователя.
  Профиль: `profiles/packet_tracer.yaml`. Файлы `.pka/.pkt` зашифрованы — читать их как текст нельзя.
  В PT есть IPC API (`help/default/IpcAPI`, класс `Simulation`: `setSimulationMode`, `forward`,
  `getFrameInstanceAt`) — путь к автоматизации симуляции через Script Module или ExApp (PTMP, TCP 39000); не сделано.
- **Burp Community 2026.8:** горячие клавиши работают только когда окно Burp в фокусе.

## AI-планировщик агента

`lab-agent` планирует через `OPENAI_API_KEY`, Ollama или **`--ai-provider codex`** — Codex CLI (`codex exec`) на
подписке ChatGPT, без API-ключа (проверено: план за ~50 с). Без них — детерминированный планировщик (работает нормально).

## Открытые задачи

- **Packet Tracer 9.2.4 «Identify Packet Flow»** (Network Security, Module 9). Лист задания:
  `C:\Users\iopwisp\Downloads\week 2 assignment 2 (1).pdf`. Нужны ещё `9.2.4-identify-packet-flow.pka` и
  PDF-инструкция Cisco с netacad.com — пользователь скачивает сам. Сдать `Surname_week2.docx`: 7 вопросов
  инструкции + дополнительный вопрос (в листе его нет — спросить у пользователя), для Part 2 и Part 3 Step 1 —
  прогноз DNS-пути, наблюдаемый HTTP-путь и путь после удаления линка (**каждый путь полностью**:
  `PC0 > Router1 > Switch2 > Server`), таблица tracert (строки 1–5; 6–7 уже даны) + сравнение с симуляцией,
  скриншоты окна Simulation для трёх вопросов об изменении пути. Теория — разделы 9.2.1 и 9.2.2.
- Коммит `41cd3c6 asd` уже в `origin/main` — не переписывать. В git `user.email` стоит заглушка `твоя@почта.com`:
  коммиты не привязываются к GitHub-аккаунту — пусть пользователь поставит свой адрес.
- В `workspace/` лежат старые неудачные прогоны `Assignment_3_20260930T11…` — удалять только с согласия пользователя.
