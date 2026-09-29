# DoneAsik Lab Agent

Локальный агент для учебных лабораторных заданий. Он принимает папку или набор файлов с заданием и evidence, создаёт изолированный workspace, строит план, выполняет доступные шаги, сохраняет скриншоты и формирует DOCX/PDF отчёт.

Исходные файлы не изменяются. В `metadata/input_manifest.json` для каждого оригинала сохраняются путь и SHA-256, а агент использует копию из `input/`.

## Установка

```powershell
py -3.12 -m pip install -e ".[all]"
```

Если папка Python Scripts не добавлена в `PATH`, заменяйте `lab-agent` в примерах на `py -3.12 -m lab_agent.cli`.

Для браузерных лабораторных дополнительно установите Chromium для Playwright:

```powershell
py -3.12 -m playwright install chromium
```

## Один запуск

```powershell
lab-agent run "C:\Assignments\Assignment_3" --workspace-root .\workspace --ai-provider auto
```

Команда автоматически выбирает AI-планировщик:

| Условие | Планировщик |
| --- | --- |
| `OPENAI_API_KEY` задан | OpenAI Responses API |
| есть `OLLAMA_HOST` | локальный Ollama |
| ни один не настроен | прозрачный детерминированный fallback |

Для OpenAI можно указать модель явно:

```powershell
$env:OPENAI_API_KEY = "..."
lab-agent run "C:\Assignments\Assignment_3" --ai-provider openai --model gpt-6-astra
```

AI получает содержимое задания и возвращает строгий JSON-план. Исполнитель принимает только ограниченные действия: хеширование входных данных, браузер, операции из desktop-профиля, снимок экрана и зафиксированная ручная проверка. Он не выполняет сгенерированные моделью PowerShell-команды и не использует произвольные координаты мыши.

После запуска находятся:

```text
workspace/<assignment>/
├── screenshots/                 # снимки до и после шагов
├── evidence/registry.json       # относительные пути и SHA-256
├── results/                     # хеши и результаты браузера
├── state/agent.db               # SQLite: шаги, evidence и события
├── state/state.json             # переносимый checkpoint
├── execution_summary.json
└── reports/
    ├── <assignment>_Report.docx
    └── <assignment>_Report.pdf
```

`resume` повторно проверяет evidence и затем исполняет только незавершённые либо неуспешные этапы:

```powershell
lab-agent resume .\workspace\Assignment_3
lab-agent resume .\workspace\Assignment_3 --verify-only
```

## Web panel

```powershell
lab-agent serve --workspace-root .\workspace
```

Откройте `http://127.0.0.1:8765`. Страница принимает несколько файлов, запускает обработку, показывает статусы задач, SQLite-события, скриншоты и ссылки на готовые отчёты. API включает загрузку, запуск, resume, stop, задачи, evidence, логи и отчёты.

## Autopsy and Burp

Desktop-профили запускают приложение, ждут окно через Windows UI Automation, выполняют только действия, описанные в YAML-профиле, и сохраняют скриншот результата. Укажите реальные пути до приложений перед запуском:

```powershell
$env:LAB_AGENT_AUTOPSY_PATH = "C:\Program Files\Autopsy\bin\autopsy64.exe"
$env:LAB_AGENT_BURP_PATH = "C:\Program Files\BurpSuiteCommunity\BurpSuiteCommunity.exe"
```

В `profiles/autopsy.yaml` и `profiles/burp.yaml` находятся разрешённые операции и селекторы. Для другой версии приложения добавьте её проверенные UIA-селекторы туда; агент не будет угадывать координаты и нажимать неизвестные кнопки.

Playwright запускает браузер только для `localhost`, `127.0.0.1` или хостов, явно добавленных в задание/команду:

```powershell
lab-agent run "C:\Assignments\web-lab" --allowed-target lab.example.edu
```

Используйте Burp и браузер только для локальных или явно разрешённых учебных стендов.

## Проверка

```powershell
py -3.12 -m ruff check src tests
py -3.12 -m pytest -q
```

Набор тестов включает полный E2E путь: входное задание → план → выполнение → скриншоты → evidence → DOCX/PDF отчёты.


## Архитектура интеграций

Исполнитель работает через реестр capabilities, а не через ветвления «если Autopsy — сделай X, если Burp — сделай Y».

Текущие capabilities:

| Capability | Назначение |
| --- | --- |
| \`core.hash_inputs\` | Хеширование входных evidence |
| \`core.screenshot\` | Снимок интерактивного рабочего стола |
| \`core.manual_review\` | Безопасная остановка на ручную проверку |
| \`browser.visit\` | Авторизованный web-lab через Playwright |
| \`desktop.profile\` | Любая операция из YAML-профиля Windows UI Automation |
| \`autopsy.e2e\` | Полный сценарий Autopsy для forensic image |

AI-планировщик получает этот каталог и выбирает capability по имени. Runner вызывает реестр, получает единый результат \`verified/evidence/details\`, проверяет обязательное evidence и только после этого отмечает шаг выполненным.

### Добавление нового приложения

Для обычного Windows приложения достаточно добавить \`profiles/<app>.yaml\`. Capability \`desktop.profile\` автоматически использует executable environment variable, regex окна и разрешённые UIA-операции из профиля. Core runner при этом менять не нужно.

Для сложного приложения создаётся отдельный адаптер в \`src/lab_agent/integrations/\`, который публикует свои capabilities, например:

\`\`\`text
packet_tracer.create_topology
packet_tracer.configure_router
packet_tracer.configure_switch
packet_tracer.verify_connectivity
\`\`\`

Внешние Python-пакеты могут подключать такие адаптеры через entry point group \`doneasik_lab_agent.integrations\`. Поэтому добавление Packet Tracer, Overleaf, Wireshark или другого инструмента не требует переписывать planner, runner, evidence или reports.

### Контракт capability

Каждая интеграция публикует:
1. уникальное имя capability;
2. описание для AI-планировщика;
3. список параметров;
4. типы допустимого evidence;
5. метод исполнения, возвращающий \`verified\`, детали и evidence.

Это позволяет постепенно добавлять новые технологии без разрастания центрального runner.
