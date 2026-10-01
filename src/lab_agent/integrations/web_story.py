"""How browser and Burp Suite steps read in the student report (see :mod:`lab_agent.narrative`)."""

from __future__ import annotations

from typing import Any

from .base import Narrative, StepFacts


def _status_ru(status: Any) -> str:
    try:
        code = int(status)
    except (TypeError, ValueError):
        return "ответ не получен"
    meaning = {200: "OK", 201: "Created", 204: "No Content", 301: "Moved Permanently", 302: "Found", 303: "See Other",
               304: "Not Modified", 400: "Bad Request", 401: "Unauthorized", 403: "Forbidden", 404: "Not Found",
               405: "Method Not Allowed", 500: "Internal Server Error"}.get(code, "")
    return f"{code} {meaning}".strip()


class BrowserNarration:
    def narrate_launch(self, facts: StepFacts, language: str) -> Narrative:
        proxy = facts.details.get("proxy") or facts.parameters.get("proxy")
        if language == "ru":
            text = "Запустили браузер Chromium" + (f", весь трафик которого шёл через прокси {proxy}." if proxy else ".")
            return Narrative("Запуск браузера", [text])
        return Narrative("Browser", ["Chromium was started" + (f" with all traffic sent through the proxy {proxy}." if proxy else ".")])

    def narrate_navigate(self, facts: StepFacts, language: str) -> Narrative:
        d = facts.details
        url = d.get("url") or facts.parameters.get("url")
        title = d.get("title") or ""
        if language == "ru":
            text = f"Открыли страницу {url}"
            text += f" («{title}»)" if title else ""
            text += f", сервер ответил {_status_ru(d.get('status'))}." if facts.completed else "."
            return Narrative(f"Открытие {url}", [text], figure_caption=f"Страница {title or url}")
        text = f"The page {url}" + (f" (“{title}”)" if title else "") + (f" was opened; the server answered {d.get('status')}."
                                                                        if facts.completed else " was requested.")
        return Narrative(f"Opening {url}", [text], figure_caption=f"The page {title or url}")

    narrate_visit = narrate_navigate

    def narrate_click(self, facts: StepFacts, language: str) -> Narrative:
        selector = facts.parameters.get("selector")
        if language == "ru":
            return Narrative("Действие на странице", [f"Нажали на элемент {selector}; после этого открылась {facts.details.get('url', 'страница')}."])
        return Narrative("Page action", [f"The element {selector} was clicked; the browser then showed {facts.details.get('url', 'the page')}."])

    def narrate_type(self, facts: StepFacts, language: str) -> Narrative:
        selector = facts.parameters.get("selector")
        secret = facts.details.get("secret") or facts.parameters.get("secret_env")
        value = "" if secret else str(facts.parameters.get("text", ""))
        if language == "ru":
            what = "пароль (значение не приводится)" if secret else f"значение «{value}»"
            return Narrative("Ввод данных", [f"В поле {selector} ввели {what}."])
        what = "the password (value not shown)" if secret else f"“{value}”"
        return Narrative("Input", [f"{what} was entered into {selector}."])

    def narrate_inspect(self, facts: StepFacts, language: str) -> Narrative:
        d = facts.details
        expected = facts.parameters.get("expected_text")
        if language == "ru":
            text = f"Проверили содержимое страницы {d.get('url', '')}"
            if expected:
                text += f": текст «{expected}» " + ("на странице есть." if d.get("expected_text_found") else "не найден.")
            else:
                text += "."
            return Narrative("Проверка страницы", [text])
        text = f"The page {d.get('url', '')} was checked" + (f": “{expected}” is " + ("present." if d.get("expected_text_found") else "absent.")
                                                             if expected else ".")
        return Narrative("Page check", [text])

    def narrate_read_text(self, facts: StepFacts, language: str) -> Narrative:
        text = str(facts.details.get("text", ""))[:400]
        if language == "ru":
            return Narrative("Чтение данных со страницы", [f"Со страницы считали текст элемента {facts.parameters.get('selector')}: «{text}»."])
        return Narrative("Reading the page", [f"The text of {facts.parameters.get('selector')} reads: “{text}”."])

    def narrate_screenshot(self, facts: StepFacts, language: str) -> Narrative:
        if language == "ru":
            return Narrative("Снимок страницы", [f"Сделали снимок страницы {facts.details.get('url', '')}."], figure_caption="Снимок страницы")
        return Narrative("Page screenshot", [f"A screenshot of {facts.details.get('url', '')} was taken."], figure_caption="Page screenshot")

    def narrate_download(self, facts: StepFacts, language: str) -> Narrative:
        d = facts.details
        if language == "ru":
            return Narrative("Загрузка файла", [f"Скачали файл {d.get('file')} ({d.get('size')} байт)."])
        return Narrative("Download", [f"The file {d.get('file')} ({d.get('size')} bytes) was downloaded."])


class BurpNarration:
    def narrate_launch(self, facts: StepFacts, language: str) -> Narrative:
        port = facts.details.get("port") or facts.parameters.get("port") or 8080
        if language == "ru":
            return Narrative("Запуск Burp Suite", [
                ("Запустили Burp Suite Community Edition с временным проектом (Temporary project) и настройками по "
                f"умолчанию. После запуска прокси-слушатель Burp поднялся на 127.0.0.1:{port}.")],
                figure_caption="Главное окно Burp Suite")
        return Narrative("Starting Burp Suite", [(f"Burp Suite Community was started with a temporary project and default settings; "
                                                 f"its proxy listener came up on 127.0.0.1:{port}.")],
                         figure_caption="Burp Suite main window")

    def narrate_configure_proxy(self, facts: StepFacts, language: str) -> Narrative:
        port = facts.details.get("port") or facts.parameters.get("port") or 8080
        if language == "ru":
            return Narrative("Настройка прокси", [
                (f"Прокси-слушатель Burp (Proxy → Proxy settings) работает на 127.0.0.1:{port}. Проверили, что порт принимает "
                "соединения, а чтобы убедиться, что на нём действительно Burp, через прокси открыли служебный адрес "
                "http://burp/ — ответила страница Burp Suite.")],
                finding=f"Прокси Burp Suite работает на 127.0.0.1:{port} и перехватывает трафик браузера.")
        return Narrative("Proxy configuration", [
            (f"The proxy listener is active on 127.0.0.1:{port}; opening http://burp/ through it returns Burp's own page, "
            "so the port really belongs to Burp.")],
            finding=f"The Burp proxy is listening on 127.0.0.1:{port}.")

    narrate_wait_for_proxy = narrate_configure_proxy

    def narrate_open_target(self, facts: StepFacts, language: str) -> Narrative:
        d = facts.details
        url, title = d.get("url") or facts.parameters.get("url"), d.get("title") or ""
        if language == "ru":
            return Narrative(f"Открытие {url} через Burp", [
                f"Браузер настроили на прокси Burp и открыли {url}" + (f" («{title}»)" if title else "")
                + (f". Страница загрузилась ({_status_ru(d.get('status'))}); так как браузер работал через прокси, все его "
                   "запросы прошли через Burp и попадают в Proxy → HTTP history."
                   if facts.completed else ".")],
                figure_caption=f"Страница {title or url}, открытая через Burp")
        return Narrative(f"Opening {url} through Burp", [
            f"The browser was pointed at the Burp proxy and opened {url}" + (f" (“{title}”)" if title else "")
            + (f"; the page loaded ({d.get('status')}) and, as all browser traffic went through the proxy, its requests are "
               "listed in Proxy → HTTP history." if facts.completed else ".")],
            figure_caption=f"{title or url} through Burp")

    def narrate_send_request(self, facts: StepFacts, language: str) -> Narrative:
        d, p = facts.details, facts.parameters
        method, url = p.get("method", "GET"), d.get("url") or p.get("url")
        if language == "ru":
            return Narrative(f"Запрос {method} {url}", [
                (f"Через прокси Burp отправили запрос {method} {url}; сервер ответил {_status_ru(d.get('status'))}. "
                "Ответ сохранён для дальнейшего анализа.")])
        return Narrative(f"{method} {url}", [f"A {method} request to {url} was sent through Burp; the server answered {d.get('status')}."])

    def narrate_intercept_request(self, facts: StepFacts, language: str) -> Narrative:
        url = facts.details.get("url") or facts.parameters.get("url")
        hold = facts.parameters.get("hold_seconds", 4)
        if language == "ru":
            text = (f"Во вкладке Proxy → Intercept включили перехват (Intercept is on) и отправили запрос к {url}. "
                    f"Запрос остановился в Burp: спустя {hold} с ответа всё ещё не было — Burp держал его и ждал решения "
                    "(Forward или Drop).")
            return Narrative("Перехват запроса", [text] if facts.completed else [text.split(". ")[0] + "."],
                             figure_caption="Перехваченный запрос во вкладке Proxy → Intercept",
                             finding="Burp перехватывает запросы: при включённом Intercept запрос не уходит на сервер, "
                                     "пока его не отпустят вручную.")
        return Narrative("Intercepting a request", [
            (f"Intercept was switched on in Proxy → Intercept and a request to {url} was sent. Burp held it: after {hold} s "
            "there was still no response and the request was shown in the Intercept tab.")],
            figure_caption="The held request in Proxy → Intercept",
            finding="With Intercept on, Burp holds requests until they are forwarded.")

    def narrate_forward_request(self, facts: StepFacts, language: str) -> Narrative:
        status = facts.details.get("status")
        if language == "ru":
            return Narrative("Пропуск запроса (Forward)", [
                "Нажали Forward (Ctrl+F), и Burp отпустил задержанный запрос на сервер"
                + (f": ответ {_status_ru(status)} пришёл в браузер." if facts.completed else ".")])
        return Narrative("Forwarding the request", ["Forward released the held request" + (f"; the response {status} arrived."
                                                                                          if facts.completed else ".")])

    def narrate_send_to_repeater(self, facts: StepFacts, language: str) -> Narrative:
        if language == "ru":
            return Narrative("Работа с Repeater", [
                "Запрос отправили в Repeater (Ctrl+R) и открыли эту вкладку: здесь запрос можно менять и повторять вручную."],
                figure_caption="Запрос во вкладке Repeater")
        return Narrative("Repeater", ["The request was sent to Repeater (Ctrl+R), where it can be edited and resent."],
                         figure_caption="The request in Repeater")

    def narrate_inspect_response(self, facts: StepFacts, language: str) -> Narrative:
        d, p = facts.details, facts.parameters
        expected = p.get("expected_text")
        if language == "ru":
            text = f"Изучили ответ сервера: код {_status_ru(d.get('status'))}"
            text += f", в теле ответа есть «{expected}»." if expected and facts.completed else "."
            return Narrative("Анализ ответа сервера", [text])
        return Narrative("Response analysis", [f"The response has status {d.get('status')}" + (f" and contains “{expected}”." if expected else ".")])

    def narrate_capture_evidence(self, facts: StepFacts, language: str) -> Narrative:
        if language == "ru":
            return Narrative("Снимок окна Burp Suite", ["Текущее состояние Burp Suite показано на рисунке."],
                             figure_caption="Окно Burp Suite")
        return Narrative("Burp Suite window", ["The current state of Burp Suite is shown in the figure."], figure_caption="Burp Suite")
