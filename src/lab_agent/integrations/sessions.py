"""Shared Playwright browser session used by the browser, Burp and Overleaf integrations.

The session stays open across steps of one run (same thread), so multi-step
web workflows keep cookies and page state.  Every top-level navigation -
including redirects and links clicked by the page - is checked against the
authorized scope; out-of-scope navigations are aborted.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any
from urllib.parse import urljoin, urlparse

from .base import CapabilityBlocked


class BrowserSession:
    def __init__(self, url_allowed: Callable[[str], bool], *, headless: bool = False, proxy: str | None = None,
                 timeout_seconds: float = 45, viewport: tuple[int, int] = (1440, 1000),
                 allow_external_subresources: bool = True) -> None:
        self.url_allowed = url_allowed
        self.allow_external_subresources = allow_external_subresources
        self.headless = headless
        self.proxy = proxy
        self.timeout_ms = int(timeout_seconds * 1000)
        self.viewport = viewport
        self._playwright: Any = None
        self._browser: Any = None
        self.context: Any = None
        self.page: Any = None
        self.last_status: int | None = None
        self.blocked_navigations: list[str] = []

    @property
    def active(self) -> bool:
        return self.page is not None

    def start(self) -> None:
        if self.active:
            return
        try:
            from playwright.sync_api import sync_playwright
        except ImportError as exc:
            raise CapabilityBlocked("Browser automation requires: pip install -e .[browser] && python -m playwright install chromium") from exc
        self._playwright = sync_playwright().start()
        launch: dict[str, Any] = {"headless": self.headless}
        if self.proxy:
            launch["proxy"] = {"server": self.proxy}
            # Chromium sends localhost straight to the server even with a proxy set; lab targets (DVWA, Juice
            # Shop) usually live on localhost, so loopback must go through Burp too.
            launch["args"] = ["--proxy-bypass-list=<-loopback>"]
        try:
            self._browser = self._playwright.chromium.launch(**launch)
        except Exception as exc:
            self._playwright.stop()
            self._playwright = None
            raise CapabilityBlocked(f"Chromium could not start ({exc}); run: python -m playwright install chromium") from exc
        self.context = self._browser.new_context(
            viewport={"width": self.viewport[0], "height": self.viewport[1]},
            accept_downloads=True, ignore_https_errors=bool(self.proxy),
        )
        self.context.set_default_timeout(self.timeout_ms)
        self.context.route("**/*", self._guard)
        self.page = self.context.new_page()

    def _guard(self, route: Any, request: Any) -> None:
        """Scope guard for every request of the session.

        * navigations to unauthorized hosts are aborted;
        * navigations are fetched *without* following redirects so a redirect
          to an unauthorized host is caught (the browser would otherwise follow
          it inside the network stack, bypassing the route handler);
        * state-changing requests (POST/PUT/...) to unauthorized hosts are aborted;
        * passive sub-resources (GET images/scripts/styles) may load unless
          ``allow_external_subresources`` is False.
        """
        allowed = self.url_allowed(request.url)
        if request.is_navigation_request():
            if not allowed:
                self.blocked_navigations.append(request.url)
                route.abort("blockedbyclient")
                return
            response = route.fetch(max_redirects=0)
            location = response.headers.get("location")
            if 300 <= response.status < 400 and location:
                target = urljoin(request.url, location)
                if not self.url_allowed(target):
                    self.blocked_navigations.append(target)
                    route.fulfill(status=403, content_type="text/plain",
                                  body=f"lab-agent blocked a redirect to an unauthorized host: {target}")
                    return
            route.fulfill(response=response)
            return
        if not allowed and (request.method != "GET" or not self.allow_external_subresources):
            route.abort("blockedbyclient")
            return
        route.continue_()

    def goto(self, url: str) -> int | None:
        if not self.url_allowed(url):
            raise PermissionError(f"Browser target {url} is outside the authorized scope.")
        self.start()
        response = self.page.goto(url, wait_until="load", timeout=self.timeout_ms)
        try:
            self.page.wait_for_load_state("networkidle", timeout=min(self.timeout_ms, 10_000))
        except Exception:  # noqa: BLE001, S110 - busy pages never go idle; load already happened
            pass
        self.last_status = response.status if response else None
        return self.last_status

    def require_page(self) -> Any:
        if not self.active:
            raise RuntimeError("No page is open; navigate first.")
        host = urlparse(self.page.url).hostname
        if host and not self.url_allowed(self.page.url):
            raise PermissionError(f"Current page {self.page.url} is outside the authorized scope.")
        return self.page

    def close(self) -> None:
        for closer in (self.context, self._browser):
            try:
                if closer is not None:
                    closer.close()
            except Exception:  # noqa: BLE001, S110
                pass
        if self._playwright is not None:
            try:
                self._playwright.stop()
            except Exception:  # noqa: BLE001, S110
                pass
        self._playwright = self._browser = self.context = self.page = None
