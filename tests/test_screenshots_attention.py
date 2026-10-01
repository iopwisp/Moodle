from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
from PIL import Image

from lab_agent.tools import screenshot as shots


def test_requested_window_is_never_replaced_by_the_desktop(tmp_path: Path, monkeypatch) -> None:
    desktop_grabs: list[Any] = []
    monkeypatch.setattr(shots, "find_window", lambda title_re, timeout=5.0: None)
    monkeypatch.setattr(shots, "_grab", lambda bbox: desktop_grabs.append(bbox) or Image.new("RGB", (40, 30)))
    monkeypatch.setattr(shots.time, "sleep", lambda s: None)
    with pytest.raises(shots.ScreenshotUnavailable):
        shots.take_screenshot(tmp_path, name="w.png", window_title_re="Burp Suite")
    assert desktop_grabs == []
    # the old behaviour is still available explicitly, and a plain desktop capture still works
    assert shots.take_screenshot(tmp_path, name="d.png", window_title_re="Burp Suite", require_window=False).is_file()
    assert shots.take_screenshot(tmp_path, name="full.png").is_file()


def test_covered_window_uses_its_own_pixels(tmp_path: Path, monkeypatch) -> None:
    class Window:
        handle = 42

        def is_minimized(self) -> bool:
            return False

    monkeypatch.setattr(shots, "find_window", lambda title_re, timeout=5.0: Window())
    monkeypatch.setattr(shots, "capture_window", lambda handle: Image.new("RGB", (64, 48), (200, 10, 10)))
    monkeypatch.setattr(shots, "_grab", lambda bbox: pytest.fail("a screen grab would show what covers the window"))
    path = shots.take_screenshot(tmp_path, name="w.png", window_title_re="Burp Suite")
    with Image.open(path) as image:
        assert image.size == (64, 48) and image.getpixel((1, 1)) == (200, 10, 10)


def test_background_window_without_own_rendering_is_refused(tmp_path: Path, monkeypatch) -> None:
    class Window:
        handle = 42

        def is_minimized(self) -> bool:
            return False

    monkeypatch.setattr(shots, "find_window", lambda title_re, timeout=5.0: Window())
    monkeypatch.setattr(shots, "capture_window", lambda handle: None)
    monkeypatch.setattr(shots, "find_window_rect", lambda title_re, **k: (0, 0, 100, 100))
    monkeypatch.setattr(shots, "_is_foreground", lambda handle: False)
    monkeypatch.setattr(shots, "_grab", lambda bbox: pytest.fail("not in front: the rectangle shows another window"))
    monkeypatch.setattr(shots.time, "sleep", lambda s: None)
    with pytest.raises(shots.ScreenshotUnavailable):
        shots.take_screenshot(tmp_path, name="w.png", window_title_re="Burp Suite")


def test_interactive_capabilities_are_declared_and_real(registry) -> None:
    names = {c.name for c in registry.capabilities()}
    interactive = {c.name for c in registry.capabilities() if c.interactive}
    for adapter in registry.adapters():
        assert set(getattr(adapter, "INTERACTIVE", ())) <= names, adapter.name
    assert {"burp.launch", "burp.intercept_request", "burp.forward_request", "burp.send_to_repeater"} <= interactive
    assert not any(name.startswith(("browser.", "forensics.", "core.")) for name in interactive)
