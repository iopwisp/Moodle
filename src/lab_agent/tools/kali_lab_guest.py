"""Fixed educational jobs executed in Kali by the existing SSH terminal bridge.

Only the standard library is imported until the DVWA job requests Selenium.
There is no installation, sudo, screenshot generation or database reset here.
"""

from __future__ import annotations

import base64
import gzip
import hashlib
import importlib.util
import ipaddress
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

MARKER = "DONEASIK_LAB_RESULT="


def local_url(value: str) -> str:
    parsed = urlsplit(value)
    try:
        local = ipaddress.ip_address(parsed.hostname or "").is_loopback
        port = parsed.port
    except ValueError:
        local = False
        port = None
    if (not local or parsed.scheme != "http" or parsed.username is not None
            or parsed.password is not None or parsed.query or parsed.fragment
            or (port is not None and not 1 <= port <= 65535)
            or any(c in value for c in "\r\n\x00\\")):
        raise ValueError("Use an HTTP URL with a literal guest loopback IP and no credentials/query.")
    return value.rstrip("/") + "/"


def command(argv: list[str], timeout: int, cwd: Path) -> dict[str, Any]:
    env = dict(os.environ, LC_ALL="C.UTF-8")
    try:
        r = subprocess.run(argv, cwd=cwd, stdin=subprocess.DEVNULL, capture_output=True,
                           text=True, errors="replace", timeout=timeout, env=env, check=False)
        return {"argv": argv, "exit_code": r.returncode,
                "output": r.stdout + r.stderr, "timed_out": False}
    except subprocess.TimeoutExpired as exc:
        output = (exc.stdout or b"") + (exc.stderr or b"")
        return {"argv": argv, "exit_code": None, "output": output.decode(errors="replace"),
                "timed_out": True}


def preflight(job: dict[str, Any], directory: Path) -> dict[str, Any]:
    tools = {name: shutil.which(name) for name in (
        "nikto", "john", "hashcat", "rtgen", "rtsort", "rcrack", "gvm-start", "gvmd",
        "gsad", "ospd-openvas", "zaproxy", "chromium", "chromedriver")}
    plugin_dir = Path("/var/lib/openvas/plugins")
    try:
        plugins: int | None = sum(1 for p in plugin_dir.glob("*.nasl") if p.is_file())
        if not plugin_dir.is_dir():
            plugins = None
    except OSError:
        plugins = None
    backend = (command([tools["hashcat"], "-I"], 20, directory)
               if tools["hashcat"] else None)
    missing = [name for name, path in tools.items() if not path]
    # This capability verifies an inventory, not that all labs are ready.
    return {"status": "completed", "summary": "Kali prerequisites inspected; see readiness fields.",
            "tools": tools, "selenium": importlib.util.find_spec("selenium") is not None,
            "openvas_nasl_files": plugins, "hashcat_backend": backend,
            "missing_tools": missing,
            "ready": {"nikto": bool(tools["nikto"]),
                      "john": bool(tools["john"]),
                      "gvm_components_and_feed": bool(plugins and all(
                          tools[k] for k in ("gvmd", "gsad", "ospd-openvas")))}}


def nikto(job: dict[str, Any], directory: Path) -> dict[str, Any]:
    url = local_url(job["url"])
    exe = shutil.which("nikto")
    if not exe:
        return {"status": "blocked", "summary": "Nikto is not installed in Kali."}
    argv = [exe, "-h", url, "-nointeractive", "-nocheck", "-ask", "no", "-nolookup",
            "-maxtime", str(job["seconds"]), "-timeout", "3", "-output", "scan.csv",
            "-Format", "csv"]
    if job.get("sql_only"):
        argv += ["-Tuning", "9"]
    result = command(argv, job["seconds"] + 30, directory)
    output = result["output"]
    # Some releases append an extension even if one was provided.
    exports = sorted(directory.glob("scan.csv*"))
    csv = next((p.read_text(errors="replace") for p in exports if p.is_file()), "")
    partial = bool(result["timed_out"] or result["exit_code"] != 0 or not csv
                   or "maximum execution time" in output.lower()
                   or "scan terminated" in output.lower()
                   or re.search(r"\b[1-9]\d* errors?\b", output, re.IGNORECASE))
    return {"status": "partial" if partial else "completed", "command": result,
            "summary": ("Scan incomplete or reported errors; do not treat as a full assessment."
                        if partial else "Nikto finished; findings still require manual validation."),
            "files": {"nikto.txt": output, **({"nikto.csv": csv} if csv else {})}}


def passwords(job: dict[str, Any], directory: Path) -> dict[str, Any]:
    engine = job["engine"]
    if engine not in {"john", "hashcat"}:
        raise ValueError("engine must be john or hashcat")
    exe = shutil.which(engine)
    if not exe:
        return {"status": "blocked", "summary": f"{engine} is not installed in Kali."}
    text = base64.b64decode(job["hashes_b64"], validate=True).decode("utf-8-sig")
    hashes = []
    for line in text.splitlines():
        if not re.fullmatch(r"(?:[A-Za-z0-9_.-]+:)?[0-9a-fA-F]{32}", line):
            raise ValueError("Expected raw MD5 or username:MD5, one entry per line.")
        hashes.append(line.rsplit(":", 1)[-1].lower())
    if not hashes:
        raise ValueError("The hash file is empty.")
    source = directory / "hashes.txt"
    source.write_text("\n".join(hashes) + "\n")
    wordlist = Path(job["wordlist"])
    if not wordlist.is_absolute() or not wordlist.is_file():
        return {"status": "blocked", "summary": "The absolute guest wordlist path does not exist."}
    if wordlist.suffix == ".gz":
        unpacked = directory / "wordlist.txt"
        with gzip.open(wordlist, "rb") as reader, unpacked.open("wb") as writer:
            shutil.copyfileobj(reader, writer)
        wordlist = unpacked
    if engine == "john":
        argv = [exe, "--format=raw-md5", "--pot=" + str(directory / "john.pot"),
                "--wordlist=" + str(wordlist), str(source)]
        show = [exe, "--show", "--format=raw-md5", "--pot=" + str(directory / "john.pot"), str(source)]
    else:
        argv = [exe, "-m", "0", "-a", "0", "--potfile-path", str(directory / "hashcat.pot"),
                str(source), str(wordlist)]
        show = [exe, "--show", "-m", "0", "--potfile-path", str(directory / "hashcat.pot"), str(source)]
    try:
        ran = command(argv, job["seconds"], directory)
        shown = command(show, 20, directory)
    finally:
        # The installed compressed dictionary is original input; the large disposable
        # expansion is not evidence and need not accumulate once a job has finished.
        if wordlist == directory / "wordlist.txt":
            wordlist.unlink(missing_ok=True)
    # Verify each recovered candidate against the supplied digest, including duplicates.
    recovered = {}
    for line in shown["output"].splitlines():
        _, sep, candidate = line.partition(":")
        if sep:
            digest = hashlib.md5(candidate.encode()).hexdigest()
            if digest in hashes:
                recovered[digest] = candidate
    count = sum(digest in recovered for digest in hashes)
    complete = count == len(hashes) and not ran["timed_out"] and shown["exit_code"] == 0
    blocked = any(t in ran["output"].lower() for t in (
        "no opencl", "cl_platform_not_found", "no devices found", "no compatible platform"))
    return {"status": "completed" if complete else "blocked" if blocked else "partial",
            "summary": f"{engine}: recovered {count}/{len(hashes)} MD5 entries.",
            "engine": engine, "recovered_count": count, "total": len(hashes),
            "recovered": recovered, "command": ran, "show": shown,
            "files": {"passwords.txt": ran["output"] + "\n" + shown["output"]}}


def dvwa(job: dict[str, Any], directory: Path) -> dict[str, Any]:
    base = local_url(job["url"])
    if job["case"] not in {"sql", "reflected_xss"} or job["level"] not in {"low", "medium", "high"}:
        raise ValueError("Unsupported DVWA case/security level")
    try:
        from selenium import webdriver
        from selenium.common.exceptions import NoAlertPresentException, TimeoutException
        from selenium.webdriver.chrome.service import Service
        from selenium.webdriver.common.by import By
        from selenium.webdriver.support.ui import Select
        from selenium.webdriver.support.wait import WebDriverWait
    except ImportError:
        return {"status": "blocked", "summary": "Install Selenium in Kali before this job."}
    browser, driver = shutil.which("chromium"), shutil.which("chromedriver")
    if not browser or not driver:
        return {"status": "blocked", "summary": "Chromium and chromedriver are required in Kali."}
    options = webdriver.ChromeOptions()
    options.binary_location = browser
    options.add_argument("--disable-dev-shm-usage")
    options.add_argument("--window-size=1200,800")
    # Every browser network request is restricted to this numeric loopback origin.
    options.add_argument("--proxy-server=http://127.0.0.1:9")
    options.add_argument("--proxy-bypass-list=" + str(urlsplit(base).hostname))
    options.add_argument("--disable-background-networking")
    options.set_capability("unhandledPromptBehavior", "ignore")
    d = webdriver.Chrome(service=Service(driver), options=options)
    d.set_page_load_timeout(20)
    try:
        def navigate(path: str) -> None:
            d.get(base + path)
            actual, expected = urlsplit(d.current_url), urlsplit(base)
            if (actual.scheme, actual.netloc) != (expected.scheme, expected.netloc):
                raise ValueError("DVWA navigated outside the configured origin.")

        navigate("login.php")
        if "DVWA" not in d.title:
            return {"status": "blocked", "summary": "The URL did not show the DVWA login page."}
        d.find_element(By.NAME, "username").send_keys("admin")
        d.find_element(By.NAME, "password").send_keys("password")
        d.find_element(By.NAME, "Login").click()
        navigate("security.php")
        Select(d.find_element(By.NAME, "security")).select_by_value(job["level"])
        d.find_element(By.NAME, "seclev_submit").click()
        WebDriverWait(d, 5).until(lambda w: Select(w.find_element(
            By.NAME, "security")).first_selected_option.get_attribute("value") == job["level"])
        if job["case"] == "sql":
            navigate("vulnerabilities/sqli/")
            d.find_element(By.NAME, "id").send_keys("' OR 1=1 #")
            d.find_element(By.CSS_SELECTOR, "input[type=submit]").click()
            text = d.find_element(By.TAG_NAME, "body").text
            records = re.findall(r"First name: ([^\n]+)\nSurname: ([^\n]+)", text)
            return {"status": "completed" if len(records) > 1 else "partial", "records": records,
                    "summary": f"DVWA SQL test returned {len(records)} records.",
                    "files": {"dvwa.txt": text}}
        navigate("vulnerabilities/xss_r/")
        payloads = {"low": '<script>alert("DoneAsik_XSS_test")</script>',
                    "medium": '<ScRipt>alert("DoneAsik_XSS_test")</ScRipt>',
                    "high": '<img src=x onerror=alert("DoneAsik_XSS_test")>'}
        d.find_element(By.NAME, "name").send_keys(payloads[job["level"]])
        d.find_element(By.CSS_SELECTOR, "input[type=submit]").click()
        try:
            alert = WebDriverWait(d, 5, ignored_exceptions=(NoAlertPresentException,)).until(
                lambda w: w.switch_to.alert)
            observed = alert.text
            alert.accept()
        except TimeoutException as exc:
            # Selenium timeouts/failures must never be substituted by an expected alert.
            return {"status": "partial", "summary": "No verified alert: " + str(exc)}
        return {"status": "completed" if observed == "DoneAsik_XSS_test" else "partial",
                "alert": observed, "summary": "Observed DVWA reflected alert: " + observed}
    finally:
        d.quit()


def main() -> None:
    job = json.loads(base64.b64decode(sys.argv[1], validate=True))
    directory = Path(tempfile.mkdtemp(prefix="doneasik-lab-"))
    try:
        handler = {"preflight": preflight, "nikto": nikto, "passwords": passwords, "dvwa": dvwa}[job["job"]]
        result = handler(job, directory)
    except Exception as exc:  # noqa: BLE001 - serialized failure boundary in the remote process
        result = {"status": "failed", "summary": str(exc)}
    result["guest_directory"] = str(directory)
    print(MARKER + json.dumps(result, ensure_ascii=True), flush=True)
    # Retain the full protocol in captured stdout, but keep the actual terminal
    # readable for PrintWindow instead of filling it with transport base64/JSON.
    print("\033[2J\033[H", end="", flush=True)
    print("\n" + result["status"].upper() + ": " + result["summary"], flush=True)
    if "ready" in result:
        print("Ready: " + json.dumps(result["ready"]), flush=True)
        print("OpenVAS NASL files: " + str(result["openvas_nasl_files"]), flush=True)
        print("Missing tools: " + ", ".join(result["missing_tools"]), flush=True)
    if result.get("records"):
        print(json.dumps(result["records"], ensure_ascii=False), flush=True)
    if result.get("recovered"):
        print(json.dumps(result["recovered"], ensure_ascii=False), flush=True)
    raw = result.get("show") or result.get("command")
    if isinstance(raw, dict) and raw.get("output"):
        print("\nObserved program output (last 24 lines):", flush=True)
        print("\n".join(raw["output"].splitlines()[-24:]), flush=True)
    sys.exit(0 if result["status"] == "completed" else 2)


if __name__ == "__main__":
    main()
