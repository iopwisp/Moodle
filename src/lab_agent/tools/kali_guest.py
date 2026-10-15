"""Python helpers sent over SSH; no screenshots or image generation in the guest.

The terminal runs on the logged-in guest's X11 desktop. Its actual output stays
visible for a host-side PrintWindow capture. Only JSON and text cross SSH.
"""

TERMINAL_WORKER = r'''
import json, os, signal, subprocess, sys
from pathlib import Path

job = json.loads(sys.argv[1])
if job.get("title"):
    print("\033]0;" + job["title"] + "\007", end="", flush=True)
print("$ " + job["command"], flush=True)
process = subprocess.Popen(
    ["/bin/bash", "-lc", job["command"]], cwd=job["cwd"] or None,
    stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
    start_new_session=True,
)
Path(job["directory"], "pid").write_text(str(process.pid))
timed_out = False
try:
    output, _ = process.communicate(timeout=job["timeout"])
except subprocess.TimeoutExpired:
    timed_out = True
    os.killpg(process.pid, signal.SIGKILL)
    output, _ = process.communicate()
text = output.decode("utf-8", errors="replace")
print(text, end="" if text.endswith("\n") else "\n", flush=True)
print("\nExit code: " + str(process.returncode), flush=True)
result = {"exit_code": process.returncode, "stdout": text, "timed_out": timed_out}
temporary = Path(job["directory"], "result.tmp")
temporary.write_text(json.dumps(result), encoding="utf-8")
temporary.replace(Path(job["directory"], "result.json"))
if job.get("hold_open"):
    signal.pause()
'''

SSH_BOOTSTRAP = r'''
import json, os, re, shutil, signal, subprocess, sys, tempfile, time
from pathlib import Path

job = json.load(sys.stdin)
guest_macs = {p.read_text().strip().replace(":", "").lower()
              for p in Path("/sys/class/net").glob("*/address")}
if not guest_macs.intersection(job["vm_macs"]):
    raise RuntimeError("SSH host network adapters do not match the selected VirtualBox VM")
directory = Path(tempfile.mkdtemp(prefix="doneasik-"))
job["directory"] = str(directory)
environment = dict(os.environ, DISPLAY=job["display"])
environment.setdefault("XDG_RUNTIME_DIR", "/run/user/" + str(os.getuid()))
environment.setdefault("DBUS_SESSION_BUS_ADDRESS", "unix:path=" + environment["XDG_RUNTIME_DIR"] + "/bus")
if job.get("xauthority"):
    environment["XAUTHORITY"] = job["xauthority"]
else:
    environment.setdefault("XAUTHORITY", str(Path.home() / ".Xauthority"))
error_path = directory / "terminal.log"
if shutil.which("xfce4-screensaver-command"):
    subprocess.run(["xfce4-screensaver-command", "--deactivate"], env=environment,
                   stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                   stderr=subprocess.DEVNULL, timeout=5, check=False)
    with error_path.open("a") as error:
        # A temporary inhibit expires automatically; no user preferences change.
        subprocess.Popen(
            ["timeout", str(job["timeout"] + 30), "xfce4-screensaver-command", "--inhibit",
             "--application-name", "DoneAsik", "--reason", "Collect lab window evidence"],
            env=environment, stdin=subprocess.DEVNULL, stdout=error, stderr=error,
            start_new_session=True,
        )
worker = job.pop("worker")
if shutil.which("xterm"):
    terminal_command = ["xterm", "-hold", "-T", job["title"], "-geometry", "110x32+0+0",
                        "-fa", "Monospace", "-fs", "12"]
elif shutil.which("qterminal"):
    terminal_command = ["qterminal"]
    job["hold_open"] = True
else:
    raise RuntimeError("Install xterm or qterminal in the Kali guest")
with error_path.open("w") as error:
    terminal = subprocess.Popen(
        [*terminal_command, "-e", "python3", "-c", worker, json.dumps(job)],
        env=environment, stdin=subprocess.DEVNULL, stdout=error, stderr=error,
        start_new_session=True,
    )
deadline = time.monotonic() + job["timeout"] + 15
result_path = directory / "result.json"
while not result_path.exists():
    if terminal.poll() is not None:
        raise RuntimeError("Guest terminal could not execute command: " + error_path.read_text())
    if time.monotonic() > deadline:
        pid_path = directory / "pid"
        if pid_path.exists():
            try:
                os.killpg(int(pid_path.read_text()), signal.SIGKILL)
            except ProcessLookupError:
                pass
        os.killpg(terminal.pid, signal.SIGKILL)
        raise TimeoutError("No result from guest terminal; inspect " + str(directory))
    time.sleep(0.1)
result = json.loads(result_path.read_text(encoding="utf-8"))
result.update(guest_directory=str(directory), title=job["title"], guest_macs=sorted(guest_macs),
              terminal=terminal_command[0])
result["terminal_visible"] = False
deadline = time.monotonic() + 5
while time.monotonic() < deadline:
    try:
        active = subprocess.check_output(
            ["xprop", "-root", "_NET_ACTIVE_WINDOW"], env=environment, timeout=2,
        ).decode()
        match = re.search(r"0x[0-9a-fA-F]+", active)
        if match is None:
            break
        window_id = match.group(0)
        title = subprocess.check_output(
            ["xprop", "-id", window_id, "WM_NAME"], env=environment, timeout=2,
        ).decode()
        if job["title"] in title:
            visible = True
            if shutil.which("xfce4-screensaver-command"):
                state = subprocess.run(["xfce4-screensaver-command", "--query"],
                                       env=dict(environment, LC_ALL="C.UTF-8"),
                                       capture_output=True, text=True, timeout=2, check=False)
                visible = state.returncode == 0 and "is active" not in state.stdout
            if visible:
                result["terminal_visible"] = True
                break
    except (OSError, subprocess.SubprocessError):
        pass
    time.sleep(0.1)
print(json.dumps(result))
'''

SSH_OBSERVE = r'''
import json, os, re, shutil, subprocess, sys
from pathlib import Path
job = json.load(sys.stdin)
macs = {p.read_text().strip().replace(":", "").lower()
        for p in Path("/sys/class/net").glob("*/address")}
if not macs.intersection(job["vm_macs"]):
    raise RuntimeError("SSH host does not match the selected VirtualBox VM")
environment = dict(os.environ, DISPLAY=job["display"],
                   XAUTHORITY=job.get("xauthority") or str(Path.home() / ".Xauthority"),
                   DBUS_SESSION_BUS_ADDRESS="unix:path=/run/user/" + str(os.getuid()) + "/bus",
                   LC_ALL="C.UTF-8")
visible = False
active = subprocess.check_output(["xprop", "-root", "_NET_ACTIVE_WINDOW"], env=environment, timeout=3).decode()
match = re.search(r"0x[0-9a-fA-F]+", active)
if match:
    title = subprocess.check_output(["xprop", "-id", match.group(0), "WM_NAME"], env=environment, timeout=3).decode()
    visible = job["title"] in title
if shutil.which("xfce4-screensaver-command"):
    state = subprocess.run(["xfce4-screensaver-command", "--query"], env=environment,
                           capture_output=True, text=True, timeout=3, check=False)
    if state.returncode != 0 or "is active" in state.stdout:
        visible = False
print(json.dumps({"terminal_visible": visible}))
'''
