"""Try the adaptive agent against two local forms; no external sites or credentials."""
import argparse
import json
import secrets
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs

from lab_agent.config import AgentConfig
from lab_agent.evidence import register_evidence
from lab_agent.integrations.base import ExecutionContext
from lab_agent.integrations.registry import build_registry

ROOT = Path(__file__).resolve().parents[1] / "workspace" / "BrowserAgentDemo"
TOKEN = secrets.token_hex(4)
FIELDS = {key: secrets.token_hex(5) for key in ("name", "group", "ready", "port")}
RESULTS = []


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def send_page(self, content, variant=1):
        html = f'''<!doctype html><html><head><meta charset="utf-8"><title>Local browser lab {TOKEN} / {variant}</title>
        <style>body{{font:20px system-ui;background:#eaf0f7;color:#142238;margin:50px auto;max-width:850px}}
        main{{background:white;padding:36px;border-radius:12px}}label{{display:block;margin:20px 0}}
        input,select,button{{font:inherit;padding:8px}}button{{background:#244b83;color:white;border:0;border-radius:5px}}
        h1{{font-size:28px}}aside{{color:#47617e}}</style></head><body><main>
        <aside>DoneAsik · локальный учебный стенд · вариант {variant}</aside>{content}</main></body></html>'''
        data = html.encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        variant = 2 if self.path.startswith("/second") else 1
        name = "Full name" if variant == 1 else "Student name"
        group = "Class group" if variant == 1 else "Your group"
        ready = "I am ready for the lab" if variant == 1 else "Confirm participation"
        controls = [f'<label>{name} <input name="{FIELDS["name"]}" required></label>',
                    (f'<label>{group} <select name="{FIELDS["group"]}" required><option value="">Choose</option>'
                     '<option value="g1">cs-2410</option><option value="g2">cs-2426</option></select></label>'),
                    f'<label><input type="checkbox" name="{FIELDS["ready"]}" required> {ready}</label>']
        if variant == 2:
            controls = [controls[1], controls[0], controls[2]]
        self.send_page(f'<h1>Network security lab</h1><p>Register and answer the networking question.</p>'
                       f'<form method="post" action="/stage/{variant}">{"".join(controls)}'
                       '<button>Continue to question</button></form>', variant)

    def do_POST(self):
        values = parse_qs(self.rfile.read(int(self.headers.get("Content-Length", "0"))).decode())
        variant = int(self.path.rsplit("/", 1)[-1])
        if self.path.startswith("/stage/"):
            valid = (values.get(FIELDS["name"]) == ["Demo Student"]
                     and values.get(FIELDS["group"]) == ["g2"] and FIELDS["ready"] in values)
            if not valid:
                self.send_page("<h1>Registration incomplete</h1>", variant)
                return
            self.send_page(f'<h1>Question</h1><p>Which TCP port is used by HTTPS by default?</p>'
                           f'<form method="post" action="/finish/{variant}"><label>HTTPS port '
                           f'<select name="{FIELDS["port"]}"><option value="">Choose</option>'
                           '<option value="80">80</option><option value="443">443</option><option value="22">22</option>'
                           '</select></label><button>Submit answer</button></form>', variant)
        else:
            ok = values.get(FIELDS["port"]) == ["443"]
            RESULTS.append({"variant": variant, "port": values.get(FIELDS["port"]), "accepted": ok})
            (ROOT / f"server_observations_{TOKEN}.json").write_text(json.dumps(RESULTS, indent=2))
            self.send_page(f'<h1 id="result">{"Lab completed successfully" if ok else "Incorrect answer"}</h1>'
                           '<p>Your submitted answer has been checked by the local server.</p>', variant)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--provider", default="ollama", choices=("ollama", "codex", "openai"))
    parser.add_argument("--model", default=None)
    args = parser.parse_args()
    ROOT.mkdir(parents=True, exist_ok=True)
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    config = AgentConfig(ai={"provider": args.provider,
                             "model": args.model or ("qwen3:4b" if args.provider == "ollama" else None),
                             "ollama_think": False, "ollama_num_ctx": 16384,
                             "timeout_seconds": 90, "max_retries": 0})
    try:
        for variant in (1, 2):
            ws = ROOT / f"run_{TOKEN}_{variant}"
            context = ExecutionContext(ws, "Local browser demonstration", config=config,
                                       event_fn=lambda event, data: print(json.dumps({"event": event, "turn": data.get("turn"),
                                           "action": data.get("action", {}).get("action"),
                                           "target": data.get("action", {}).get("target")}, ensure_ascii=False), flush=True))
            registry = build_registry(config=config)
            try:
                params = {"url": f"http://127.0.0.1:{server.server_port}/{'second' if variant == 2 else 'first'}",
                          "goal": "Register as Demo Student in group cs-2426, confirm participation, continue to the question, "
                                  "choose HTTPS default TCP port 443, and submit the answer.",
                          "expected_text": "Lab completed successfully", "success_selector": "#result",
                          "max_steps": 15}
                result = registry.execute("browser.run_task", params, context)
                for artifact in result.evidence:
                    register_evidence(ws, Path(artifact["path"]), artifact["description"], artifact["type"],
                                      capability="browser.run_task")
                summary = {"variant": variant, "verified": result.verified, "blocked": result.blocked,
                           "details": result.details, "evidence": result.evidence}
                (ROOT / f"summary_{TOKEN}_{variant}.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")
                print(json.dumps({"demo_result": summary}, ensure_ascii=False), flush=True)
                if not result.verified:
                    raise SystemExit(3)
            finally:
                registry.shutdown()
    finally:
        server.shutdown()


if __name__ == "__main__":
    main()
