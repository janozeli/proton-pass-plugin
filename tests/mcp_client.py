import json, os, subprocess, sys
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

class Client:
    def __init__(self, env=None, drop=()):
        merged = dict(os.environ, **(env or {}))
        for key in drop:
            merged.pop(key, None)
        self.p = subprocess.Popen([sys.executable, f"{ROOT}/server/proton_pass_mcp.py"], stdin=subprocess.PIPE,
                                  stdout=subprocess.PIPE, text=True, env=merged)
        self.n = 0
        self.rpc("initialize", {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "test"}})
        self.send({"jsonrpc": "2.0", "method": "notifications/initialized"})

    def send(self, obj):
        self.p.stdin.write(json.dumps(obj) + "\n")
        self.p.stdin.flush()

    def send_raw(self, line):
        self.p.stdin.write(line if line.endswith("\n") else line + "\n")
        self.p.stdin.flush()

    def read(self):
        line = self.p.stdout.readline()
        if not line:
            raise RuntimeError("server exited")
        return json.loads(line)

    def rpc(self, method, params=None):
        self.n += 1
        self.send({"jsonrpc": "2.0", "id": self.n, "method": method, "params": params or {}})
        msg = self.read()
        if "error" in msg:
            raise RuntimeError(json.dumps(msg["error"]))
        return msg["result"]

    def call(self, name, **args):
        r = self.rpc("tools/call", {"name": name, "arguments": args})
        text = r["content"][0]["text"]
        if r.get("isError"):
            raise RuntimeError(text)
        return json.loads(text)

    def close(self):
        self.p.stdin.close(); self.p.wait()
