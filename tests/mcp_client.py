import json, os, subprocess, sys
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

class Client:
    def __init__(self, env=None):
        self.p = subprocess.Popen([sys.executable, f"{ROOT}/server/proton_pass_mcp.py"], stdin=subprocess.PIPE,
                                  stdout=subprocess.PIPE, text=True, env=dict(os.environ, **(env or {})))
        self.n = 0
        self.rpc("initialize", {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "test"}})
        self.p.stdin.write(json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized"}) + "\n")

    def rpc(self, method, params=None):
        self.n += 1
        self.p.stdin.write(json.dumps({"jsonrpc": "2.0", "id": self.n, "method": method, "params": params or {}}) + "\n")
        self.p.stdin.flush()
        return json.loads(self.p.stdout.readline())["result"]

    def call(self, name, **args):
        r = self.rpc("tools/call", {"name": name, "arguments": args})
        text = r["content"][0]["text"]
        if r.get("isError"):
            raise RuntimeError(text)
        return json.loads(text)

    def close(self):
        self.p.stdin.close(); self.p.wait()
