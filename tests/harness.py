import json, os, site, socket, sys, tempfile, threading
from mcp_client import ROOT, Client

SERVER = os.path.join(ROOT, "server", "proton_pass_mcp.py")
TOKEN = "pst-TEST-TOKEN-value"
PASSWORD = "hunter2-secret-value"
PIN = "9876"
SEED = "SEEDSECRETVALUE"
HOST_SECRET = "other-host-secret-value"

FAKE = r'''#!PYTHON
import json, os, sys
here = os.path.dirname(os.path.abspath(__file__))


def path(name):
    return os.path.join(here, name)


def finish(out="", err="", code=0):
    sys.stdout.write(out)
    sys.stderr.write(err)
    sys.exit(code)


raw = open("/proc/self/environ", "rb").read().split(b"\0")
env = dict(entry.decode().split("=", 1) for entry in raw if entry)
args = sys.argv[1:]
with open(path("calls"), "a") as f:
    f.write(json.dumps(args) + "\n")
if args == ["login"]:
    json.dump(env, open(path("login-env.json"), "w"))
    if os.path.exists(path("login-fail")):
        finish(err="rejected " + env.get("PROTON_PASS_PERSONAL_ACCESS_TOKEN", ""), code=1)
    open(path("ok"), "w").close()
    finish()
if not os.path.exists(path("ok")):
    finish(err="Error: This operation requires an authenticated client", code=1)
if args[:1] == ["info"]:
    try:
        os.remove(path("ok"))
    except FileNotFoundError:
        pass
    finish(err="session invalidated", code=1)
if os.path.exists(path("stderr")):
    finish(err=open(path("stderr")).read(), code=1)
if args[:3] == ["item", "create", "login"]:
    open(path("created.json"), "w").write(sys.stdin.read())
    finish("item-new\n")
if args[:2] == ["item", "delete"]:
    open(path("deleted"), "a").write(json.dumps(args) + "\n")
    finish()
if args[:2] == ["run", "--"]:
    json.dump(env, open(path("run-env.json"), "w"))
    json.dump([os.readlink(f"/proc/self/fd/{n}") for n in range(3)], open(path("run-fds.json"), "w"))
    secrets = json.load(open(path("secrets.json")))
    child = {k: secrets[v[len("pass://"):]] if v.startswith("pass://") else v for k, v in env.items()}
    os.execve(args[2], args[2:], child)
replies = {"vault list": "vaults.json", "item list": "items.json", "item view": "item.json",
           "item totp": "totp.json", "share list": "shares.json"}
name = replies.get(" ".join(args[:2]))
if not name:
    finish(err="unexpected " + " ".join(args), code=1)
finish(open(path(name)).read())
'''

CHILD = r'''
import json, os, socket, sys
port, want, *host = sys.argv[1:]
raw = open("/proc/self/environ", "rb").read().split(b"\0")
env = dict(entry.decode().split("=", 1) for entry in raw if entry)
seen = {"env": env, "cwd": os.getcwd(), "tmp": os.listdir("/tmp"), "host": [p for p in host if os.path.exists(p)]}
print(env.get("PW"))
try:
    with socket.create_connection(("127.0.0.1", int(port)), timeout=5) as s:
        s.sendall(json.dumps(seen).encode())
except OSError:
    sys.exit(7 if seen == json.loads(want) else 8)
sys.exit(9)
'''
PYTHON = "/usr/bin/python3"


def item(urls):
    return {"item": {"id": "item1", "share_id": "share1", "content": {
        "title": "Bank", "note": "private note",
        "content": {"Login": {
            "username": "ada", "email": "ada@example.com", "password": PASSWORD,
            "totp_uri": f"otpauth://totp/Bank?secret={SEED}", "urls": list(urls),
        }},
        "extra_fields": [{"name": "api"}],
    }}}


def write(d, name, data):
    with open(os.path.join(d, name), "w") as f:
        f.write(data if isinstance(data, str) else json.dumps(data))


def session(d):
    return os.path.join(d, "session")


def server_env(d, **env):
    # HOME moves to a temp dir, so pin the user site that may hold Playwright.
    return {"HOME": os.path.join(d, "home"), "PYTHONUSERBASE": site.getuserbase(),
            "PASS_CLI": os.path.join(d, "pass-cli"), "PASS_PAT_FILE": os.path.join(d, "pat"),
            "PROTON_PASS_SESSION_DIR": session(d), "OTHER_HOST_SECRET": HOST_SECRET, **env}


def install(d=None, urls=("https://bank.com/login",), token=TOKEN):
    d = d or tempfile.mkdtemp()
    os.makedirs(os.path.join(d, "home"), exist_ok=True)
    write(d, "pass-cli", FAKE.replace("#!PYTHON", "#!" + sys.executable, 1))
    os.chmod(os.path.join(d, "pass-cli"), 0o755)
    write(d, "pat", token + "\n")
    os.chmod(os.path.join(d, "pat"), 0o600)
    write(d, "vaults.json", {"vaults": [{"name": "V", "vault_id": "v", "share_id": "share1"}]})
    write(d, "shares.json", {"shares": [{"id": "share1", "name": "V", "share_type": "Vault", "share_role": "Viewer"}]})
    write(d, "items.json", {"items": [
        {"title": "Bank", "item_type": "login", "share_id": "share1", "id": "item1", "modify_time": 1, "state": "Active"},
        {"title": "Old", "item_type": "login", "share_id": "share1", "id": "item2", "modify_time": 1, "state": "Trashed"},
    ]})
    write(d, "item.json", item(urls))
    write(d, "totp.json", {"totp": "123456", "otpauth": f"otpauth://totp/Bank?secret={SEED}"})
    write(d, "secrets.json", {"share1/item1/password": PASSWORD, "share1/item1/pin": PIN})
    return d


def start(d=None, urls=("https://bank.com/login",), token=TOKEN, drop=(), **env):
    d = install(d, urls, token)
    return d, Client(server_env(d, **env), drop=drop)


def calls(d):
    p = os.path.join(d, "calls")
    return [json.loads(line) for line in open(p)] if os.path.exists(p) else []


def error(c, name, **args):
    try:
        got = c.call(name, **args)
    except RuntimeError as e:
        return str(e)
    raise AssertionError(f"{name} succeeded: {got}")


def child(d, port=1):
    want = {"env": {"PATH": "/usr/bin:/bin", "HOME": "/tmp", "PWD": "/tmp", "PW": PIN}, "cwd": "/tmp", "tmp": [], "host": []}
    host = [d, session(d), os.path.join(d, "pat"), ROOT, os.path.expanduser("~")]
    return [PYTHON, "-c", CHILD, str(port), json.dumps(want), *host], want


class Operator:
    def __init__(self, d, reply=None, gate=None):
        self.prompts, self.reply, self.gate = [], reply or {"op": "allow"}, gate
        self.path = os.path.join(session(d), "approve.sock")
        self.sock = socket.socket(socket.AF_UNIX)
        self.sock.bind(self.path)
        self.sock.listen()
        threading.Thread(target=self.serve, daemon=True).start()

    def serve(self):
        while True:
            try:
                conn, _ = self.sock.accept()
            except OSError:
                return
            with conn:
                self.prompts.append(json.loads(conn.makefile("rb").readline()))
                if self.gate:
                    self.gate.wait(30)
                conn.sendall(json.dumps(self.reply).encode() + b"\n")

    def close(self):
        try:
            self.sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        self.sock.close()
        os.unlink(self.path)
