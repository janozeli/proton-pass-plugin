#!/usr/bin/env python3
import json, os, re, stat, subprocess, sys
from urllib.parse import urlparse

PASS_CLI = os.path.expanduser(os.environ.get("PASS_CLI", "~/.local/bin/pass-cli"))
PAT_FILE = os.path.expanduser(os.environ.get("PASS_PAT_FILE", "~/.config/pass-agent/pat"))
REASON = "proton-pass plugin"
AUTH_ERR = re.compile(r"requires an authenticated client|unauthori[sz]ed|session expired", re.I)
ENV_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]*$")
PROTOCOL = "2025-06-18"
SUPPORTED = {"2024-11-05", "2025-03-26", PROTOCOL}
_hidden = set()


class PassError(Exception):
    pass


def remember(value):
    if isinstance(value, str) and len(value) >= 5:
        _hidden.add(value)


def redact(text):
    if not isinstance(text, str):
        return text
    for secret in sorted(_hidden, key=len, reverse=True):
        text = text.replace(secret, "***")
    return text


def scrub(obj):
    if isinstance(obj, str):
        return redact(obj)
    if isinstance(obj, list):
        return [scrub(x) for x in obj]
    if isinstance(obj, dict):
        return {k: scrub(v) for k, v in obj.items()}
    return obj


def ensure_session():
    path = os.path.expanduser(os.environ.get("PROTON_PASS_SESSION_DIR", "~/.local/share/pass-agent"))
    if os.path.islink(path):
        raise PassError("PROTON_PASS_SESSION_DIR must not be a symlink")
    os.makedirs(path, mode=0o700, exist_ok=True)
    os.chmod(path, 0o700)
    os.environ["PROTON_PASS_SESSION_DIR"] = path


def login():
    try:
        info = os.stat(PAT_FILE)
    except OSError as e:
        raise PassError(f"PAT file: {e.strerror or e}")
    mode = stat.S_IMODE(info.st_mode)
    if os.name == "posix" and mode & 0o077:
        raise PassError(f"PAT file must be mode 0600 (is {mode:04o})")
    with open(PAT_FILE) as f:
        pat = f.read().strip()
    if not pat:
        raise PassError("PAT file is empty")
    _hidden.add(pat)
    env = dict(os.environ, PROTON_PASS_PERSONAL_ACCESS_TOKEN=pat)
    try:
        r = subprocess.run([PASS_CLI, "login"], env=env, capture_output=True, text=True, timeout=60)
    except subprocess.TimeoutExpired:
        raise PassError("pass-cli login timed out")
    except OSError as e:
        raise PassError(f"pass-cli failed to start: {e.strerror or e}")
    if r.returncode != 0:
        raise PassError("pass-cli login failed: " + (r.stderr or "")[-500:])


def cli(*args, reason=None, relogin=True):
    env = dict(os.environ, PROTON_PASS_AGENT_REASON=reason or REASON)
    try:
        r = subprocess.run([PASS_CLI, *args], env=env, capture_output=True, text=True, timeout=120)
    except subprocess.TimeoutExpired:
        raise PassError(f"pass-cli {args[0]} timed out")
    except OSError as e:
        raise PassError(f"pass-cli failed to start: {e.strerror or e}")
    if r.returncode != 0:
        err = r.stderr or ""
        if relogin and AUTH_ERR.search(err):
            login()
            return cli(*args, reason=reason, relogin=False)
        raise PassError(f"pass-cli {args[0]} failed: {err.strip()[-500:]}")
    return r.stdout


def cli_json(*args, **kw):
    raw = cli(*args, "--output", "json", **kw)
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        raise PassError(f"pass-cli {args[0]} returned invalid JSON")
    if not isinstance(data, dict):
        raise PassError(f"pass-cli {args[0]} returned invalid JSON")
    return data


def item_args(a):
    return ["--share-id", a["share_id"], "--item-id", a["item_id"]]


def login_content(item):
    c = item["content"]["content"]
    return c.get("Login") if isinstance(c, dict) else None


def view_item(a, reason=None):
    item = cli_json("item", "view", *item_args(a), reason=reason)["item"]
    login = login_content(item) or {}
    remember(login.get("password"))
    remember(login.get("totp_uri"))
    return item


def list_vaults(a):
    return cli_json("vault", "list")["vaults"]


def search_items(a):
    vaults = [a["vault"]] if a.get("vault") else [v["name"] for v in list_vaults({})]
    q = (a.get("query") or "").lower()
    out = []
    for v in vaults:
        args = ["item", "list", f"--vault-name={v}"] + (["--filter-type", a["type"]] if a.get("type") else [])
        for it in cli_json(*args)["items"]:
            if q in it["title"].lower() and it.get("state", "Active").lower() == "active":
                out.append({"title": it["title"], "type": it["item_type"], "vault": v,
                            "share_id": it["share_id"], "item_id": it["id"], "modified": it["modify_time"]})
    return {"count": len(out), "items": out[: int(a.get("limit", 25))]}


def describe_item(a):
    it = view_item(a, a.get("reason"))
    c = it["content"]
    lg = login_content(it) or {}
    return {
        "title": c["title"], "share_id": it["share_id"], "item_id": it["id"],
        "type": next(iter(c["content"])) if isinstance(c["content"], dict) else c["content"],
        "urls": lg.get("urls", []), "username": lg.get("username", ""), "email": lg.get("email", ""),
        "has_password": bool(lg.get("password")), "has_totp": bool(lg.get("totp_uri")),
        "extra_field_names": [f.get("name") for f in c.get("extra_fields", [])],
        "has_note": bool(c.get("note")),
    }


def get_totp(a):
    return cli_json("item", "totp", *item_args(a), reason=a.get("reason"))


def get_secret(a):
    field = a.get("field", "password")
    value = cli("item", "view", *item_args(a), "--field", field, reason=a.get("reason")).rstrip("\n")
    return {"field": field, "value": value, "warning": "SECRET VALUE - do not repeat it in chat."}


def run_with_secrets(a):
    env = dict(os.environ)
    for k, ref in a["env"].items():
        env[k] = ref
    env["PROTON_PASS_AGENT_REASON"] = a.get("reason") or REASON
    cli("vault", "list")
    try:
        r = subprocess.run(
            [PASS_CLI, "run", "--", "bash", "-c", a["command"]],
            env=env, capture_output=True, text=True, timeout=int(a.get("timeout", 120)), cwd=a.get("cwd") or None)
    except subprocess.TimeoutExpired:
        raise PassError("command timed out")
    except OSError as e:
        raise PassError(f"pass-cli failed to start: {e.strerror or e}")
    return {"exit_code": r.returncode, "stdout": r.stdout[-8000:], "stderr": r.stderr[-4000:]}


USER_SEL = ('input[autocomplete=username], input[type=email], input[name*=user i], input[name*=login i], '
            'input[name*=email i], input[id*=user i], input[id*=email i], input[type=text]')


def tab_matches(page_url, match, hosts):
    page = urlparse(page_url)
    host = page.hostname or ""
    if match:
        parsed = urlparse(match if "//" in match else "//" + match)
        want = parsed.hostname or ""
        if not want or not (host == want or host.endswith("." + want)):
            return False
        return parsed.port is None or page.port == parsed.port
    return any(h and (host == h or host.endswith("." + h)) for h in hosts)


def fill_login(a):
    from playwright.sync_api import sync_playwright
    it = view_item(a, a.get("reason"))
    lg = login_content(it)
    if not lg:
        raise PassError("item is not a Login")
    match = a.get("url_match") or ""
    hosts = [urlparse(u if "//" in u else "https://" + u).hostname or "" for u in lg.get("urls", [])]
    port = int(a.get("cdp_port") or os.environ.get("PASS_CDP_PORT", 9222))
    with sync_playwright() as p:
        browser = p.chromium.connect_over_cdp(f"http://127.0.0.1:{port}")
        try:
            pages = [pg for ctx in browser.contexts for pg in ctx.pages]
            page = next((pg for pg in pages if tab_matches(pg.url, match, hosts)), None)
            if not page:
                raise PassError(f"no open tab matches {match or hosts}; open tabs: {[pg.url for pg in pages]}")
            filled = []
            user = lg.get("username") or lg.get("email")
            pw_sel = a.get("password_selector") or "input[type=password]"
            if user and a.get("fill_username", True):
                u = page.locator(a.get("username_selector") or USER_SEL).locator("visible=true").first
                if u.count():
                    u.fill(user); filled.append("username")
            pw = page.locator(pw_sel).locator("visible=true").first
            if lg.get("password") and pw.count():
                pw.fill(lg["password"]); filled.append("password")
            if a.get("submit") and "password" in filled:
                pw.press("Enter"); filled.append("submitted")
            url = page.url
        finally:
            browser.close()  # disconnects only; the user's browser keeps running
    return {"page": url, "filled": filled}


def _bad_token(value):
    return not isinstance(value, str) or not value or value.startswith("-") or any(c in value for c in "\n\r\x00")


def _bad_ref(ref):
    if not isinstance(ref, str) or any(c in ref for c in "\n\r\x00") or not ref.startswith("pass://"):
        return True
    parts = ref[len("pass://"):].split("/")
    return len(parts) < 3 or any(not part for part in parts[:3])


def validate(name, args):
    if name not in TOOLS:
        raise PassError(f"unknown tool {name}")
    props, required = TOOLS[name][2], TOOLS[name][3]
    if not isinstance(args, dict):
        raise PassError("arguments must be an object")
    missing = [k for k in required if k not in args]
    if missing:
        raise PassError("missing " + ", ".join(missing))
    for k, v in args.items():
        if k not in props:
            raise PassError(f"unknown argument {k}")
        spec = props[k]
        t = spec.get("type")
        if t == "string" and not isinstance(v, str):
            raise PassError(f"{k} must be a string")
        elif t == "integer" and (isinstance(v, bool) or not isinstance(v, int)):
            raise PassError(f"{k} must be an integer")
        elif t == "boolean" and not isinstance(v, bool):
            raise PassError(f"{k} must be a boolean")
        elif t == "object":
            if not isinstance(v, dict):
                raise PassError(f"{k} must be an object")
            if (spec.get("additionalProperties") or {}).get("type") == "string":
                if any(not isinstance(ek, str) or not isinstance(ev, str) for ek, ev in v.items()):
                    raise PassError(f"{k} values must be strings")
        if "enum" in spec and v not in spec["enum"]:
            raise PassError(f"{k} must be one of: " + ", ".join(spec["enum"]))
    for key in ("share_id", "item_id", "field"):
        if key in args and _bad_token(args[key]):
            raise PassError(f"{key} is invalid")
    if "vault" in args and any(c in args["vault"] for c in "\n\r\x00"):
        raise PassError("vault is invalid")
    if "limit" in args and args["limit"] < 0:
        raise PassError("limit must be >= 0")
    if "timeout" in args and args["timeout"] <= 0:
        raise PassError("timeout must be > 0")
    if "cdp_port" in args and not 1 <= args["cdp_port"] <= 65535:
        raise PassError("cdp_port is invalid")
    if "command" in args and not args["command"].strip():
        raise PassError("command is empty")
    if "env" in args:
        if not args["env"]:
            raise PassError("env is empty")
        for k, ref in args["env"].items():
            if not ENV_NAME.fullmatch(k):
                raise PassError(f"invalid env name {k}")
            if _bad_ref(ref):
                raise PassError(f"env {k} must be a pass://SHARE_ID/ITEM_ID/FIELD reference")


S = {"type": "string"}
ITEM = {"share_id": S, "item_id": S, "reason": {"type": "string", "description": "Why access is needed (logged by Proton)."}}
TOOLS = {
    "list_vaults": (list_vaults, "List Proton Pass vaults (names and ids).", {}, []),
    "search_items": (search_items, "Search items by title (case-insensitive substring). Metadata only, no secrets.",
                     {"query": S, "vault": S, "type": {"type": "string", "enum": ["login", "note", "alias", "credit-card", "identity", "ssh-key", "wifi", "custom"]}, "limit": {"type": "integer"}}, []),
    "describe_item": (describe_item, "Item details without secrets: URLs, username/email, has_password, has_totp, extra field names.", ITEM, ["share_id", "item_id"]),
    "get_totp": (get_totp, "Current TOTP code for an item (short-lived, OK to type into a 2FA prompt).", ITEM, ["share_id", "item_id"]),
    "fill_login": (fill_login, "Fill username/password of a Login item into an open Chrome tab over CDP. Secrets never return to the model. The tab is chosen by host (url_match) or the item's URL hosts.",
                   {**ITEM, "cdp_port": {"type": "integer", "description": "Chrome --remote-debugging-port (default PASS_CDP_PORT or 9222)."},
                    "url_match": S, "username_selector": S, "password_selector": S,
                    "fill_username": {"type": "boolean"}, "submit": {"type": "boolean"}}, ["share_id", "item_id"]),
    "run_with_secrets": (run_with_secrets, "Run a bash command with secrets injected as env vars (values are pass://SHARE_ID/ITEM_ID/FIELD). pass-cli masks those values in output.",
                         {"command": S, "env": {"type": "object", "additionalProperties": S}, "cwd": S, "timeout": {"type": "integer"}, "reason": S}, ["command", "env"]),
    "get_secret": (get_secret, "RETURNS THE SECRET VALUE to the model. Only use when the user explicitly asks and no secret-safe tool fits. field: password, username, email, note, or extra field name.",
                   {**ITEM, "field": S}, ["share_id", "item_id"]),
}


def _result(mid, result):
    return {"jsonrpc": "2.0", "id": mid, "result": result}


def _error(mid, code, message):
    return {"jsonrpc": "2.0", "id": mid, "error": {"code": code, "message": redact(message)}}


def handle(msg):
    if not isinstance(msg, dict) or not isinstance(msg.get("method"), str):
        return _error(msg.get("id") if isinstance(msg, dict) else None, -32600, "invalid request")
    if "id" not in msg:
        return None
    mid, method = msg["id"], msg["method"]
    params = msg.get("params") if msg.get("params") is not None else {}
    if not isinstance(params, dict):
        return _error(mid, -32602, "invalid params")
    if method == "initialize":
        version = params.get("protocolVersion")
        if version not in SUPPORTED:
            version = PROTOCOL
        return _result(mid, {"protocolVersion": version, "capabilities": {"tools": {}},
                             "serverInfo": {"name": "proton-pass", "version": "0.1.1"}})
    if method == "tools/list":
        tools = [{"name": n, "description": d, "inputSchema": {"type": "object", "properties": p, "required": r, "additionalProperties": False}}
                 for n, (_, d, p, r) in TOOLS.items()]
        return _result(mid, {"tools": tools})
    if method == "tools/call":
        if not isinstance(params.get("name"), str):
            return _error(mid, -32602, "invalid params")
        name, args = params["name"], params.get("arguments") or {}
        try:
            validate(name, args)
            out = TOOLS[name][0](args)
            if name == "get_secret":
                text = json.dumps(out, ensure_ascii=False, indent=1)
                remember(out.get("value"))
            else:
                text = json.dumps(scrub(out), ensure_ascii=False, indent=1)
            res = {"content": [{"type": "text", "text": text}]}
        except Exception as e:
            res = {"content": [{"type": "text", "text": redact(f"{type(e).__name__}: {e}")}], "isError": True}
        return _result(mid, res)
    if method == "ping":
        return _result(mid, {})
    return _error(mid, -32601, f"unknown method {method}")


def write(obj):
    sys.stdout.write(json.dumps(obj) + "\n")
    sys.stdout.flush()


def main():
    try:
        ensure_session()
    except (OSError, PassError) as e:
        print(f"proton-pass: {e}", file=sys.stderr)
        sys.exit(1)
    for line in sys.stdin:
        if not line.strip():
            continue
        try:
            msg = json.loads(line)
        except json.JSONDecodeError:
            write({"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": "parse error"}})
            continue
        try:
            reply = handle(msg)
        except Exception:
            if not isinstance(msg, dict) or "id" not in msg:
                continue
            reply = {"jsonrpc": "2.0", "id": msg.get("id"), "error": {"code": -32603, "message": "internal error"}}
        if reply:
            write(reply)


if __name__ == "__main__":
    main()
