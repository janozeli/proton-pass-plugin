#!/usr/bin/env python3
"""Proton Pass MCP server (stdio). Wraps the official pass-cli.

Secret values never reach the model except through get_totp (a 30s code) and
get_secret (explicitly opt-in). fill_login and run_with_secrets use secrets
inside this process / pass-cli and return only redacted results.
"""
import json, os, re, subprocess, sys
from urllib.parse import urlparse

PASS_CLI = os.path.expanduser(os.environ.get("PASS_CLI", "~/.local/bin/pass-cli"))
PAT_FILE = os.path.expanduser(os.environ.get("PASS_PAT_FILE", "~/.config/pass-agent/pat"))
os.environ.setdefault("PROTON_PASS_SESSION_DIR", "/tmp/pass-agent-mcp")
REASON = "Grok Bot proton-pass plugin"
AUTH_ERR = re.compile(r"authenticated|session|expired|unauthori|log ?in", re.I)


class PassError(Exception):
    pass


def login():
    with open(PAT_FILE) as f:
        pat = f.read().strip()
    env = dict(os.environ, PROTON_PASS_PERSONAL_ACCESS_TOKEN=pat)
    r = subprocess.run([PASS_CLI, "login"], env=env, capture_output=True, text=True, timeout=60)
    if r.returncode != 0:
        raise PassError("pass-cli login failed: " + r.stderr.replace(pat, "***")[-500:])


def cli(*args, reason=None, relogin=True):
    env = dict(os.environ, PROTON_PASS_AGENT_REASON=reason or REASON)
    r = subprocess.run([PASS_CLI, *args], env=env, capture_output=True, text=True, timeout=120)
    if r.returncode != 0:
        if relogin and AUTH_ERR.search(r.stderr):
            login()
            return cli(*args, reason=reason, relogin=False)
        raise PassError(f"pass-cli {args[0]} {args[1] if len(args) > 1 else ''} failed: {r.stderr.strip()[-500:]}")
    return r.stdout


def cli_json(*args, **kw):
    return json.loads(cli(*args, "--output", "json", **kw))


def item_args(a):
    return ["--share-id", a["share_id"], "--item-id", a["item_id"]]


def view_item(a, reason=None):
    return cli_json("item", "view", *item_args(a), reason=reason)["item"]


def login_content(item):
    c = item["content"]["content"]
    return c.get("Login") if isinstance(c, dict) else None


# ---- tools ----

def list_vaults(a):
    return cli_json("vault", "list")["vaults"]


def search_items(a):
    vaults = [a["vault"]] if a.get("vault") else [v["name"] for v in list_vaults({})]
    q = (a.get("query") or "").lower()
    out = []
    for v in vaults:
        args = ["item", "list", v] + (["--filter-type", a["type"]] if a.get("type") else [])
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
    return {"field": field, "value": cli("item", "view", *item_args(a), "--field", field, reason=a.get("reason")).rstrip("\n"),
            "warning": "SECRET VALUE - do not repeat it in chat."}


def run_with_secrets(a):
    env = dict(os.environ)
    for k, ref in a["env"].items():
        if not str(ref).startswith("pass://"):
            raise PassError(f"env {k} must be a pass://SHARE_ID/ITEM_ID/FIELD reference")
        env[k] = ref
    env["PROTON_PASS_AGENT_REASON"] = a.get("reason") or REASON
    cli("vault", "list")  # refresh the session first so the command never runs twice
    cmd = [PASS_CLI, "run", "--", "bash", "-c", a["command"]]
    r = subprocess.run(cmd, env=env, capture_output=True, text=True, timeout=int(a.get("timeout", 120)), cwd=a.get("cwd"))
    return {"exit_code": r.returncode, "stdout": r.stdout[-8000:], "stderr": r.stderr[-4000:],
            "note": "pass-cli masks secret values in output"}


USER_SEL = ('input[autocomplete=username], input[type=email], input[name*=user i], input[name*=login i], '
            'input[name*=email i], input[id*=user i], input[id*=email i], input[type=text]')


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
        pages = [pg for ctx in browser.contexts for pg in ctx.pages]
        def ok(pg):
            if match:
                return match in pg.url
            h = urlparse(pg.url).hostname or ""
            return any(x and (h == x or h.endswith("." + x)) for x in hosts)
        page = next((pg for pg in pages if ok(pg)), None)
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
        browser.close()  # disconnects only; the user's browser keeps running
    return {"page": url, "filled": filled}


S = {"type": "string"}
ITEM = {"share_id": S, "item_id": S, "reason": {"type": "string", "description": "Why access is needed (logged by Proton)."}}
TOOLS = {
    "list_vaults": (list_vaults, "List Proton Pass vaults (names and ids).", {}, []),
    "search_items": (search_items, "Search items by title (case-insensitive substring). Metadata only, no secrets.",
                     {"query": S, "vault": S, "type": {"type": "string", "enum": ["login", "note", "alias", "credit-card", "identity", "ssh-key", "wifi", "custom"]}, "limit": {"type": "integer"}}, []),
    "describe_item": (describe_item, "Item details without secrets: URLs, username/email, has_password, has_totp, extra field names.", ITEM, ["share_id", "item_id"]),
    "get_totp": (get_totp, "Current TOTP code for an item (short-lived, OK to type into a 2FA prompt).", ITEM, ["share_id", "item_id"]),
    "fill_login": (fill_login, "Fill username/password of a Login item into an open Chrome tab over CDP. Secrets never return to the model. Tab chosen by url_match or the item's URLs.",
                   {**ITEM, "cdp_port": {"type": "integer", "description": "Chrome --remote-debugging-port (default PASS_CDP_PORT or 9222)."},
                    "url_match": S, "username_selector": S, "password_selector": S,
                    "fill_username": {"type": "boolean"}, "submit": {"type": "boolean"}}, ["share_id", "item_id"]),
    "run_with_secrets": (run_with_secrets, "Run a bash command with secrets injected as env vars (values are pass://SHARE_ID/ITEM_ID/FIELD). Output is masked by pass-cli.",
                         {"command": S, "env": {"type": "object", "additionalProperties": S}, "cwd": S, "timeout": {"type": "integer"}, "reason": S}, ["command", "env"]),
    "get_secret": (get_secret, "RETURNS THE SECRET VALUE to the model. Only use when the user explicitly asks and no secret-safe tool fits. field: password, username, email, note, or extra field name.",
                   {**ITEM, "field": S}, ["share_id", "item_id"]),
}


def handle(msg):
    m, mid = msg.get("method"), msg.get("id")
    if m == "initialize":
        res = {"protocolVersion": msg["params"].get("protocolVersion", "2025-06-18"),
               "capabilities": {"tools": {}}, "serverInfo": {"name": "proton-pass", "version": "0.1.0"}}
    elif m == "tools/list":
        res = {"tools": [{"name": n, "description": d, "inputSchema": {"type": "object", "properties": p, "required": r}}
                         for n, (_, d, p, r) in TOOLS.items()]}
    elif m == "tools/call":
        name, args = msg["params"]["name"], msg["params"].get("arguments") or {}
        try:
            out = TOOLS[name][0](args)
            res = {"content": [{"type": "text", "text": json.dumps(out, ensure_ascii=False, indent=1)}]}
        except Exception as e:
            res = {"content": [{"type": "text", "text": f"{type(e).__name__}: {e}"}], "isError": True}
    elif m == "ping":
        res = {}
    else:
        if mid is None:
            return None
        return {"jsonrpc": "2.0", "id": mid, "error": {"code": -32601, "message": f"unknown method {m}"}}
    return None if mid is None else {"jsonrpc": "2.0", "id": mid, "result": res}


def main():
    for line in sys.stdin:
        if line.strip():
            reply = handle(json.loads(line))
            if reply:
                sys.stdout.write(json.dumps(reply) + "\n"); sys.stdout.flush()


if __name__ == "__main__":
    main()
