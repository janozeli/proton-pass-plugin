#!/usr/bin/env python3
import ipaddress, http.client, json, os, re, resource, shutil, signal, select, socket, stat, struct, subprocess, sys, termios, time, unicodedata
from urllib.parse import urlsplit
import idna

PASS_CLI = os.path.expanduser(os.environ.get("PASS_CLI", "~/.local/bin/pass-cli"))
PAT_FILE = os.path.expanduser(os.environ.get("PASS_PAT_FILE", "~/.config/pass-agent/pat"))
REASON = "proton-pass plugin"
AUTH_ERR = re.compile(r"requires an authenticated client|unauthori[sz]ed|session expired", re.I)
ENV_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
REF = re.compile(r"pass://([^/?#%]+)/([^/?#%]+)/([^/?#%]+)")
PROTOCOL = "2025-06-18"
SUPPORTED = {"2024-11-05", "2025-03-26", PROTOCOL}
FORBIDDEN = {"get_secret", "run_with_secrets", "command", "url_match", "url", "username_selector",
             "password_selector", "cdp_port", "cwd", "value", "password", "totp_uri"}
RESERVED_ENV = {"PATH", "HOME", "LD_PRELOAD", "LD_LIBRARY_PATH", "PROTON_PASS_SESSION_DIR", "PROTON_PASS_AGENT_REASON",
                "PROTON_PASS_PERSONAL_ACCESS_TOKEN", "PASS_PAT_FILE", "PASS_CLI"}
# pass-cli puts the resolved secrets in the environment it hands to bwrap, so the sandbox unsets
# names instead of clearing the environment.
SANDBOX = ("--unshare-user", "--unshare-pid", "--unshare-ipc", "--unshare-net", "--die-with-parent",
           *(arg for name in ("PROTON_PASS_SESSION_DIR", "PROTON_PASS_AGENT_REASON", "PROTON_PASS_PERSONAL_ACCESS_TOKEN",
                              "PASS_PAT_FILE", "PASS_CLI", "HOME") for arg in ("--unsetenv", name)),
           "--setenv", "HOME", "/tmp", "--setenv", "PATH", "/usr/bin:/bin",
           *(arg for path in ("/usr", "/bin", "/lib", "/lib64", "/etc/resolv.conf", "/etc/hosts",
                              "/etc/nsswitch.conf", "/etc/ssl") for arg in ("--ro-bind-try", path, path)),
           "--proc", "/proc", "--dev", "/dev", "--tmpfs", "/tmp", "--chdir", "/tmp", "--")
APPROVAL_TIMEOUT = 180
RUN_TIMEOUT = 300
REASON_LIMIT = 300
ARGV_LIMIT = 1024
RENAME = (
    "import ctypes,errno,json,os,sys\n"
    # Namespaces do not isolate inherited kernel keyrings. Install the filter
    # in this trusted trampoline before renaming secrets or executing user code.
    # libseccomp resolves native syscall numbers and rejects other ABIs by default.
    "sc=ctypes.CDLL('libseccomp.so.2')\n"
    "sc.seccomp_init.argtypes=[ctypes.c_uint32]\n"
    "sc.seccomp_init.restype=ctypes.c_void_p\n"
    "sc.seccomp_syscall_resolve_name.argtypes=[ctypes.c_char_p]\n"
    "sc.seccomp_rule_add.argtypes=[ctypes.c_void_p,ctypes.c_uint32,ctypes.c_int,ctypes.c_uint]\n"
    "sc.seccomp_load.argtypes=[ctypes.c_void_p]\n"
    "sc.seccomp_release.argtypes=[ctypes.c_void_p]\n"
    "sc.seccomp_release.restype=None\n"
    "ctx=sc.seccomp_init(0x7fff0000) # SCMP_ACT_ALLOW\n"
    "if not ctx: raise RuntimeError('seccomp initialization failed')\n"
    "try:\n"
    " for name in (b'add_key',b'request_key',b'keyctl'):\n"
    "  nr=sc.seccomp_syscall_resolve_name(name)\n"
    "  if nr<0 or sc.seccomp_rule_add(ctx,0x00050000|errno.EPERM,nr,0)!=0:\n"
    "   raise RuntimeError('seccomp rule failed')\n"
    " if sc.seccomp_load(ctx)!=0: raise RuntimeError('seccomp load failed')\n"
    "finally: sc.seccomp_release(ctx)\n"
    "keep={'PATH','HOME','PWD'}\n"
    "for src,dst in json.loads(sys.argv[1]):\n"
    " os.environ[dst]=os.environ.pop(src)\n"
    " keep.add(dst)\n"
    "for name in list(os.environ):\n"
    " if name not in keep: del os.environ[name]\n"
    "os.execv(sys.argv[2],sys.argv[2:])\n"
)
SESSION = None


class PassError(Exception):
    pass


def ensure_session():
    path = os.path.abspath(os.path.expanduser(os.environ.get("PROTON_PASS_SESSION_DIR") or "~/.local/share/pass-agent"))
    os.makedirs(os.path.dirname(path), exist_ok=True)
    try:
        os.mkdir(path, 0o700)
    except FileExistsError:
        pass
    st = os.lstat(path)
    if stat.S_ISLNK(st.st_mode):
        raise PassError("PROTON_PASS_SESSION_DIR must not be a symlink")
    if not stat.S_ISDIR(st.st_mode) or st.st_uid != os.getuid():
        raise PassError("PROTON_PASS_SESSION_DIR must be a directory owned by this user")
    if stat.S_IMODE(st.st_mode) != 0o700:
        os.chmod(path, 0o700)
    if os.path.islink(os.path.join(path, ".session")):
        raise PassError("PROTON_PASS_SESSION_DIR/.session must not be a symlink")
    return path


def cli_env(reason, extra=None):
    return {"PATH": os.environ.get("PATH", os.defpath), "PROTON_PASS_SESSION_DIR": SESSION,
            "PROTON_PASS_AGENT_REASON": reason, **(extra or {})}


def login():
    try:
        st = os.lstat(PAT_FILE)
    except OSError:
        raise PassError("PAT file cannot be read")
    if stat.S_ISLNK(st.st_mode):
        raise PassError("PAT file must not be a symlink")
    if not stat.S_ISREG(st.st_mode) or st.st_uid != os.getuid():
        raise PassError("PAT file must be a regular file owned by this user")
    if st.st_mode & 0o077:
        raise PassError("PAT file must not be accessible to group or others")
    with open(os.open(PAT_FILE, os.O_RDONLY | os.O_NOFOLLOW)) as f:
        token = f.read().strip()
    if not token:
        raise PassError("PAT file is empty")
    try:
        r = subprocess.run([PASS_CLI, "login"], env=cli_env(REASON, {"PROTON_PASS_PERSONAL_ACCESS_TOKEN": token}),
                           stdin=subprocess.DEVNULL, capture_output=True, timeout=60)
    except (OSError, subprocess.TimeoutExpired):
        raise PassError("pass-cli login failed")
    if r.returncode != 0:
        raise PassError("pass-cli login failed")


def cli(*args, reason=REASON, relogin=True):
    try:
        r = subprocess.run([PASS_CLI, *args], env=cli_env(reason), stdin=subprocess.DEVNULL, capture_output=True,
                           encoding="utf-8", errors="replace", timeout=120)
    except subprocess.TimeoutExpired:
        raise PassError(f"pass-cli {args[0]} timed out")
    except OSError:
        raise PassError("pass-cli failed to start")
    if r.returncode != 0:
        if relogin and AUTH_ERR.search(r.stderr):
            login()
            return cli(*args, reason=reason, relogin=False)
        raise PassError(f"pass-cli {args[0]} failed")
    return r.stdout


def cli_json(*args, **kw):
    try:
        data = json.loads(cli(*args, "--output", "json", **kw))
    except json.JSONDecodeError:
        raise PassError("pass-cli returned invalid JSON")
    if not isinstance(data, dict):
        raise PassError("pass-cli returned invalid JSON")
    return data


def item_args(a):
    return ["--share-id", a["share_id"], "--item-id", a["item_id"]]


def view_item(a):
    return cli_json("item", "view", *item_args(a), reason=a.get("reason") or REASON)["item"]


def login_content(item):
    c = item["content"]["content"]
    return c.get("Login") if isinstance(c, dict) else None


def browser_origin(url):
    # Accept a conservative subset of browser URLs. Never let urlsplit silently
    # strip controls or interpret a backslash differently from a browser.
    if not isinstance(url, str) or any(ord(c) <= 32 or c == "\\" for c in url):
        return None
    try:
        u = urlsplit(url if "://" in url else "https://" + url)
        default = {"https": 443, "http": 80}.get(u.scheme)
        if not default or not u.hostname:
            return None
        port = u.port
        authority = u.netloc.rsplit("@", 1)[-1]
        if ":" in u.hostname:
            if not re.fullmatch(r"\[[0-9a-fA-F:.]+\](?::[0-9]*)?", authority):
                return None
            host = f"[{ipaddress.IPv6Address(u.hostname)}]"
        else:
            host = idna.encode(u.hostname, uts46=True, transitional=False).decode("ascii")
            # WHATWG also accepts legacy IPv4 spellings; reject those rather
            # than treating a numeric host as an ordinary DNS name.
            last = host.rstrip(".").rsplit(".", 1)[-1]
            if last.isdigit() or re.fullmatch(r"0x[0-9a-f]*", last):
                if str(ipaddress.IPv4Address(host)) != host:
                    return None
    except (ValueError, idna.IDNAError):
        return None
    return f"{u.scheme}://{host}" + (f":{port}" if port not in (None, default) else "")


def reason_key(value):
    text = unicodedata.normalize("NFKC", value)
    return "".join(ch for ch in text if unicodedata.category(ch) != "Cf").casefold()


def shown(value, limit):
    if len(value) <= limit:
        return repr(value)
    return repr(value[:limit]) + f" (truncated, {len(value)} characters)"


def peer_uid(sock):
    return struct.unpack("3i", sock.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i")))[1]


def release(prompt):
    with socket.socket(socket.AF_UNIX) as s:
        s.settimeout(APPROVAL_TIMEOUT)
        try:
            s.connect(os.path.join(SESSION, "approve.sock"))
        except OSError:
            raise PassError("approval unavailable")
        try:
            if peer_uid(s) != os.getuid():
                raise PassError("release denied")
            s.sendall(json.dumps(prompt).encode() + b"\n")
            reply = json.loads(s.makefile("rb").readline(4096))
        except (OSError, ValueError):
            raise PassError("release denied")
    op = reply.get("op") if isinstance(reply, dict) else None
    if op == "allow" or (op == "allow-net" and prompt["action"] == "run"):
        return op
    raise PassError("release denied")


def render(p):
    if p["action"] not in ("fill", "totp", "run"):
        raise ValueError("unknown action")
    lines = ["proton-pass release request", f"  action:  {p['action']}"]
    if p["action"] == "run":
        if any(len(a) > ARGV_LIMIT for a in p["argv"]):
            raise ValueError("argv exceeds the display limit")
        lines.append("  argv:    " + "\n           ".join(repr(a) for a in p["argv"]))
        lines.append("  env:     " + "\n           ".join(f"{n!r} = {r!r} (field {f!r} of {t!r})" for n, r, t, f in p["env"]))
        lines.append("  network: off (type approve-net to allow it)")
    else:
        lines.append(f"  item:    {p['title']!r}")
    if p["action"] == "fill":
        lines += [f"  origin:  {p['origin']!r}", f"  submit:  {p['submit']!r}"]
    lines += [f"  reason:  {shown(p['reason'], REASON_LIMIT)}", "Type approve to release. Anything else denies."]
    return "\n".join(lines)


def read_approval_prompt(conn, deadline):
    data = bytearray()
    while len(data) < 65536:
        remaining = deadline - time.monotonic()
        if remaining <= 0 or not select.select([conn], [], [], remaining)[0]:
            raise ValueError("request expired")
        chunk = conn.recv(65536 - len(data))
        if not chunk:
            raise ValueError("request disconnected")
        data.extend(chunk)
        if b"\n" in data:
            return json.loads(data)
    raise ValueError("request too large")


def read_approval_answer(conn, tty_in, deadline):
    answer = bytearray()
    while len(answer) < 4096:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return None
        ready, _, _ = select.select([conn, tty_in], [], [], remaining)
        # The request protocol has no further client messages. Readability here
        # means disconnection or unexpected data; either invalidates approval.
        if not ready or conn in ready or time.monotonic() >= deadline:
            return None
        chunk = os.read(tty_in.fileno(), 4096 - len(answer))
        if not chunk:
            return None
        answer.extend(chunk)
        if b"\n" in answer:
            return answer.decode("utf-8", errors="replace").strip()
    return None


def serve_approvals():
    path = os.path.join(SESSION, "approve.sock")
    if os.path.islink(path):
        raise PassError("approve.sock must not be a symlink")
    if os.path.lexists(path):
        if not stat.S_ISSOCK(os.lstat(path).st_mode):
            raise PassError("approve.sock is not a socket")
        with socket.socket(socket.AF_UNIX) as probe:
            if probe.connect_ex(path) == 0:
                raise PassError("another approval helper is running")
        os.unlink(path)
    try:
        tty_in, tty = open("/dev/tty"), open("/dev/tty", "w")
    except OSError:
        raise PassError("approve needs a terminal (/dev/tty)")
    srv = socket.socket(socket.AF_UNIX)
    srv.bind(path)
    srv.listen()
    print(f"proton-pass approval helper listening on {path!r}", file=tty, flush=True)
    while True:
        conn, _ = srv.accept()
        with conn:
            try:
                if peer_uid(conn) != os.getuid():
                    continue
                deadline = time.monotonic() + APPROVAL_TIMEOUT
                conn.settimeout(10)
                prompt = read_approval_prompt(conn, min(deadline, time.monotonic() + 10))
                if time.monotonic() >= deadline or select.select([conn], [], [], 0)[0]:
                    continue
                text = render(prompt)
                termios.tcflush(tty_in, termios.TCIFLUSH)
                print(text, file=tty, flush=True)
                line = read_approval_answer(conn, tty_in, deadline)
                if line is None:
                    print("Request expired or disconnected; denied.", file=tty, flush=True)
                op = "allow-net" if line == "approve-net" and prompt["action"] == "run" else "allow" if line == "approve" else "deny"
                conn.sendall(json.dumps({"op": op}).encode() + b"\n")
            except (OSError, ValueError, KeyError, TypeError):
                pass


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
    it = view_item(a)
    c = it["content"]
    lg = login_content(it) or {}
    return {
        "title": c["title"], "share_id": it["share_id"], "item_id": it["id"],
        "type": next(iter(c["content"])) if isinstance(c["content"], dict) else c["content"],
        "urls": [u for u in map(browser_origin, lg.get("urls", [])) if u],
        "username": lg.get("username", ""), "email": lg.get("email", ""),
        "has_password": bool(lg.get("password")), "has_totp": bool(lg.get("totp_uri")),
        "extra_field_names": [f.get("name") for f in c.get("extra_fields", [])],
        "has_note": bool(c.get("note")),
    }


def get_totp(a):
    release({"action": "totp", "title": view_item(a)["content"]["title"], "reason": a["reason"]})
    data = cli_json("item", "totp", *item_args(a), reason=a["reason"])
    code = data.get("totp")
    if not isinstance(code, str) or not re.fullmatch(r"[0-9]{6,8}", code):
        raise PassError("item has no TOTP code")
    return {"code": code}


FILL = """function(arg) {
  if (location.origin !== arg.origin) return null;
  const eligible = el => {
    const box = el.getBoundingClientRect();
    return el.isConnected && !el.matches(':disabled') && !el.closest('[inert]') &&
      !el.readOnly && box.width > 0 && box.height > 0 &&
      el.checkVisibility({visibilityProperty: true, opacityProperty: true});
  };
  const inputs = () => [...document.querySelectorAll("input")].filter(eligible);
  const shown = inputs();
  let pw = shown.find(el => el.type === "password");
  if (!pw) return [];
  const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value").set;
  const set = (el, v) => {
    setter.call(el, v);
    el.dispatchEvent(new Event("input", {bubbles: true}));
    el.dispatchEvent(new Event("change", {bubbles: true}));
  };
  const before = shown.slice(0, shown.indexOf(pw)).filter(el => el.form === pw.form && ["text", "email", "tel"].includes(el.type));
  const user = before.find(el => /username|email/.test(el.autocomplete)) || before[before.length - 1];
  const filled = [];
  if (user && arg.username) {
    set(user, arg.username);
    if (eligible(user) && user.value === arg.username) filled.push("username");
  }
  // Username events may synchronously replace, hide, or disable the target.
  pw = inputs().find(el => el.type === "password");
  if (!pw) return [];
  set(pw, arg.password);
  pw.focus();
  // Input, change, and focus handlers can also invalidate the completed fill.
  if (!eligible(pw) || pw.type !== "password" || pw.value !== arg.password) return [];
  filled.push("password");
  return filled;
}"""

def cdp_endpoint():
    try:
        port = int(os.environ.get("PASS_CDP_PORT", "9222"))
    except ValueError:
        raise PassError("PASS_CDP_PORT is invalid")
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    try:
        conn.request("GET", "/json/version")
        ws = urlsplit(json.loads(conn.getresponse().read())["webSocketDebuggerUrl"])
    except (OSError, ValueError, KeyError, TypeError, http.client.HTTPException):
        raise PassError(f"no browser is listening on CDP port {port}")
    finally:
        conn.close()
    if ws.hostname != "127.0.0.1":
        raise PassError("the browser's CDP address is not 127.0.0.1")
    browser_id = ws.path.removeprefix("/devtools/browser/")
    if not re.fullmatch(r"[A-Za-z0-9-]+", browser_id):
        raise PassError("the browser's CDP address is invalid")
    return f"ws://127.0.0.1:{port}/devtools/browser/{browser_id}"


def fill_login(a):
    if a.get("submit", False):
        raise PassError("automatic submission is unavailable; fill without submit and submit manually")
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        raise PassError("fill_login needs the Playwright Python package")
    item = view_item(a)
    lg = login_content(item)
    if not lg or not lg.get("password"):
        raise PassError("item is not a Login with a password")
    origins = {browser_origin(u) for u in lg.get("urls", [])} - {None}
    if not origins:
        raise PassError("item has no website to fill")
    submit = a.get("submit", False)
    endpoint = cdp_endpoint()
    with sync_playwright() as p:
        browser = p.chromium.connect_over_cdp(endpoint)
        try:
            pages = [pg for ctx in browser.contexts for pg in ctx.pages]
            hits = [pg for pg in pages if browser_origin(pg.url) in origins]
            if len(hits) != 1:
                which = "more than one" if hits else "no"
                raise PassError(f"{which} open tab matches this item's websites ({len(pages)} tabs open)")
            page, allowed = hits[0], browser_origin(hits[0].url)
            release({"action": "fill", "title": item["content"]["title"], "origin": allowed, "submit": submit,
                     "reason": a["reason"]})
            secret = {"origin": allowed, "username": lg.get("username") or lg.get("email") or "",
                      "password": lg["password"], "submit": submit}
            got = isolated(page, FILL, secret)
            if got is None:
                raise PassError(f"no open tab matches this item's websites ({len(pages)} tabs open)")
            filled = [f for f in ("username", "password") if isinstance(got, list) and f in got]
            if not filled:
                raise PassError("no password field on the matching tab")
        finally:
            browser.close()
    return {"filled": filled, "submitted": submit}


def isolated(page, source, arg):
    try:
        session = page.context.new_cdp_session(page)
        frame = session.send("Page.getFrameTree")["frameTree"]["frame"]["id"]
        world = session.send("Page.createIsolatedWorld", {"frameId": frame, "worldName": "proton-pass"})
        result = session.send("Runtime.callFunctionOn", {
            "functionDeclaration": source,
            "executionContextId": world["executionContextId"],
            "arguments": [{"value": arg}],
            "returnByValue": True,
        })
    except (OSError, KeyError, TypeError):
        raise PassError("internal error")
    if result.get("exceptionDetails") is not None:
        raise PassError("internal error")
    return result.get("result", {}).get("value")


def ref_parts(ref):
    m = REF.fullmatch(ref)
    return m.groups() if m and not any(map(bad_token, m.groups())) else None


def check_core_policy():
    # RLIMIT_CORE is ignored for external collectors. Even collectors that
    # discard the memory image may journal attacker-controlled process metadata.
    try:
        with open("/proc/sys/kernel/core_pattern") as f:
            pattern = f.read()
    except OSError:
        raise PassError("run refused: cannot verify core dump policy")
    if pattern.startswith(("|", "@")):
        raise PassError("run refused: external core dump collector is not supported")


def disable_core_dumps():
    # Runs in the child before pass-cli resolves any references. Both limits
    # survive exec and fork; the sandbox cannot raise the hard limit again.
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    check_core_policy()


def run_approved(a):
    bwrap = shutil.which("bwrap")
    if not bwrap:
        raise PassError("bwrap is not installed")
    check_core_policy()
    argv, env = tuple(a["argv"]), dict(a["env"])
    shown, bindings = [], []
    for index, (name, ref) in enumerate(env.items()):
        share, item, field = ref_parts(ref)
        shown.append([name, ref, view_item({"share_id": share, "item_id": item})["content"]["title"], field])
        bindings.append((f"PP{index}", name, ref))
    op = release({"action": "run", "argv": list(argv), "env": shown, "reason": a["reason"]})
    sandbox = SANDBOX if op == "allow" else tuple(arg for arg in SANDBOX if arg != "--unshare-net")
    launch = ["/usr/bin/python3", "-c", RENAME, json.dumps([[src, dst] for src, dst, _ in bindings])]
    try:
        p = subprocess.Popen([PASS_CLI, "run", "--", bwrap, *sandbox, *launch, *argv],
                             env=cli_env(REASON, {src: ref for src, _, ref in bindings}),
                             stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                             start_new_session=True, preexec_fn=disable_core_dumps)
    except subprocess.SubprocessError:
        raise PassError("run refused: cannot disable core dumps")
    except OSError:
        raise PassError("pass-cli failed to start")
    try:
        return {"exit_code": p.wait(timeout=RUN_TIMEOUT)}
    except subprocess.TimeoutExpired:
        os.killpg(p.pid, signal.SIGKILL)
        p.wait()
        raise PassError("run timed out")


def bad_token(value):
    return not value or value.startswith("-") or any(c in value for c in "\n\r\x00")


KIND = {"string": "a string", "integer": "an integer", "boolean": "a boolean",
        "array": "an array of strings", "object": "an object of strings"}


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
        t = props[k]["type"]
        ok = {"string": isinstance(v, str), "boolean": isinstance(v, bool),
              "integer": isinstance(v, int) and not isinstance(v, bool),
              "array": isinstance(v, list) and all(isinstance(x, str) for x in v),
              "object": isinstance(v, dict) and all(isinstance(x, str) for x in v.values())}[t]
        if not ok:
            raise PassError(f"{k} must be {KIND[t]}")
        if "enum" in props[k] and v not in props[k]["enum"]:
            raise PassError(f"{k} must be one of: " + ", ".join(props[k]["enum"]))
    for k in ("share_id", "item_id"):
        if k in args and bad_token(args[k]):
            raise PassError(f"{k} is invalid")
    if args.get("vault") and bad_token(args["vault"]):
        raise PassError("vault is invalid")
    if "\x00" in args.get("reason", "") or "pass://" in reason_key(args.get("reason", "")):
        raise PassError("reason is invalid")
    if args.get("limit", 0) < 0:
        raise PassError("limit must be >= 0")
    if "argv" in args:
        if not args["argv"]:
            raise PassError("argv must not be empty")
        if not os.path.isabs(args["argv"][0]):
            raise PassError("argv[0] must be an absolute path")
        if any(len(part) > ARGV_LIMIT for part in args["argv"]):
            raise PassError(f"argv arguments must be at most {ARGV_LIMIT} characters")
        if any("\x00" in part for part in args["argv"]):
            raise PassError("argv is invalid")
    if "env" in args:
        if not args["env"]:
            raise PassError("env must not be empty")
        for k, ref in args["env"].items():
            if not ENV_NAME.fullmatch(k):
                raise PassError(f"invalid env name {k}")
            if k in RESERVED_ENV or re.fullmatch(r"PP\d+", k):
                raise PassError(f"env name {k} is reserved")
            if not ref_parts(ref):
                raise PassError(f"env {k} must be a pass://SHARE_ID/ITEM_ID/FIELD reference")


S = {"type": "string"}
WHY = {"type": "string", "description": "Why access is needed. Shown to the operator and stored in Proton's audit log."}
ITEM = {"share_id": S, "item_id": S, "reason": WHY}
TOOLS = {
    "list_vaults": (list_vaults, "List Proton Pass vaults (names and ids).", {}, []),
    "search_items": (search_items, "Search items by title (case-insensitive substring). Metadata only, no secrets.",
                     {"query": S, "vault": S, "type": {"type": "string", "enum": ["login", "note", "alias", "credit-card", "identity", "ssh-key", "wifi", "custom"]}, "limit": {"type": "integer"}}, []),
    "describe_item": (describe_item, "Item metadata: website origins (scheme, host, and port only), username, email, has_password, has_totp, extra field names. No path, query, fragment, or secret values.", ITEM, ["share_id", "item_id"]),
    "get_totp": (get_totp, "Current TOTP code from the item's totp field, after the operator approves in the approval terminal. Returns only the digits.", ITEM, ["share_id", "item_id", "reason"]),
    "fill_login": (fill_login, "After the operator approves, type the item's username and password into the one open Chrome tab whose origin equals one of the item's saved websites. The password never comes back. Automatic submission is refused: omit submit or set it to false, then submit manually. submitted is always false.",
                   {**ITEM, "submit": {"type": "boolean"}}, ["share_id", "item_id", "reason"]),
    "run_approved": (run_approved, "After the operator approves this exact argv, run it in a bubblewrap sandbox with pass://SHARE_ID/ITEM_ID/FIELD references injected as environment variables. The sandbox sees /usr, /bin, and /lib read-only, /etc name-service and TLS files, and an empty /tmp. It has no network unless the operator allows it. Output is discarded. Returns only the exit code.",
                     {"argv": {"type": "array", "items": S, "description": "Absolute path of the program, then its arguments. No shell is added."},
                      "env": {"type": "object", "additionalProperties": S, "description": "Variable name to pass://SHARE_ID/ITEM_ID/FIELD reference."},
                      "reason": WHY}, ["argv", "env", "reason"]),
}


def check_census():
    for name, (_, _, props, _) in TOOLS.items():
        hit = FORBIDDEN & {name, *props}
        if hit:
            raise PassError("forbidden tool or parameter name: " + ", ".join(sorted(hit)))


def _result(mid, result):
    return {"jsonrpc": "2.0", "id": mid, "result": result}


def _error(mid, code, message):
    return {"jsonrpc": "2.0", "id": mid, "error": {"code": code, "message": message}}


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
                             "serverInfo": {"name": "proton-pass", "version": "0.2.0"}})
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
            res = {"content": [{"type": "text", "text": json.dumps(TOOLS[name][0](args), ensure_ascii=False, indent=1)}]}
        except PassError as e:
            res = {"content": [{"type": "text", "text": e.args[0]}], "isError": True}
        except Exception:
            res = {"content": [{"type": "text", "text": "internal error"}], "isError": True}
        return _result(mid, res)
    if method == "ping":
        return _result(mid, {})
    return _error(mid, -32601, f"unknown method {method}")


def write(obj):
    sys.stdout.write(json.dumps(obj) + "\n")
    sys.stdout.flush()


def main():
    global SESSION
    try:
        if sys.argv[1:] == ["approve"]:
            SESSION = ensure_session()
            return serve_approvals()
        check_census()
        SESSION = ensure_session()
    except PassError as e:
        sys.exit(f"proton-pass: {e.args[0]}")
    except OSError as e:
        sys.exit(f"proton-pass: {e.strerror or 'startup failed'}")
    except KeyboardInterrupt:
        return
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
