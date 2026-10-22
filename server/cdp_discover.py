"""Find a loopback Chrome DevTools endpoint.

An explicit PASS_CDP_PORT wins. Otherwise this scans browser command lines and
DevToolsActivePort files. Several live browsers are disambiguated by an open
page on the item's origin; a tie is an error and does not guess.
"""
import http.client, json, os, re
from urllib.parse import urlsplit


class DiscoverError(Exception):
    pass


def parse_port(value):
    try:
        port = int(value)
    except (TypeError, ValueError):
        raise DiscoverError("PASS_CDP_PORT is invalid")
    if not 1 <= port <= 65535:
        raise DiscoverError("PASS_CDP_PORT is invalid")
    return port


def ports_from_cmdline(raw):
    parts = [part.decode("utf-8", "replace") for part in raw.split(b"\0") if part]
    blob = " ".join(parts).lower()
    if not any(name in blob for name in ("chrome", "chromium", "msedge", "brave")):
        return []
    found = []
    for index, arg in enumerate(parts):
        value = None
        if arg.startswith("--remote-debugging-port="):
            value = arg.split("=", 1)[1]
        elif arg == "--remote-debugging-port" and index + 1 < len(parts):
            value = parts[index + 1]
        if value and value.isdigit() and int(value) > 0:
            found.append(int(value))
    return found


def port_from_devtools(text):
    line = text.splitlines()[0].strip() if text else ""
    if line.isdigit() and int(line) > 0:
        return int(line)
    return None


def _walk_devtools(root, max_depth):
    if not os.path.isdir(root):
        return
    base = root.rstrip(os.sep).count(os.sep)
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False, onerror=lambda _e: None):
        if dirpath.count(os.sep) - base >= max_depth:
            dirnames.clear()
        if "DevToolsActivePort" in filenames:
            yield os.path.join(dirpath, "DevToolsActivePort")


def devtools_paths(home):
    roots = [
        os.path.join(home, ".config", "google-chrome"),
        os.path.join(home, ".config", "google-chrome-beta"),
        os.path.join(home, ".config", "google-chrome-unstable"),
        os.path.join(home, ".config", "chromium"),
        os.path.join(home, ".config", "chromium-browser"),
        os.path.join(home, ".config", "microsoft-edge"),
        os.path.join(home, ".config", "BraveSoftware"),
    ]
    for root in roots:
        yield from _walk_devtools(root, 4)
    for root in ("/tmp", "/dev/shm"):
        yield from _walk_devtools(root, 2)


def read_devtools_port(path):
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    except OSError:
        return None
    try:
        with os.fdopen(fd) as handle:
            return port_from_devtools(handle.read(256))
    except OSError:
        return None


def live_cmdlines():
    try:
        entries = os.listdir("/proc")
    except OSError:
        return
    for pid in entries:
        if not pid.isdigit():
            continue
        try:
            with open(f"/proc/{pid}/cmdline", "rb") as handle:
                yield handle.read()
        except OSError:
            continue


def scan_ports(proc_cmdlines=None, devtools=None, home=None):
    ports = []
    for raw in live_cmdlines() if proc_cmdlines is None else proc_cmdlines:
        ports.extend(ports_from_cmdline(raw))
    paths = devtools if devtools is not None else devtools_paths(home or os.path.expanduser("~"))
    for path in paths:
        port = read_devtools_port(path)
        if port:
            ports.append(port)
    unique = []
    for port in ports:
        if port not in unique:
            unique.append(port)
    return unique


def _http_json(port, path, timeout):
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=timeout)
    try:
        conn.request("GET", path)
        payload = json.loads(conn.getresponse().read().decode("utf-8", "replace"))
    finally:
        conn.close()
    return payload


def connect(port, timeout=5):
    try:
        payload = _http_json(port, "/json/version", timeout)
        ws = urlsplit(payload["webSocketDebuggerUrl"])
    except (OSError, ValueError, KeyError, TypeError, http.client.HTTPException, UnicodeError):
        raise DiscoverError(f"no browser is listening on CDP port {port}")
    if ws.hostname != "127.0.0.1":
        raise DiscoverError("the browser's CDP address is not 127.0.0.1")
    browser_id = ws.path.removeprefix("/devtools/browser/")
    if not re.fullmatch(r"[A-Za-z0-9-]+", browser_id):
        raise DiscoverError("the browser's CDP address is invalid")
    return f"ws://127.0.0.1:{port}/devtools/browser/{browser_id}"


def page_urls(port):
    try:
        payload = _http_json(port, "/json/list", 1)
    except (OSError, ValueError, http.client.HTTPException, UnicodeError):
        return []
    if not isinstance(payload, list):
        return []
    return [item.get("url") or "" for item in payload if isinstance(item, dict) and item.get("type") == "page"]


def discover_cdp(env_port, origins, origin_of, candidates=None):
    if env_port not in (None, ""):
        return connect(parse_port(env_port))
    ports = scan_ports() if candidates is None else list(candidates)
    verified = []
    for port in ports:
        try:
            verified.append((port, connect(port, timeout=1)))
        except DiscoverError:
            continue
    if not verified:
        raise DiscoverError(
            "no Chrome with remote debugging is listening on 127.0.0.1. "
            "Start Chrome with --remote-debugging-port, or set PASS_CDP_PORT.")
    if len(verified) == 1:
        return verified[0][1]
    matched = []
    wanted = set(origins)
    for port, endpoint in verified:
        if any(origin_of(url) in wanted for url in page_urls(port)):
            matched.append((port, endpoint))
    if len(matched) == 1:
        return matched[0][1]
    shown = ", ".join(str(port) for port, _ in (matched or verified))
    raise DiscoverError(
        "more than one Chrome with remote debugging is listening on 127.0.0.1 "
        f"(ports {shown}). Open the item's website in one of them, or set PASS_CDP_PORT.")
