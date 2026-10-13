import contextlib, http.server, os, socket, subprocess, tempfile, threading, time, urllib.request
from types import SimpleNamespace
from playwright.sync_api import sync_playwright
from harness import PASSWORD, Operator, error, start, write

PAGES = {
    "login.html": """<form id=search><input id=q name=q></form>
<form action=done.html><input id=user name=username><input id=pw type=password><button>Go</button></form>
<iframe srcdoc="<input id=fpw type=password>"></iframe>""",
    "stuck.html": """<form onsubmit="return false">
<input id=user name=username><input id=pw type=password><button>Go</button></form>""",
    "done.html": "<p>done</p>",
}
ITEM = {"share_id": "share1", "item_id": "item1", "reason": "log in"}


class Quiet(http.server.SimpleHTTPRequestHandler):
    def log_message(self, *args):
        pass


def serve(root):
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), lambda *a: Quiet(*a, directory=root))
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return f"http://127.0.0.1:{srv.server_address[1]}"


def launch(pw, url):
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    proc = subprocess.Popen([pw.chromium.executable_path, "--headless=new", f"--remote-debugging-port={port}",
                             f"--user-data-dir={tempfile.mkdtemp()}", "--no-first-run", "--no-default-browser-check",
                             url], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    for _ in range(100):
        try:
            urllib.request.urlopen(f"http://127.0.0.1:{port}/json/version", timeout=1)
            return proc, port
        except OSError:
            time.sleep(0.1)
    proc.kill()
    raise RuntimeError("Chromium did not open its CDP port")


def value(page, selector):
    return page.eval_on_selector(selector, "e => e.value")


def frame_value(page):
    return page.main_frame.child_frames[0].eval_on_selector("#fpw", "e => e.value")


@contextlib.contextmanager
def tab(lab, path):
    page = lab.ctx.new_page()
    page.goto(lab.good + path)
    try:
        yield page
    finally:
        page.close()


def server(lab):
    return start(urls=[f"{lab.good}/login.html"], PASS_CDP_PORT=str(lab.port))


def test_fill_skips_a_tab_on_another_origin_and_hides_its_url(lab):
    d, c = server(lab)
    op = Operator(d)
    try:
        got = error(c, "fill_login", **ITEM)
        assert got == "no open tab matches this item's websites (1 tabs open)", got
        assert op.prompts == [], op.prompts
        assert value(lab.phish, "#pw") == ""
    finally:
        op.close()
        c.close()


def test_fill_types_only_into_the_main_frame_password_of_the_item_origin(lab):
    d, c = server(lab)
    op = Operator(d)
    try:
        with tab(lab, "/login.html") as page:
            got = c.call("fill_login", **ITEM)
            assert got == {"filled": ["username", "password"], "submitted": False}, got
            assert op.prompts == [{"action": "fill", "title": "Bank", "origins": [lab.good],
                                   "submit": False, "reason": "log in"}], op.prompts
            fields = [value(page, "#user"), value(page, "#pw"), value(page, "#q"), frame_value(page)]
            assert fields == ["ada", PASSWORD, "", ""], fields
            assert value(lab.phish, "#pw") == ""
    finally:
        op.close()
        c.close()


def test_fill_submit_clears_a_password_the_page_kept(lab):
    d, c = server(lab)
    op = Operator(d)
    try:
        with tab(lab, "/stuck.html") as page:
            got = c.call("fill_login", submit=True, **ITEM)
            assert got == {"filled": ["username", "password"], "submitted": False}, got
            assert [value(page, "#user"), value(page, "#pw")] == ["ada", ""]
        with tab(lab, "/login.html") as page:
            got = c.call("fill_login", submit=True, **ITEM)
            assert got == {"filled": ["username", "password"], "submitted": True}, got
            assert page.url == f"{lab.good}/done.html?username=ada", page.url
    finally:
        op.close()
        c.close()


def test_fill_fails_closed_without_an_allow(lab):
    d, c = server(lab)
    try:
        with tab(lab, "/login.html") as page:
            assert (got := error(c, "fill_login", **ITEM)) == "approval helper is not running", got
            for reply in ({"op": "deny"}, {"op": "allow-net"}):
                op = Operator(d, reply)
                assert (got := error(c, "fill_login", **ITEM)) == "release denied", got
                op.close()
            assert [value(page, "#user"), value(page, "#pw")] == ["", ""]
    finally:
        c.close()


if __name__ == "__main__":
    root = tempfile.mkdtemp()
    for name, html in PAGES.items():
        write(root, name, html)
    good, bad = serve(root), serve(root)
    failed = 0
    with sync_playwright() as pw:
        chrome, port = launch(pw, f"{bad}/login.html")
        try:
            ctx = pw.chromium.connect_over_cdp(f"http://127.0.0.1:{port}").contexts[0]
            phish = ctx.pages[0]
            phish.wait_for_load_state()
            lab = SimpleNamespace(ctx=ctx, phish=phish, good=good, port=port)
            tests = [f for name, f in list(globals().items()) if name.startswith("test_")]
            for test in tests:
                try:
                    test(lab)
                except Exception as e:
                    failed += 1
                    print(f"FAIL {test.__name__}: {type(e).__name__}: {e}")
                else:
                    print(f"OK   {test.__name__}")
        finally:
            chrome.kill()
    if failed:
        raise SystemExit(f"{failed} of {len(tests)} fill tests failed")
    print(f"{len(tests)} fill tests OK")
