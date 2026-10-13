import contextlib, http.server, json, os, socket, subprocess, tempfile, threading, time, urllib.request
from types import SimpleNamespace
from playwright.sync_api import sync_playwright
from harness import PASSWORD, Operator, error, start, write

PAGES = {
    "login.html": """<form id=search><input id=q name=q></form>
<form action=done.html><input id=user name=username><input id=hpw type=password hidden><input id=pw type=password>
<button>Go</button></form>
<iframe srcdoc="<input id=fpw type=password>"></iframe>""",
    "stuck.html": """<form onsubmit="return false">
<input id=user name=username><input id=pw type=password><button>Go</button></form>""",
    "done.html": "<p>done</p>",
    "kept.html": "<input id=pw type=password value=leftover>",
    "patched.html": """<script>
Array.prototype.includes = () => true; Array.prototype.indexOf = () => 0;
window.__captured = [];
const origEval = window.eval;
window.eval = function(src) {
  const fn = origEval.call(window, src);
  if (typeof fn !== "function") return fn;
  return function(...args) {
    try { window.__captured.push(JSON.stringify(args)); } catch (e) {}
    return fn.apply(this, args);
  };
};
</script>
<form><input id=user name=username><input id=pw type=password><button>Go</button></form>""",
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


def server(lab, port=None):
    return start(urls=[f"{lab.good}/login.html"], PASS_CDP_PORT=str(port or lab.port))


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


def test_fill_refuses_two_matching_tabs(lab):
    d, c = server(lab)
    op = Operator(d)
    try:
        with tab(lab, "/login.html") as one, tab(lab, "/stuck.html") as two:
            got = error(c, "fill_login", **ITEM)
            assert got == "more than one open tab matches this item's websites (3 tabs open)", got
            assert op.prompts == [], op.prompts
            assert [value(one, "#pw"), value(two, "#pw")] == ["", ""]
    finally:
        op.close()
        c.close()


def test_fill_types_only_into_the_visible_main_frame_password_of_the_item_origin(lab):
    d, c = server(lab)
    op = Operator(d)
    try:
        with tab(lab, "/login.html") as page:
            got = c.call("fill_login", **ITEM)
            assert got == {"filled": ["username", "password"], "submitted": False}, got
            assert op.prompts == [{"action": "fill", "title": "Bank", "origin": lab.good,
                                   "submit": False, "reason": "log in"}], op.prompts
            fields = [value(page, s) for s in ("#user", "#pw", "#hpw", "#q")] + [frame_value(page)]
            assert fields == ["ada", PASSWORD, "", "", ""], fields
            assert value(lab.phish, "#pw") == ""
    finally:
        op.close()
        c.close()


def test_fill_submit_presses_enter_and_clears_the_password_only_off_origin(lab):
    d, c = server(lab)
    op = Operator(d)
    try:
        with tab(lab, "/stuck.html") as page:
            got = c.call("fill_login", submit=True, **ITEM)
            assert got == {"filled": ["username", "password"], "submitted": True}, got
            assert [value(page, "#user"), value(page, "#pw")] == ["ada", PASSWORD]
        with tab(lab, "/login.html") as page:
            got = c.call("fill_login", submit=True, **ITEM)
            assert got == {"filled": ["username", "password"], "submitted": True}, got
            page.wait_for_url(f"{lab.good}/done.html?username=ada", timeout=5000)
    finally:
        op.close()
        c.close()


def test_fill_rechecks_the_origin_after_approval(lab):
    d, c = server(lab)
    gate = threading.Event()
    op = Operator(d, gate=gate)
    try:
        with tab(lab, "/login.html") as page:
            c.send({"jsonrpc": "2.0", "id": 70, "method": "tools/call",
                    "params": {"name": "fill_login", "arguments": ITEM}})
            for _ in range(200):
                if op.prompts:
                    break
                time.sleep(0.05)
            page.goto(f"{lab.bad}/patched.html")
            assert page.evaluate("() => window.__captured.length") >= 1
            gate.set()
            got = c.read()["result"]
            assert got == {"content": [{"type": "text", "text": "no open tab matches this item's websites (2 tabs open)"}],
                           "isError": True}, got
            assert [value(page, "#user"), value(page, "#pw")] == ["", ""]
            captured = page.evaluate("() => window.__captured.slice()")
            assert all(PASSWORD not in item for item in captured), captured
    finally:
        op.close()
        c.close()


def test_fill_refuses_a_cdp_endpoint_off_loopback(lab):
    class Version(Quiet):
        def do_GET(self):
            body = json.dumps({"webSocketDebuggerUrl": f"ws://evil.example:{lab.port}/devtools/browser/x"}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Version)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    d, c = server(lab, srv.server_address[1])
    op = Operator(d)
    try:
        assert (got := error(c, "fill_login", **ITEM)) == "the browser's CDP address is not 127.0.0.1", got
        assert op.prompts == [], op.prompts
    finally:
        op.close()
        c.close()
        srv.shutdown()


def test_fill_submit_refuses_a_cross_origin_form_action(lab):
    d, c = server(lab)
    op = Operator(d)
    try:
        with tab(lab, "/away.html") as page:
            got = error(c, "fill_login", submit=True, **ITEM)
            assert got == "form action origin does not match", got
            assert page.url.startswith(lab.good + "/away.html"), page.url
            assert PASSWORD not in page.content()
    finally:
        op.close()
        c.close()


def test_fill_submit_clears_every_field_that_held_the_password(lab):
    d, c = server(lab)
    op = Operator(d)
    try:
        with tab(lab, "/copy.html") as page:
            got = c.call("fill_login", submit=True, **ITEM)
            assert got == {"filled": ["username", "password"], "submitted": True}, got
            page.wait_for_url(f"{lab.bad}/landed.html", timeout=5000)
            assert [value(page, "#pw"), value(page, "#copy")] == ["", ""], [value(page, "#pw"), value(page, "#copy")]
    finally:
        op.close()
        c.close()


def test_fill_fails_closed_without_an_allow(lab):
    d, c = server(lab)
    try:
        with tab(lab, "/login.html") as page:
            assert (got := error(c, "fill_login", **ITEM)) == "approval unavailable", got
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
    write(root, "away.html", f"""<form action="{bad}/kept.html">
<input id=user name=username><input id=pw type=password><button>Go</button></form>""")
    write(root, "copy.html", f"""<form action="done.html" onsubmit="location.href='{bad}/landed.html'; return false;">
<input id=user name=username><input id=pw type=password><button>Go</button></form>""")
    write(root, "landed.html", f"""<input id=pw type=password value=leftover>
<input id=copy type=text value="{PASSWORD}">""")
    failed = 0
    with sync_playwright() as pw:
        chrome, port = launch(pw, f"{bad}/login.html")
        try:
            ctx = pw.chromium.connect_over_cdp(f"http://127.0.0.1:{port}").contexts[0]
            phish = ctx.pages[0]
            phish.wait_for_load_state()
            lab = SimpleNamespace(ctx=ctx, phish=phish, good=good, bad=bad, port=port)
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
