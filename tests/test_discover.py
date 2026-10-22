import json, os, sys, threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "server"))
from cdp_discover import DiscoverError, discover_cdp, port_from_devtools, ports_from_cmdline, scan_ports


def origin_of(url):
    if url.startswith("https://bank.example"):
        return "https://bank.example"
    return None


class Browser(BaseHTTPRequestHandler):
    def do_GET(self):
        port = self.server.server_address[1]
        if self.path == "/json/version":
            host = getattr(self.server, "ws_host", "127.0.0.1")
            body = json.dumps({"webSocketDebuggerUrl": f"ws://{host}:{port}/devtools/browser/abc-1"}).encode()
        elif self.path == "/json/list":
            body = json.dumps([{"type": "page", "url": self.server.page_url}, {"type": "browser", "url": ""}]).encode()
        else:
            self.send_error(404)
            return
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


def serve(url, host="127.0.0.1"):
    server = ThreadingHTTPServer(("127.0.0.1", 0), Browser)
    server.page_url = url
    server.ws_host = host
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


def test_cmdline_and_devtools_port_parsing():
    raw = b"/opt/google/chrome/chrome\0--remote-debugging-port=9333\0--other\0"
    spaced = b"chromium\0--remote-debugging-port\09344\0"
    ignored = b"/usr/bin/python3\0--remote-debugging-port=9335\0"
    zero = b"chrome\0--remote-debugging-port=0\0"
    assert ports_from_cmdline(raw) == [9333]
    assert ports_from_cmdline(spaced) == [9344]
    assert ports_from_cmdline(ignored) == []
    assert ports_from_cmdline(zero) == []
    assert port_from_devtools("9333\n/devtools/browser/abc\n") == 9333
    assert port_from_devtools("0\n") is None
    root = os.path.join("/tmp", f"devtools-scan-{os.getpid()}")
    os.makedirs(root, exist_ok=True)
    with open(os.path.join(root, "DevToolsActivePort"), "w") as handle:
        handle.write("9456\n/devtools/browser/abc\n")
    assert scan_ports(proc_cmdlines=[raw], devtools=[os.path.join(root, "DevToolsActivePort")]) == [9333, 9456]
    os.remove(os.path.join(root, "DevToolsActivePort"))
    os.rmdir(root)


def test_explicit_port_overrides_other_candidates_and_rejects_a_non_loopback_socket():
    good = serve("https://bank.example/login")
    evil = serve("https://bank.example/login", host="evil.example")
    try:
        got = discover_cdp(str(good.server_address[1]), {"https://bank.example"}, origin_of, candidates=[evil.server_address[1]])
        assert got == f"ws://127.0.0.1:{good.server_address[1]}/devtools/browser/abc-1", got
        try:
            discover_cdp(str(evil.server_address[1]), {"https://bank.example"}, origin_of, candidates=[good.server_address[1]])
        except DiscoverError as exc:
            assert str(exc) == "the browser's CDP address is not 127.0.0.1", exc
        else:
            raise AssertionError("off-loopback endpoint was accepted")
        try:
            discover_cdp("nope", set(), origin_of)
        except DiscoverError as exc:
            assert str(exc) == "PASS_CDP_PORT is invalid"
        else:
            raise AssertionError("invalid port was accepted")
    finally:
        good.shutdown()
        evil.shutdown()


def test_no_browser_is_an_error():
    try:
        discover_cdp(None, {"https://bank.example"}, origin_of, candidates=[])
    except DiscoverError as exc:
        assert "no Chrome" in str(exc), exc
    else:
        raise AssertionError("empty scan succeeded")


def test_matching_origin_wins_and_a_tie_lists_ports_without_urls():
    bank = serve("https://bank.example/secret-path")
    other = serve("https://other.example/login")
    second = serve("https://bank.example/also-secret")
    try:
        got = discover_cdp(None, {"https://bank.example"}, origin_of,
                           candidates=[other.server_address[1], bank.server_address[1]])
        assert got.endswith(f":{bank.server_address[1]}/devtools/browser/abc-1"), got
        try:
            discover_cdp(None, {"https://bank.example"}, origin_of,
                         candidates=[bank.server_address[1], second.server_address[1]])
        except DiscoverError as exc:
            text = str(exc)
            assert str(bank.server_address[1]) in text and str(second.server_address[1]) in text, text
            assert "secret-path" not in text and "also-secret" not in text, text
        else:
            raise AssertionError("two matching browsers were guessed")
        try:
            discover_cdp(None, {"https://bank.example"}, origin_of,
                         candidates=[other.server_address[1], serve("https://elsewhere.example/").server_address[1]])
        except DiscoverError as exc:
            assert "more than one Chrome" in str(exc), exc
        else:
            raise AssertionError("two unmatched browsers were guessed")
    finally:
        bank.shutdown()
        other.shutdown()
        second.shutdown()


if __name__ == "__main__":
    tests = [value for name, value in list(globals().items()) if name.startswith("test_")]
    failed = 0
    for test in tests:
        try:
            test()
        except Exception as exc:
            failed += 1
            print(f"FAIL {test.__name__}: {type(exc).__name__}: {exc}")
        else:
            print(f"OK   {test.__name__}")
    if failed:
        raise SystemExit(f"{failed} of {len(tests)} discover tests failed")
    print(f"{len(tests)} discover tests OK")
