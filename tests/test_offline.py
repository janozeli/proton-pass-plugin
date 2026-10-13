import fcntl, json, os, select, shutil, socket, stat, subprocess, sys, termios
from harness import (PASSWORD, PIN, SEED, SERVER, TOKEN, Operator, calls, child, error, install, server_env,
                     session, start, write)

BWRAP = shutil.which("bwrap")
SANDBOX = ["--unshare-user", "--unshare-net", "--die-with-parent",
           "--unsetenv", "PROTON_PASS_SESSION_DIR", "--unsetenv", "PROTON_PASS_AGENT_REASON",
           "--unsetenv", "PROTON_PASS_PERSONAL_ACCESS_TOKEN", "--unsetenv", "PASS_PAT_FILE", "--unsetenv", "PASS_CLI",
           "--unsetenv", "HOME", "--setenv", "HOME", "/tmp", "--setenv", "PATH", "/usr/bin:/bin",
           "--ro-bind-try", "/usr", "/usr", "--ro-bind-try", "/bin", "/bin", "--ro-bind-try", "/lib", "/lib",
           "--ro-bind-try", "/lib64", "/lib64", "--proc", "/proc", "--dev", "/dev", "--tmpfs", "/tmp", "--chdir", "/tmp",
           "--"]
NET_SANDBOX = [a for a in SANDBOX if a != "--unshare-net"]
REF = "pass://share1/item1/pin"
FORBIDDEN = {"get_secret", "run_with_secrets", "command", "url_match", "url", "username_selector",
             "password_selector", "cdp_port", "cwd", "value", "password", "totp_uri"}


def runs(d):
    return [a for a in calls(d) if a[:1] == ["run"]]


def logins(d):
    return [a for a in calls(d) if a == ["login"]]


def startup(d, **env):
    r = subprocess.run([sys.executable, SERVER], env=dict(os.environ, **server_env(d, **env)),
                       stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=30)
    return r.returncode, r.stderr


def test_get_secret_and_run_with_secrets_are_unknown_tools():
    d, c = start()
    try:
        assert (got := error(c, "get_secret", share_id="share1", item_id="item1")) == "unknown tool get_secret", got
        assert (got := error(c, "run_with_secrets", command="env", env={"PW": REF})) == "unknown tool run_with_secrets", got
        names = [t["name"] for t in c.rpc("tools/list")["tools"]]
        assert names == ["list_vaults", "search_items", "describe_item", "get_totp", "fill_login", "run_approved"], names
        assert calls(d) == [], calls(d)
    finally:
        c.close()


def test_no_tool_takes_a_forbidden_parameter():
    d, c = start()
    try:
        tools = c.rpc("tools/list")["tools"]
        props = {t["name"]: sorted(t["inputSchema"]["properties"]) for t in tools}
        assert props == {
            "list_vaults": [], "search_items": ["limit", "query", "type", "vault"],
            "describe_item": ["item_id", "reason", "share_id"], "get_totp": ["item_id", "reason", "share_id"],
            "fill_login": ["item_id", "reason", "share_id", "submit"], "run_approved": ["argv", "env", "reason"],
        }, props
        assert (hit := FORBIDDEN & {n for t in tools for n in (t["name"], *t["inputSchema"]["properties"])}) == set(), hit
        assert all(t["inputSchema"]["additionalProperties"] is False for t in tools), tools
    finally:
        c.close()


def test_fill_login_rejects_url_match_selectors_and_cdp_port():
    d, c = start()
    try:
        for key, value in (("url_match", "127.0.0.1:8765"), ("username_selector", "#q"),
                           ("password_selector", "#q"), ("cdp_port", 9333)):
            got = error(c, "fill_login", share_id="share1", item_id="item1", reason="log in", **{key: value})
            assert got == f"unknown argument {key}", got
        assert calls(d) == [], calls(d)
    finally:
        c.close()


def test_startup_refuses_a_forbidden_parameter_name():
    d = install()
    code = ("import sys; sys.path.insert(0, %r); import proton_pass_mcp as m; "
            "m.TOOLS['fill_login'][2]['cdp_port'] = {'type': 'integer'}; m.main()") % os.path.dirname(SERVER)
    r = subprocess.run([sys.executable, "-c", code], env=dict(os.environ, **server_env(d)),
                       stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=30)
    assert (r.returncode, r.stderr) == (1, "proton-pass: forbidden tool or parameter name: cdp_port\n"), r


def test_run_child_has_no_network_and_no_host_secrets_under_approve():
    d, c = start()
    op = Operator(d)
    listener = socket.create_server(("127.0.0.1", 0))
    listener.settimeout(0.5)
    try:
        argv, _ = child(d, listener.getsockname()[1])
        got = c.call("run_approved", argv=argv, env={"PW": REF}, reason="deploy")
        assert got == {"exit_code": 7}, got
        assert PIN not in json.dumps(got), got
        assert op.prompts == [{"action": "run", "argv": argv, "env": [["PW", REF, "Bank", "pin"]],
                               "reason": "deploy"}], op.prompts
        assert runs(d) == [["run", "--", BWRAP, *SANDBOX, *argv]], runs(d)
        cli_env = json.load(open(os.path.join(d, "run-env.json")))
        assert cli_env == {"PATH": os.environ["PATH"], "PROTON_PASS_SESSION_DIR": session(d),
                           "PROTON_PASS_AGENT_REASON": "proton-pass plugin", "PW": REF}, cli_env
        assert (fds := json.load(open(os.path.join(d, "run-fds.json")))) == ["/dev/null"] * 3, fds
        try:
            listener.accept()
            raise AssertionError("the child reached the listener without approve-net")
        except TimeoutError:
            pass
        assert (left := os.listdir(session(d))) == ["approve.sock"], left
    finally:
        listener.close()
        op.close()
        c.close()


def test_run_child_reaches_the_network_only_under_approve_net():
    d, c = start()
    op = Operator(d, {"op": "allow-net"})
    listener = socket.create_server(("127.0.0.1", 0))
    listener.settimeout(5)
    try:
        argv, want = child(d, listener.getsockname()[1])
        assert (got := c.call("run_approved", argv=argv, env={"PW": REF}, reason="deploy")) == {"exit_code": 9}, got
        assert runs(d) == [["run", "--", BWRAP, *NET_SANDBOX, *argv]], runs(d)
        conn, _ = listener.accept()
        with conn:
            assert (seen := json.loads(conn.makefile().read())) == want, seen
    finally:
        listener.close()
        op.close()
        c.close()


def test_run_executes_a_shell_only_when_the_operator_approved_that_argv():
    d, c = start()
    op = Operator(d)
    try:
        assert (got := c.call("run_approved", argv=["/bin/sh", "-c", "exit 3"], env={"PW": REF}, reason="r")) == {"exit_code": 3}, got
        assert op.prompts[0]["argv"] == ["/bin/sh", "-c", "exit 3"], op.prompts
        assert runs(d) == [["run", "--", BWRAP, *SANDBOX, "/bin/sh", "-c", "exit 3"]], runs(d)
    finally:
        op.close()
        c.close()


def test_run_fails_closed_and_ignores_an_argv_in_the_reply():
    d, c = start()
    try:
        argv, _ = child(d)
        assert (got := error(c, "run_approved", argv=argv, env={"PW": REF}, reason="r")) == "approval unavailable", got
        op = Operator(d, {"op": "deny"})
        assert (got := error(c, "run_approved", argv=argv, env={"PW": REF}, reason="r")) == "release denied", got
        op.close()
        assert runs(d) == [], runs(d)
        pwned = os.path.join(d, "pwned")
        op = Operator(d, {"op": "allow", "argv": ["/bin/sh", "-c", f"touch {pwned}"]})
        assert (got := c.call("run_approved", argv=argv, env={"PW": REF}, reason="r")) == {"exit_code": 7}, got
        op.close()
        assert runs(d) == [["run", "--", BWRAP, *SANDBOX, *argv]], runs(d)
        assert not os.path.exists(pwned)
    finally:
        c.close()


def test_run_without_bwrap_does_not_ask_or_run():
    d, c = start(PATH="/nonexistent")
    op = Operator(d)
    try:
        argv, _ = child(d)
        assert (got := error(c, "run_approved", argv=argv, env={"PW": REF}, reason="r")) == "bwrap is not installed", got
        assert (op.prompts, runs(d)) == ([], []), (op.prompts, runs(d))
    finally:
        op.close()
        c.close()


def test_run_rejects_relative_argv_reserved_names_and_literal_values():
    d, c = start()
    op = Operator(d)
    try:
        cases = (
            ({"argv": ["sh", "-c", "env"], "env": {"PW": REF}}, "argv[0] must be an absolute path"),
            ({"argv": [], "env": {"PW": REF}}, "argv must not be empty"),
            ({"argv": ["/bin/true"], "env": {"PATH": REF}}, "env name PATH is reserved"),
            ({"argv": ["/bin/true"], "env": {"LD_PRELOAD": REF}}, "env name LD_PRELOAD is reserved"),
            ({"argv": ["/bin/true"], "env": {"PW": "literal-secret-value"}},
             "env PW must be a pass://SHARE_ID/ITEM_ID/FIELD reference"),
            ({"argv": ["/bin/true"], "env": {"BAD-NAME": REF}}, "invalid env name BAD-NAME"),
            *(({"argv": ["/bin/true"], "env": {"PW": ref}}, "env PW must be a pass://SHARE_ID/ITEM_ID/FIELD reference")
              for ref in ("pass://share1/item1/password?totp=uri", "pass://share1/item1/pin#x",
                          "pass://share1/item1/pin/extra", "pass://share1//pin", "pass://share1/item1/-pin")),
        )
        for args, want in cases:
            got = error(c, "run_approved", reason="r", **args)
            assert got == want, (args, got)
        assert calls(d) == [] and op.prompts == [], (calls(d), op.prompts)
    finally:
        op.close()
        c.close()


def test_describe_item_drops_url_userinfo():
    d, c = start(urls=["https://user:URLPASS-CANARY@bank.example/login", "bank.com/login", "https://[broken/x"])
    try:
        got = c.call("describe_item", share_id="share1", item_id="item1", reason="r")
        assert got["urls"] == ["https://bank.example/login", "https://bank.com/login"], got["urls"]
    finally:
        c.close()


def test_describe_item_returns_no_note_card_number_or_private_key():
    note, card, key = "NOTE-CANARY", "4111111111111111", "-----BEGIN OPENSSH PRIVATE KEY-----KEY-CANARY"
    d, c = start()
    try:
        for kind, content in (("CreditCard", {"cardholder_name": "Ada", "number": card, "verification_number": "123"}),
                              ("SshKey", {"private_key": key, "public_key": "ssh-ed25519 AAAA"})):
            write(d, "item.json", {"item": {"id": "item1", "share_id": "share1", "content": {
                "title": "Bank", "note": note, "content": {kind: content},
                "extra_fields": [{"name": "backup", "content": {"Hidden": key}}]}}})
            got = c.call("describe_item", share_id="share1", item_id="item1", reason="r")
            assert got == {"title": "Bank", "share_id": "share1", "item_id": "item1", "type": kind, "urls": [],
                           "username": "", "email": "", "has_password": False, "has_totp": False,
                           "extra_field_names": ["backup"], "has_note": True}, got
            assert [s for s in (note, card, key) if s in json.dumps(got)] == [], got
    finally:
        c.close()


def test_pass_cli_stderr_never_reaches_the_tool_error():
    d, c = start()
    try:
        c.call("list_vaults")
        write(d, "stderr", f"Error: boom tok={TOKEN} pw={PASSWORD} STDERR-CANARY")
        assert (got := error(c, "describe_item", share_id="share1", item_id="item1")) == "pass-cli item failed", got
        assert (got := error(c, "list_vaults")) == "pass-cli vault failed", got
        assert len(logins(d)) == 1, calls(d)
    finally:
        c.close()


def test_get_totp_returns_only_the_digits_after_approval():
    d, c = start()
    op = Operator(d)
    try:
        assert (got := c.call("get_totp", share_id="share1", item_id="item1", reason="2fa")) == {"code": "123456"}, got
        assert op.prompts == [{"action": "totp", "title": "Bank", "reason": "2fa"}], op.prompts
        op.close()
        before = len(calls(d))
        assert (got := error(c, "get_totp", share_id="share1", item_id="item1", reason="2fa")) == "approval unavailable", got
        assert [a for a in calls(d)[before:] if a[:2] == ["item", "totp"]] == [], calls(d)
        op = Operator(d, {"op": "allow-net"})
        assert (got := error(c, "get_totp", share_id="share1", item_id="item1", reason="2fa")) == "release denied", got
        op.close()
        assert [a for a in calls(d)[before:] if a[:2] == ["item", "totp"]] == [], calls(d)
    finally:
        c.close()


def test_pass_cli_gets_a_fresh_environment():
    d, c = start()
    try:
        c.call("list_vaults")
        seen = json.load(open(os.path.join(d, "login-env.json")))
        assert seen == {"PATH": os.environ["PATH"], "PROTON_PASS_SESSION_DIR": session(d),
                        "PROTON_PASS_AGENT_REASON": "proton-pass plugin",
                        "PROTON_PASS_PERSONAL_ACCESS_TOKEN": TOKEN}, seen
    finally:
        c.close()


def test_symlink_pat_is_refused_and_login_is_not_run():
    d, c = start()
    try:
        real = os.path.join(d, "real-pat")
        os.rename(os.path.join(d, "pat"), real)
        os.symlink(real, os.path.join(d, "pat"))
        assert (got := error(c, "list_vaults")) == "PAT file must not be a symlink", got
        assert logins(d) == [], calls(d)
    finally:
        c.close()


def test_pat_must_be_private_to_its_owner():
    for mode in (0o644, 0o640, 0o602):
        d, c = start()
        try:
            os.chmod(os.path.join(d, "pat"), mode)
            assert (got := error(c, "list_vaults")) == "PAT file must not be accessible to group or others", (mode, got)
            assert logins(d) == [], calls(d)
        finally:
            c.close()
    for mode in (0o400, 0o600):
        d, c = start()
        try:
            os.chmod(os.path.join(d, "pat"), mode)
            assert c.call("list_vaults")[0]["name"] == "V"
            assert len(logins(d)) == 1, calls(d)
        finally:
            c.close()


def test_symlink_session_dir_refuses_to_start():
    d = install()
    os.mkdir(os.path.join(d, "real-session"), 0o700)
    os.symlink(os.path.join(d, "real-session"), session(d))
    assert (got := startup(d)) == (1, "proton-pass: PROTON_PASS_SESSION_DIR must not be a symlink\n"), got


def test_symlink_dot_session_refuses_to_start():
    d = install()
    os.mkdir(session(d), 0o700)
    os.mkdir(os.path.join(d, "elsewhere"), 0o700)
    os.symlink(os.path.join(d, "elsewhere"), os.path.join(session(d), ".session"))
    assert (got := startup(d)) == (1, "proton-pass: PROTON_PASS_SESSION_DIR/.session must not be a symlink\n"), got


def test_open_session_dir_we_own_becomes_0700_and_a_second_start_adopts_it():
    d = install()
    os.mkdir(session(d))
    os.chmod(session(d), 0o777)
    for _ in range(2):
        d, c = start(d)
        try:
            assert c.call("list_vaults")[0]["name"] == "V"
            assert (mode := stat.S_IMODE(os.stat(session(d)).st_mode)) == 0o700, oct(mode)
        finally:
            c.close()


def test_leading_dash_ids_and_vaults_never_reach_pass_cli():
    d, c = start()
    try:
        cases = (
            ("describe_item", {"share_id": "--field", "item_id": "item1"}, "share_id is invalid"),
            ("describe_item", {"share_id": "share1", "item_id": "-x"}, "item_id is invalid"),
            ("describe_item", {"share_id": "share1", "item_id": "item1\n--field"}, "item_id is invalid"),
            ("search_items", {"vault": "--help"}, "vault is invalid"),
            ("search_items", {"vault": "V\nW"}, "vault is invalid"),
            ("get_totp", {"share_id": "-s", "item_id": "item1", "reason": "r"}, "share_id is invalid"),
            ("fill_login", {"share_id": "share1", "item_id": "-i", "reason": "r"}, "item_id is invalid"),
            ("run_approved", {"argv": ["/bin/true"], "env": {"PW": "pass://share1/-item1/pin"}, "reason": "r"},
             "env PW must be a pass://SHARE_ID/ITEM_ID/FIELD reference"),
        )
        for name, args, want in cases:
            got = error(c, name, **args)
            assert got == want, (name, args, got)
        assert calls(d) == [], calls(d)
    finally:
        c.close()


def start_helper(d):
    master, slave = os.openpty()
    p = subprocess.Popen([sys.executable, SERVER, "approve"], env=dict(os.environ, **server_env(d)),
                         stdin=slave, stdout=slave, stderr=slave, start_new_session=True,
                         preexec_fn=lambda: fcntl.ioctl(0, termios.TIOCSCTTY, 0))
    os.close(slave)
    return p, master


def read_tty(master, marker):
    buf = b""
    while marker not in buf:
        ready, _, _ = select.select([master], [], [], 15)
        if not ready:
            raise AssertionError(f"the tty never showed {marker!r}: {buf!r}")
        buf += os.read(master, 4096)
    return buf.decode().replace("\r\n", "\n")


def result(msg):
    text = msg["result"]["content"][0]["text"]
    return text if msg["result"].get("isError") else json.loads(text)


def test_approve_helper_shows_the_claim_on_the_tty():
    d, c = start()
    helper, tty = start_helper(d)
    try:
        read_tty(tty, b"listening")
        argv, _ = child(d)
        reason = "deploy\x1b[2J\nnow"
        c.send({"jsonrpc": "2.0", "id": 90, "method": "tools/call", "params": {
            "name": "run_approved", "arguments": {"argv": argv, "env": {"PW": REF}, "reason": reason}}})
        shown = read_tty(tty, b"denies.")
        os.write(tty, b"approve\n")
        assert result(c.read()) == {"exit_code": 7}
        want = "\n".join([
            "proton-pass release request",
            "  action:  run",
            "  argv:    " + repr(argv[0]),
            *["           " + repr(a) for a in argv[1:]],
            f"  env:     'PW' = {REF!r} (field 'pin' of 'Bank')",
            "  network: off (type approve-net to allow it)",
            "  reason:  " + repr(reason),
            "Type approve to release. Anything else denies.",
        ])
        assert want in shown, shown
        assert "\x1b" not in shown, shown
        c.send({"jsonrpc": "2.0", "id": 91, "method": "tools/call", "params": {
            "name": "get_totp", "arguments": {"share_id": "share1", "item_id": "item1", "reason": "2fa"}}})
        shown = read_tty(tty, b"denies.")
        os.write(tty, b"approve-net\n")
        assert result(c.read()) == "release denied"
        want = ("proton-pass release request\n  action:  totp\n  item:    'Bank'\n  reason:  '2fa'\n"
                "Type approve to release. Anything else denies.")
        assert want in shown, shown
        assert [a for a in calls(d) if a[:2] == ["item", "totp"]] == [], calls(d)
    finally:
        helper.terminate()
        helper.wait()
        os.close(tty)
        c.close()


def test_approve_helper_refuses_a_symlink_socket():
    d = install()
    os.mkdir(session(d), 0o700)
    os.symlink(os.path.join(d, "elsewhere.sock"), os.path.join(session(d), "approve.sock"))
    r = subprocess.run([sys.executable, SERVER, "approve"], env=dict(os.environ, **server_env(d)),
                       stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=30, start_new_session=True)
    assert (r.returncode, r.stderr) == (1, "proton-pass: approve.sock must not be a symlink\n"), r
    assert not os.path.exists(os.path.join(d, "elsewhere.sock"))


def test_search_and_describe_return_metadata_only():
    d, c = start()
    try:
        assert c.call("search_items", query="bank", limit=10) == {
            "count": 1,
            "items": [{"title": "Bank", "type": "login", "vault": "V", "share_id": "share1",
                       "item_id": "item1", "modified": 1}],
        }
        got = c.call("describe_item", share_id="share1", item_id="item1", reason="offline test")
        assert got == {
            "title": "Bank", "share_id": "share1", "item_id": "item1", "type": "Login",
            "urls": ["https://bank.com/login"], "username": "ada", "email": "ada@example.com",
            "has_password": True, "has_totp": True, "extra_field_names": ["api"], "has_note": True,
        }, got
    finally:
        c.close()


def test_non_auth_error_is_not_a_relogin():
    d, c = start()
    try:
        c.call("list_vaults")
        write(d, "stderr", "Error: item is not a login")
        assert (got := error(c, "describe_item", share_id="share1", item_id="item1")) == "pass-cli item failed", got
        assert len(logins(d)) == 1, calls(d)
    finally:
        c.close()


def test_login_failure_hides_the_token():
    for token in (TOKEN, "xy"):
        d, c = start(token=token)
        write(d, "login-fail", "")
        try:
            assert (got := error(c, "list_vaults")) == "pass-cli login failed", got
        finally:
            c.close()


def test_session_dir_is_private_and_tilde_expands():
    d, c = start(PROTON_PASS_SESSION_DIR="~/pass-session")
    try:
        c.call("list_vaults")
        seen = json.load(open(os.path.join(d, "login-env.json")))["PROTON_PASS_SESSION_DIR"]
        assert seen == os.path.join(d, "home", "pass-session"), seen
        assert stat.S_IMODE(os.stat(seen).st_mode) == 0o700
    finally:
        c.close()


def test_default_session_dir_is_under_home():
    d, c = start(drop=("PROTON_PASS_SESSION_DIR",))
    try:
        c.call("list_vaults")
        seen = json.load(open(os.path.join(d, "login-env.json")))["PROTON_PASS_SESSION_DIR"]
        assert seen == os.path.join(d, "home", ".local", "share", "pass-agent"), seen
        assert stat.S_IMODE(os.stat(seen).st_mode) == 0o700
    finally:
        c.close()


def test_parse_error_and_bad_request_do_not_kill_the_server():
    d, c = start()
    try:
        c.send_raw("{")
        msg = c.read()
        assert msg == {"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": "parse error"}}, msg
        c.send_raw(json.dumps({"jsonrpc": "2.0", "id": 50, "method": "tools/call"}))
        assert c.read()["error"]["code"] == -32602
        assert c.call("list_vaults")[0]["name"] == "V"
    finally:
        c.close()


def test_notification_does_not_run_a_tool():
    d, c = start()
    try:
        c.send({"jsonrpc": "2.0", "method": "tools/call", "params": {"name": "list_vaults", "arguments": {}}})
        assert c.rpc("ping") == {}
        assert calls(d) == [], calls(d)
    finally:
        c.close()


def test_unsupported_protocol_version_is_not_echoed():
    d, c = start()
    try:
        c.send({"jsonrpc": "2.0", "id": 40, "method": "initialize",
                "params": {"protocolVersion": "1999-01-01", "capabilities": {}, "clientInfo": {"name": "t"}}})
        assert c.read()["result"]["protocolVersion"] == "2025-06-18"
    finally:
        c.close()


def test_invalid_tool_arguments():
    d, c = start()
    try:
        cases = (
            ("describe_item", {"share_id": "share1"}, "missing item_id"),
            ("search_items", {"query": "bank", "limit": -1}, "limit must be >= 0"),
            ("search_items", {"query": "bank", "type": "password"}, "type must be one of: login, note, alias, "
                                                                     "credit-card, identity, ssh-key, wifi, custom"),
            ("list_vaults", {"nope": True}, "unknown argument nope"),
            ("fill_login", {"share_id": "share1", "item_id": "item1", "reason": "r", "submit": "yes"},
             "submit must be a boolean"),
            ("run_approved", {"argv": "/bin/true", "env": {"PW": REF}, "reason": "r"}, "argv must be an array of strings"),
            ("no_such_tool", {}, "unknown tool no_such_tool"),
        )
        for name, args, want in cases:
            got = error(c, name, **args)
            assert got == want, (name, args, got)
        assert calls(d) == [], calls(d)
        assert c.call("list_vaults")[0]["name"] == "V"
    finally:
        c.close()


def test_invalid_item_json_does_not_echo_the_body():
    d, c = start()
    try:
        write(d, "item.json", f"NOT JSON {PASSWORD}")
        assert (got := error(c, "describe_item", share_id="share1", item_id="item1")) == "pass-cli returned invalid JSON", got
    finally:
        c.close()


if __name__ == "__main__":
    tests = [f for name, f in list(globals().items()) if name.startswith("test_")]
    failed = 0
    for test in tests:
        try:
            test()
        except Exception as e:
            failed += 1
            print(f"FAIL {test.__name__}: {type(e).__name__}: {e}")
        else:
            print(f"OK   {test.__name__}")
    if failed:
        raise SystemExit(f"{failed} of {len(tests)} offline tests failed")
    print(f"{len(tests)} offline tests OK")
