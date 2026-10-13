"""Offline behavior tests. A fake pass-cli stands in for the real binary."""
import json, os, stat, tempfile
from mcp_client import Client

TOKEN = "pst-TEST-TOKEN-value"
PASSWORD = "hunter2-secret-value"
SEED = "SEEDSECRETVALUE"


def install_fake(d):
    os.makedirs(d, exist_ok=True)
    open(os.path.join(d, "password"), "w").write(PASSWORD)
    item = {"item": {
        "id": "item1", "share_id": "share1",
        "content": {
            "title": "Bank", "note": "",
            "content": {"Login": {
                "username": "ada", "email": "ada@example.com", "password": PASSWORD,
                "totp_uri": f"otpauth://totp/Bank?secret={SEED}",
                "urls": ["https://bank.com/login"],
            }},
            "extra_fields": [{"name": "api"}],
        },
    }}
    open(os.path.join(d, "item.json"), "w").write(json.dumps(item))
    fake = os.path.join(d, "pass-cli")
    open(fake, "w").write(f"""#!/bin/bash
echo "$*" >> {d}/calls
if [ -n "${{PROTON_PASS_SESSION_DIR:-}}" ]; then printf '%s' "$PROTON_PASS_SESSION_DIR" > {d}/session; fi
if [ "$1" = login ]; then
  printf '%s' "${{PROTON_PASS_PERSONAL_ACCESS_TOKEN-}}" > {d}/seen-token
  if [ -f {d}/login-fail ]; then echo "rejected ${{PROTON_PASS_PERSONAL_ACCESS_TOKEN-}}" >&2; exit 1; fi
  touch {d}/ok; exit 0
fi
if [ ! -f {d}/ok ]; then echo "Error: This operation requires an authenticated client" >&2; exit 1; fi
if [ -f {d}/not-a-login ]; then echo "Error: item is not a login" >&2; exit 1; fi
if [ -f {d}/fail-with-secrets ]; then echo "err tok=$(cat {d}/seen-token) pw=$(cat {d}/password)" >&2; exit 1; fi
if [ "$1" = vault ]; then echo '{{"vaults":[{{"name":"V","vault_id":"v","share_id":"share1"}}]}}'; exit 0; fi
if [ "$1" = item ] && [ "$2" = list ]; then
  echo '{{"items":[{{"title":"Bank","item_type":"login","share_id":"share1","id":"item1","modify_time":1,"state":"Active"}},{{"title":"Old","item_type":"login","share_id":"share1","id":"item2","modify_time":1,"state":"Trashed"}}]}}'
  exit 0
fi
if [ "$1" = item ] && [ "$2" = view ]; then
  case " $* " in
    *" --field "*) printf '%s\\n' "$(cat {d}/password)"; exit 0 ;;
  esac
  if [ -f {d}/bad-json ]; then printf 'NOT JSON %s\\n' "$(cat {d}/password)"; exit 0; fi
  cat {d}/item.json; exit 0
fi
if [ "$1" = item ] && [ "$2" = totp ]; then echo '{{"code":"123456"}}'; exit 0; fi
if [ "$1" = run ]; then
  printf '%s' "${{PW-}}" > {d}/env-pw
  if [ -f {d}/echo-secrets ]; then echo "tok=$(cat {d}/seen-token) pw=$(cat {d}/password)"; else echo done; fi
  exit 0
fi
echo "unexpected: $*" >&2; exit 1
""")
    os.chmod(fake, 0o755)
    pat = os.path.join(d, "pat")
    open(pat, "w").write(TOKEN + "\n")
    os.chmod(pat, 0o600)
    return fake, pat


def calls(d):
    p = os.path.join(d, "calls")
    return open(p).read().splitlines() if os.path.exists(p) else []


def start(d, chmod_pat=0o600, drop=(), **env):
    fake, pat = install_fake(d)
    os.chmod(pat, chmod_pat)
    home = os.path.join(d, "home")
    os.makedirs(home, exist_ok=True)
    base = {"HOME": home, "PASS_CLI": fake, "PASS_PAT_FILE": pat,
            "PROTON_PASS_SESSION_DIR": os.path.join(d, "session")}
    base.update(env)
    return Client(base, drop=drop)


def test_metadata_search_and_describe_hide_secrets():
    d = tempfile.mkdtemp()
    c = start(d)
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
            "has_password": True, "has_totp": True, "extra_field_names": ["api"], "has_note": False,
        }, got
        blob = json.dumps(got)
        assert PASSWORD not in blob and SEED not in blob and TOKEN not in blob
        assert c.call("get_totp", share_id="share1", item_id="item1") == {"code": "123456"}
        assert c.call("get_secret", share_id="share1", item_id="item1", field="password")["value"] == PASSWORD
    finally:
        c.close()


def test_non_auth_error_is_not_a_relogin():
    d = tempfile.mkdtemp()
    c = start(d)
    try:
        c.call("list_vaults")
        open(os.path.join(d, "not-a-login"), "w").close()
        try:
            c.call("describe_item", share_id="share1", item_id="item1")
            raise AssertionError("describe should have failed")
        except RuntimeError as e:
            text = str(e)
        assert "not a login" in text, text
        assert TOKEN not in text, text
        assert [line.split()[0] for line in calls(d)].count("login") == 1, calls(d)
    finally:
        c.close()


def test_login_failure_hides_the_token():
    d = tempfile.mkdtemp()
    c = start(d)
    open(os.path.join(d, "login-fail"), "w").close()
    try:
        try:
            c.call("list_vaults")
            raise AssertionError("login should have failed")
        except RuntimeError as e:
            text = str(e)
        assert TOKEN not in text, text
        assert "login failed" in text, text
    finally:
        c.close()


def test_later_error_hides_token_and_loaded_password():
    d = tempfile.mkdtemp()
    c = start(d)
    try:
        described = c.call("describe_item", share_id="share1", item_id="item1")
        assert PASSWORD not in json.dumps(described)
        open(os.path.join(d, "fail-with-secrets"), "w").close()
        try:
            c.call("list_vaults")
            raise AssertionError("expected pass-cli error")
        except RuntimeError as e:
            text = str(e)
        assert TOKEN not in text, text
        assert PASSWORD not in text, text
        assert [line.split()[0] for line in calls(d)].count("login") == 1, calls(d)
    finally:
        c.close()


def test_run_with_secrets_passes_refs_and_redacts_known_secrets():
    d = tempfile.mkdtemp()
    c = start(d)
    try:
        c.call("describe_item", share_id="share1", item_id="item1")
        open(os.path.join(d, "echo-secrets"), "w").close()
        got = c.call("run_with_secrets", command="printf done", env={"PW": "pass://share1/item1/password"}, reason="offline test")
        blob = json.dumps(got)
        assert TOKEN not in blob, blob
        assert PASSWORD not in blob, blob
        assert got["exit_code"] == 0
        assert open(os.path.join(d, "env-pw")).read() == "pass://share1/item1/password"
        assert sum(1 for line in calls(d) if line.startswith("run ")) == 1, calls(d)
    finally:
        c.close()


def test_rejects_raw_env_values_and_bad_refs_before_run():
    d = tempfile.mkdtemp()
    c = start(d)
    try:
        for env in ({"PW": "literal-secret-value"}, {"PW": "pass://only-one"}, {"BAD-NAME": "pass://share1/item1/password"}):
            before = len(calls(d))
            try:
                c.call("run_with_secrets", command="echo hi", env=env)
                raise AssertionError(f"accepted {env}")
            except RuntimeError as e:
                text = str(e)
            assert "literal-secret-value" not in text, text
            assert TOKEN not in text
            assert not any(line.startswith("run ") for line in calls(d)[before:]), calls(d)
    finally:
        c.close()


def test_world_readable_pat_is_refused():
    d = tempfile.mkdtemp()
    c = start(d, chmod_pat=0o644)
    try:
        try:
            c.call("list_vaults")
            raise AssertionError("world-readable PAT was accepted")
        except RuntimeError as e:
            text = str(e)
        assert "0600" in text, text
        assert TOKEN not in text, text
        assert not any(line.startswith("login") for line in calls(d)), calls(d)
        assert not os.path.exists(os.path.join(d, "seen-token"))
    finally:
        c.close()


def test_session_dir_is_private_and_tilde_expands():
    d = tempfile.mkdtemp()
    home = os.path.join(d, "home")
    c = start(d, PROTON_PASS_SESSION_DIR="~/pass-session")
    try:
        c.call("list_vaults")
        seen = open(os.path.join(d, "session")).read()
        expect = os.path.join(home, "pass-session")
        assert seen == expect, seen
        assert not seen.startswith("/tmp/pass-agent-mcp")
        mode = stat.S_IMODE(os.stat(seen).st_mode)
        assert mode == 0o700, oct(mode)
    finally:
        c.close()


def test_default_session_dir_is_under_home():
    d = tempfile.mkdtemp()
    home = os.path.join(d, "home")
    c = start(d, drop=("PROTON_PASS_SESSION_DIR",))
    try:
        c.call("list_vaults")
        seen = open(os.path.join(d, "session")).read()
        assert seen == os.path.join(home, ".local", "share", "pass-agent"), seen
        mode = stat.S_IMODE(os.stat(seen).st_mode)
        assert mode == 0o700, oct(mode)
    finally:
        c.close()


def test_parse_error_and_bad_request_do_not_kill_the_server():
    d = tempfile.mkdtemp()
    c = start(d)
    try:
        c.send_raw("{")
        msg = c.read()
        assert msg["error"]["code"] == -32700, msg
        assert TOKEN not in json.dumps(msg)
        c.send_raw(json.dumps({"jsonrpc": "2.0", "id": 50, "method": "tools/call"}))
        msg = c.read()
        assert msg["error"]["code"] == -32602, msg
        assert c.call("list_vaults")[0]["name"] == "V"
    finally:
        c.close()


def test_notification_does_not_run_a_tool():
    d = tempfile.mkdtemp()
    c = start(d)
    try:
        c.send({"jsonrpc": "2.0", "method": "tools/call", "params": {"name": "list_vaults", "arguments": {}}})
        assert c.rpc("ping") == {}
        assert calls(d) == [], calls(d)
    finally:
        c.close()


def test_unsupported_protocol_version_is_not_echoed():
    d = tempfile.mkdtemp()
    c = start(d)
    try:
        c.send({"jsonrpc": "2.0", "id": 40, "method": "initialize",
                "params": {"protocolVersion": "1999-01-01", "capabilities": {}, "clientInfo": {"name": "t"}}})
        msg = c.read()
        assert msg["result"]["protocolVersion"] == "2025-06-18", msg
    finally:
        c.close()


def test_invalid_tool_arguments():
    d = tempfile.mkdtemp()
    c = start(d)
    try:
        cases = (
            ("describe_item", {"share_id": "share1"}, "item_id"),
            ("describe_item", {"share_id": "--field", "item_id": "item1"}, "share_id"),
            ("search_items", {"query": "bank", "limit": -1}, "limit"),
            ("search_items", {"query": "bank", "type": "password"}, "type"),
            ("list_vaults", {"nope": True}, "unknown"),
        )
        for name, kwargs, needle in cases:
            before = calls(d)
            try:
                c.call(name, **kwargs)
                raise AssertionError(f"accepted {kwargs}")
            except RuntimeError as e:
                text = str(e)
            assert needle in text, (kwargs, text)
            assert calls(d) == before, calls(d)
        try:
            c.call("no_such_tool")
            raise AssertionError("unknown tool was accepted")
        except RuntimeError as e:
            assert "unknown tool" in str(e), e
        assert c.call("list_vaults")[0]["name"] == "V"
    finally:
        c.close()


def test_invalid_item_json_does_not_echo_the_body():
    d = tempfile.mkdtemp()
    c = start(d)
    try:
        open(os.path.join(d, "bad-json"), "w").close()
        try:
            c.call("describe_item", share_id="share1", item_id="item1")
            raise AssertionError("invalid JSON was accepted")
        except RuntimeError as e:
            text = str(e)
        assert PASSWORD not in text, text
        assert "invalid JSON" in text, text
    finally:
        c.close()


TESTS = [
    test_metadata_search_and_describe_hide_secrets,
    test_non_auth_error_is_not_a_relogin,
    test_login_failure_hides_the_token,
    test_later_error_hides_token_and_loaded_password,
    test_run_with_secrets_passes_refs_and_redacts_known_secrets,
    test_rejects_raw_env_values_and_bad_refs_before_run,
    test_world_readable_pat_is_refused,
    test_session_dir_is_private_and_tilde_expands,
    test_default_session_dir_is_under_home,
    test_parse_error_and_bad_request_do_not_kill_the_server,
    test_notification_does_not_run_a_tool,
    test_unsupported_protocol_version_is_not_echoed,
    test_invalid_tool_arguments,
    test_invalid_item_json_does_not_echo_the_body,
]

if __name__ == "__main__":
    failed = 0
    for test in TESTS:
        try:
            test()
        except Exception as e:
            failed += 1
            print(f"FAIL {test.__name__}: {type(e).__name__}: {e}")
        else:
            print(f"OK   {test.__name__}")
    if failed:
        raise SystemExit(f"{failed} failed")
    print(f"{len(TESTS)} offline tests OK")
