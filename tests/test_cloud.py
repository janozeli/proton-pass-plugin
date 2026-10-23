"""Exercise the real stdio server and PTY worker with a deterministic Proton CLI."""
import json
import os
from pathlib import Path
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

from mcp_client import Client
from test_setup import workspace as setup_workspace, entries, assert_cleaned, CREATED, RENEWED, FAKE as SETUP_FAKE

FAKE = SETUP_FAKE.replace('if args[:2] == ["share", "list"]:', 'if args[:2] == ["vault", "list"]:\n    print(json.dumps({"vaults": [{"name": "Bots", "vault_id": "v", "share_id": "s"}]}))\n    sys.exit(0)\nif args[:2] == ["share", "list"]:')

def workspace():
    result = setup_workspace()
    root, pat, log, env = result
    Path(env["PASS_CLI"]).write_text("#!" + sys.executable + "\n" + FAKE.replace('os.environ["SETUP_LOG"]', repr(log)))
    return result


def accept(params):
    assert "password" not in params["requestedSchema"]["properties"]
    return {"action": "accept", "content": {"approve": True}}


def client(env, consent=accept, capabilities=None):
    env = {**env, "PASS_APPROVAL_MODE": "mcp", "PROTON_PASS_SESSION_DIR": env["PASS_PAT_FILE"] + ".session"}
    return Client(env, capabilities={"elicitation": {}} if capabilities is None else capabilities, consent=consent)


def wait(c, job, states=("connected", "failed", "cancelled")):
    until = time.monotonic() + 10
    while time.monotonic() < until:
        value = c.call("connection_status", connection_id=job["connection_id"])
        if value["state"] in states:
            return value
        time.sleep(0.03)
    raise AssertionError(value)


def expect_error(c, name, fragment, **args):
    try:
        c.call(name, **args)
    except RuntimeError as exc:
        assert fragment in str(exc), str(exc)
    else:
        raise AssertionError("operation unexpectedly succeeded")


def test_web_connection_recovery_and_shared_lock():
    root, pat, log, env = workspace()
    fake = Path(env["PASS_CLI"])
    pause = '''    print("waiting", flush=True)
    import time
    while not os.path.exists(os.environ["SETUP_LOG"] + ".continue"):
        time.sleep(0.02)
'''
    fake.write_text("#!" + sys.executable + "\n" + FAKE.replace('    print("Waiting for authentication to complete...")', pause).replace('os.environ["SETUP_LOG"]', repr(log)))
    c, other = client(env), client(env)
    try:
        job = c.call("connect", vaults=["Bots"], role="viewer")
        assert job["state"] == "waiting_for_browser", job
        assert job["authorization_url"].startswith("https://account.proton.me/")
        assert not os.path.exists(pat)
        # MCP input is still serviced while the browser is pending.
        assert c.rpc("ping") == {}
        expect_error(other, "connect", "Another Bot", vaults=["Bots"])
        Path(log + ".continue").touch()
        done = wait(c, job)
        assert done["state"] == "connected", done
        assert "authorization_url" not in done
        assert Path(pat).read_text().strip() == CREATED
        assert not Path(pat + ".pending").exists()
        assert_cleaned(entries(log))
        # The second MCP process sees the credential without an MCP restart.
        assert other.call("session_info")["name"] == "grok-bot"
    finally:
        c.close()
        other.close()


def test_denial_and_absent_capability_do_not_start_login():
    root, pat, log, env = workspace()
    for caps, consent in (({}, accept), ({"elicitation": {}}, lambda _: {"action": "decline"})):
        c = client(env, consent, caps)
        try:
            expect_error(c, "connect", "unavailable" if not caps else "denied", vaults=["Bots"])
            assert entries(log) == []
        finally:
            c.close()


def test_cancel_cleans_login_and_releases_account_lock():
    root, pat, log, env = workspace()
    fake = Path(env["PASS_CLI"])
    fake.write_text("#!" + sys.executable + "\n" + FAKE.replace('    print("Waiting for authentication to complete...")',
                    '    print("Waiting", flush=True)\n    import time\n    time.sleep(600)'))
    c = client(env)
    try:
        job = c.call("connect", vaults=["Bots"])
        assert job["state"] == "waiting_for_browser"
        assert c.call("cancel_connection", connection_id=job["connection_id"])["state"] == "cancelling"
        assert wait(c, job)["state"] == "cancelled"
        assert not Path(pat).exists()
        assert_cleaned(entries(log))
        next_job = c.call("connect", vaults=["Bots"])
        assert next_job["connection_id"] != job["connection_id"]
        c.call("cancel_connection", connection_id=next_job["connection_id"])
        wait(c, next_job)
    finally:
        c.close()


def test_extra_password_goes_only_to_pty_and_portal_checks_origin():
    root, pat, log, env = workspace()
    marker = "only-human-knows-this"
    fake = Path(env["PASS_CLI"])
    fake.write_text("#!" + sys.executable + "\n" + FAKE.replace('    print("Waiting for authentication to complete...")',
                    f'    assert input("Enter Pass extra password: ") == {marker!r}'))
    c = client(env)
    try:
        job = c.call("connect", vaults=["Bots"])
        state = wait(c, job, ("waiting_for_extra_password", "failed"))
        assert state["state"] == "waiting_for_extra_password", state
        url = state["cloud_computer_url"]
        content = urllib.request.urlopen(url).read().decode()
        assert 'type="password"' in content
        body = urllib.parse.urlencode({"password": marker}).encode()
        bad = urllib.request.Request(url, data=body, headers={"Origin": "https://attacker.example"})
        try:
            urllib.request.urlopen(bad)
        except urllib.error.HTTPError as exc:
            assert exc.code == 403
        else:
            raise AssertionError("cross-origin submission accepted")
        answer = urllib.request.urlopen(urllib.request.Request(url, data=body)).read().decode()
        assert marker not in answer
        done = wait(c, job)
        assert done["state"] == "connected", done
        assert marker not in json.dumps([job, state, done]) + Path(log).read_text()
        assert_cleaned(entries(log))
    finally:
        c.close()


def test_resume_after_grant_failure_preserves_only_copy_of_token():
    root, pat, log, env = workspace()
    env["SETUP_GRANT_NOT_ALLOWED"] = "1"
    c = client(env)
    try:
        job = c.call("connect", vaults=["Bots"])
        assert wait(c, job)["state"] == "failed"
        assert Path(pat).read_text().strip() == CREATED
        assert Path(pat + ".pending").exists()
        expect_error(c, "list_vaults", "incomplete")
    finally:
        c.close()
    del env["SETUP_GRANT_NOT_ALLOWED"]
    c = client(env)
    try:
        job = c.call("connect", mode="resume")
        assert wait(c, job)["state"] == "connected"
        assert not Path(pat + ".pending").exists()
        assert json.loads(Path(pat + ".meta").read_text())["roles"] == {"Bots": "editor"}
        assert len([r for r in entries(log) if r["args"][:2] == ["agent", "create"]]) == 1
        assert_cleaned(entries(log))
    finally:
        c.close()


def test_cloud_schema_never_accepts_or_returns_raw_secrets():
    root, pat, log, env = workspace()
    c = client(env)
    try:
        tools = {t["name"]: t for t in c.rpc("tools/list")["tools"]}
        assert "get_totp" not in tools and "save_totp" not in tools
        assert "fill_totp" in tools
        for tool in tools.values():
            assert not {"password", "seed", "otpauth_uri", "token"} & tool["inputSchema"]["properties"].keys()
        expect_error(c, "create_login", "unknown argument password", title="x", password="secret", reason="save")
    finally:
        c.close()


def test_renew_list_failure_keeps_rotated_token_and_resume_verifies_it():
    root, pat, log, env = workspace()
    c = client(env)
    try:
        assert wait(c, c.call("connect", vaults=["Bots"]))["state"] == "connected"
    finally:
        c.close()
    env["SETUP_LIST_FAIL"] = "1"
    c = client(env)
    try:
        assert wait(c, c.call("connect", mode="renew"))["state"] == "failed"
        assert Path(pat).read_text().strip() == RENEWED
        assert Path(pat + ".pending").exists()
        expect_error(c, "session_info", "incomplete")
    finally:
        c.close()
    del env["SETUP_LIST_FAIL"]
    c = client(env)
    try:
        assert wait(c, c.call("connect", mode="resume"))["state"] == "connected"
        assert Path(pat).read_text().strip() == RENEWED
        assert not Path(pat + ".pending").exists()
        assert_cleaned(entries(log))
    finally:
        c.close()


def test_mcp_approval_binds_write_and_decline_never_changes_vault():
    from harness import install, server_env, write, calls
    root = install()
    write(root, "shares.json", {"shares": [{"id": "share1", "name": "Bots", "share_type": "Vault", "share_role": "Editor"}]})
    seen = []
    def deny(params):
        seen.append(params)
        return {"action": "decline"}
    env = server_env(root, PASS_APPROVAL_MODE="mcp")
    c = client(env, deny)
    try:
        expect_error(c, "create_login", "denied", share_id="share1", title="Test account", generate_password=True, reason="requested account")
        assert len(seen) == 1 and "Test account" in seen[0]["message"]
        assert "requested account" in seen[0]["message"]
        assert not Path(root, "created.json").exists()
        c.consent = accept
        result = c.call("create_login", share_id="share1", title="Test account", generate_password=True, reason="requested account")
        assert result == {"item_id": "item-new"}
        saved = Path(root, "created.json").read_text()
        assert len(saved) > 20 and "password" in saved
        assert not any(cmd[:2] == ["item", "totp"] for cmd in calls(root))
    finally:
        c.close()


def test_disconnect_denied_preserves_token_accepted_removes_it_for_all_bots():
    from harness import install, server_env
    root = install()
    env = server_env(root, PASS_APPROVAL_MODE="mcp")
    c, other = client(env), client(env)
    try:
        c.consent = lambda _: {"action": "decline"}
        expect_error(c, "disconnect", "denied")
        assert Path(root, "pat").exists()
        c.consent = accept
        assert c.call("disconnect") == {"state": "disconnected", "remote_token_revoked": False}
        assert not Path(root, "pat").exists()
        expect_error(other, "list_vaults", "Disconnected")
    finally:
        c.close()
        other.close()


def test_sigterm_during_login_cleans_account_session():
    root, pat, log, env = workspace()
    fake = Path(env["PASS_CLI"])
    fake.write_text("#!" + sys.executable + "\n" + FAKE.replace('    print("Waiting for authentication to complete...")',
                    '    print("Waiting", flush=True)\n    import time\n    time.sleep(600)'))
    c = client(env)
    job = c.call("connect", vaults=["Bots"])
    assert job["state"] == "waiting_for_browser"
    c.p.terminate()
    c.p.wait(timeout=10)
    assert_cleaned(entries(log))
    assert not Path(pat).exists()


if __name__ == "__main__":
    for name, test in list(globals().items()):
        if name.startswith("test_"):
            test()
            print("OK", name)
