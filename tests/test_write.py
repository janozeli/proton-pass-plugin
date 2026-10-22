import json, os, re, time
from harness import PASSWORD, SERVER, Operator, calls, error, start, write


def logins(d):
    return [call for call in calls(d) if call == ["login"]]

READ_ONLY = "this agent token can read and fill items"
SEED = "JBSWY3DPEHPK3PXP"


def editor(d):
    write(d, "shares.json", {"shares": [{"id": "share1", "name": "V", "share_type": "Vault", "share_role": "Editor"}]})


def plain_item(d):
    write(d, "item.json", {"item": {"id": "item1", "share_id": "share1", "content": {
        "title": "Bank",
        "content": {"Login": {"username": "ada", "email": "ada@example.com", "password": PASSWORD,
                              "urls": ["https://bank.com/login"]}},
    }}})


def created(d):
    path = os.path.join(d, "created.json")
    return json.load(open(path)) if os.path.exists(path) else None


def test_session_info_never_calls_info_and_the_session_still_works():
    d, c = start()
    try:
        info = c.call("session_info")
        assert info["identity_type"] == "agent_token", info
        assert info["name"] is None and info["can_write"] is False, info
        assert info["vaults"] == [{"name": "V", "vault_id": "v", "share_id": "share1", "role": "Viewer", "access": "read"}]
        assert info["expiration_warning"] is False and info["renew_command"].endswith("setup --renew"), info
        assert all(call[:1] != ["info"] for call in calls(d)), calls(d)
        assert c.call("list_vaults")[0]["name"] == "V"
        assert logins(d) == [["login"]], calls(d)
        text = open(SERVER).read() + open(os.path.join(os.path.dirname(SERVER), "setup_agent.py")).read()
        assert not re.search(r"""cli(?:_json)?\(\s*["']info["']""", text)
    finally:
        c.close()


def test_session_info_warns_below_14_days_and_hides_a_token_stored_beside_the_metadata():
    d, c = start()
    try:
        soon = int(time.time()) + 10 * 86400 + 100
        write(d, "pat.meta", {"name": "cursor-agent", "expires_at": soon, "vaults": ["V"],
                              "token": "pst_SHOULD_NOT_LEAK::key"})
        os.chmod(os.path.join(d, "pat.meta"), 0o600)
        info = c.call("session_info")
        blob = json.dumps(info)
        assert "pst_" not in blob and "SHOULD_NOT_LEAK" not in blob, blob
        assert info["name"] == "cursor-agent" and info["days_remaining"] == 10, info
        assert info["expiration_warning"] is True and "setup --renew" in info["warning"], info
        later = int(time.time()) + 20 * 86400 + 100
        write(d, "pat.meta", {"name": "cursor-agent", "expires_at": later, "vaults": ["V"]})
        os.chmod(os.path.join(d, "pat.meta"), 0o600)
        quiet = c.call("session_info")
        assert quiet["expiration_warning"] is False and quiet["days_remaining"] == 20 and quiet["warning"] is None, quiet
        write(d, "pat.meta", {"name": "cursor-agent", "expires_at": int(time.time()) - 100, "vaults": ["V"]})
        os.chmod(os.path.join(d, "pat.meta"), 0o600)
        expired = c.call("session_info")
        assert expired["expiration_warning"] is True and expired["days_remaining"] < 0, expired
        assert "expired" in expired["warning"]
        os.chmod(os.path.join(d, "pat.meta"), 0o644)
        hidden = c.call("session_info")
        assert hidden["name"] is None and hidden["expires_at"] is None, hidden
        assert all(call[:1] != ["info"] for call in calls(d))
        assert c.call("list_vaults")[0]["name"] == "V"
    finally:
        c.close()


def test_create_login_refuses_a_read_only_token_before_writing():
    d, c = start()
    try:
        got = error(c, "create_login", vault="V", title="Mail", password=PASSWORD, reason="save")
        assert got.startswith(READ_ONLY), got
        assert created(d) is None
        assert not any(call[:3] == ["item", "create", "login"] for call in calls(d)), calls(d)
        assert all(PASSWORD not in json.dumps(call) for call in calls(d))
    finally:
        c.close()


def test_create_login_waits_for_approval_and_does_not_return_the_password():
    d, c = start()
    editor(d)
    try:
        assert error(c, "create_login", vault="V", title="Mail", password=PASSWORD, reason="save") == "approval unavailable"
        assert created(d) is None
        op = Operator(d)
        got = c.call("create_login", vault="V", title="Mail", username="ada", password=PASSWORD,
                     urls=["https://mail.example/login"], reason="save")
        assert got == {"item_id": "item-new"}, got
        assert PASSWORD not in json.dumps(got) and PASSWORD not in json.dumps(op.prompts)
        assert all(PASSWORD not in json.dumps(call) for call in calls(d))
        body = created(d)
        assert body["password"] == PASSWORD and body["title"] == "Mail" and body["username"] == "ada"
        assert op.prompts[-1]["action"] == "write" and op.prompts[-1]["change"] == "create login"
        op.close()
    finally:
        c.close()


def test_generate_password_is_not_returned_or_passed_on_the_command_line():
    d, c = start()
    editor(d)
    op = Operator(d)
    try:
        got = c.call("create_login", share_id="share1", title="Mail", generate_password=True, reason="save")
        body = created(d)
        secret = body["password"]
        assert got == {"item_id": "item-new"} and secret and secret not in json.dumps(got)
        assert secret not in json.dumps(op.prompts)
        assert all(secret not in json.dumps(call) for call in calls(d))
        assert error(c, "create_login", share_id="share1", title="Mail", password=PASSWORD,
                     generate_password=True, reason="save") == "pass password or generate_password, not both"
    finally:
        op.close()
        c.close()


def test_bad_seed_is_rejected_without_echoing_it():
    d, c = start()
    editor(d)
    op = Operator(d)
    try:
        marker = "BADSEED1"
        got = error(c, "create_login", share_id="share1", title="Mail", password=PASSWORD, seed=marker, reason="save")
        assert got == "TOTP secret is invalid" and marker not in got, got
        assert created(d) is None
    finally:
        op.close()
        c.close()


def test_save_totp_recreates_a_plain_login_and_refuses_items_that_would_lose_fields():
    d, c = start()
    editor(d)
    op = None
    try:
        got = error(c, "save_totp", share_id="share1", item_id="item1", seed=SEED, reason="add 2fa")
        assert "cannot edit a login TOTP" in got, got
        assert SEED not in got and created(d) is None
        plain_item(d)
        denied = Operator(d, reply={"op": "deny"})
        assert error(c, "save_totp", share_id="share1", item_id="item1", seed=SEED, reason="add 2fa") == "release denied"
        assert created(d) is None
        denied.close()
        op = Operator(d)
        got = c.call("save_totp", share_id="share1", item_id="item1", seed=SEED, reason="add 2fa")
        assert got == {"item_id": "item-new", "replaced_item_id": "item1"}, got
        blob = json.dumps(got) + json.dumps(op.prompts)
        assert SEED not in blob and PASSWORD not in blob and "otpauth:" not in blob
        body = created(d)
        assert body["password"] == PASSWORD and body["totp_uri"].startswith("otpauth://totp/login?secret=JBSWY3DPEHPK3PXP")
        assert "item1" in open(os.path.join(d, "deleted")).read()
        assert all(call[:1] != ["info"] for call in calls(d))
    finally:
        if op:
            op.close()
        c.close()


def test_render_write_prompt_has_no_secret_values():
    sys_path = os.path.join(os.path.dirname(SERVER), "..")
    import sys
    sys.path.insert(0, os.path.dirname(SERVER))
    from proton_pass_mcp import render
    text = render({"action": "write", "title": "Bank", "change": "create login", "reason": "save a login"})
    assert "create login" in text and PASSWORD not in text and "otpauth" not in text
    assert "approve" in text


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
        raise SystemExit(f"{failed} of {len(tests)} write tests failed")
    print(f"{len(tests)} write tests OK")
