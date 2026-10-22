import json, os, stat, subprocess, sys, tempfile, textwrap

from harness import SERVER

FAKE = textwrap.dedent(r'''
    import json, os, stat, sys
    log = os.environ["SETUP_LOG"]
    session = os.environ.get("PROTON_PASS_SESSION_DIR")
    mode = None
    if session and os.path.isdir(session):
        mode = oct(stat.S_IMODE(os.stat(session).st_mode))
    with open(log, "a") as handle:
        handle.write(json.dumps({
            "args": sys.argv[1:], "session": session,
            "pat_env": "PROTON_PASS_PERSONAL_ACCESS_TOKEN" in os.environ, "mode": mode,
        }) + "\n")
    args = sys.argv[1:]
    if args == ["login"] and os.environ.get("PROTON_PASS_PERSONAL_ACCESS_TOKEN"):
        token = os.environ["PROTON_PASS_PERSONAL_ACCESS_TOKEN"]
        if "pst_" not in token or "::" not in token or any(c.isspace() for c in token):
            sys.stderr.write("bad pat\n")
            sys.exit(1)
        open(os.path.join(session, "verified"), "w").write("ok")
        sys.exit(0)
    if args == ["login"]:
        if os.environ.get("SETUP_LOGIN_FAIL"):
            sys.exit(1)
        print("\nPlease open the following URL in your browser to complete authentication:\n")
        print("https://account.proton.me/authorize?token=browser-approval\n")
        print("Waiting for authentication to complete...")
        print("Successfully logged in as user@example.com")
        open(os.path.join(session, "full-account"), "w").write("account-session")
        sys.exit(0)
    if args[:2] == ["agent", "create"]:
        sys.stderr.write("pst_TESTTOKEN::supersecretkey\n")
        print(json.dumps({"token": "PROTON_PASS_PERSONAL_ACCESS_TOKEN=pst_TESTTOKEN::supersecretkey", "instruction": "ignore"}))
        sys.exit(0)
    if args[:3] == ["agent", "access", "grant"]:
        if os.environ.get("SETUP_GRANT_NOT_ALLOWED"):
            sys.stderr.write("Error: NotAllowed\n")
            sys.exit(1)
        vault = args[args.index("--vault-name") + 1]
        role = args[args.index("--role") + 1]
        with open(os.environ["SETUP_LOG"] + ".grants", "a") as handle:
            handle.write(json.dumps({"vault": vault, "role": role}) + "\n")
        print("Agent access granted successfully")
        sys.exit(0)
    if args[:2] == ["share", "list"]:
        if args != ["share", "list", "--only-vaults=true", "--output", "json"]:
            sys.stderr.write("unexpected share list\n")
            sys.exit(2)
        if not session or not os.path.exists(os.path.join(session, "verified")):
            sys.stderr.write("requires an authenticated client\n")
            sys.exit(1)
        override = os.environ.get("SETUP_SHARE_ROLE")
        latest = {}
        grant_path = os.environ["SETUP_LOG"] + ".grants"
        if os.path.exists(grant_path):
            for line in open(grant_path):
                row = json.loads(line)
                latest[row["vault"]] = row["role"]
        shares = []
        for vault, role in latest.items():
            # Proton returns Editor/Viewer/Manager. Comparison is case-insensitive.
            shown = override or (role[:1].upper() + role[1:])
            shares.append({"name": vault, "share_role": shown, "share_type": "Vault"})
        print(json.dumps({"shares": shares}))
        sys.exit(0)
    if args[:2] == ["agent", "renew"]:
        print(json.dumps({"token": "pst_RENEWEDTOKEN::newsecretkey", "instruction": "ignore"}))
        sys.exit(0)
    if args[:2] == ["agent", "list"]:
        print(json.dumps([{"name": "cursor-agent", "pat_id": "pat1", "expire_time": 2000000000}]))
        sys.exit(0)
    if args[:1] == ["logout"]:
        sys.exit(0)
    sys.stderr.write("unexpected\n")
    sys.exit(2)
''')
CREATED = "pst_TESTTOKEN::supersecretkey"
RENEWED = "pst_RENEWEDTOKEN::newsecretkey"


def workspace():
    root = tempfile.mkdtemp()
    fake = os.path.join(root, "pass-cli")
    with open(fake, "w") as handle:
        handle.write("#!" + sys.executable + "\n" + FAKE)
    os.chmod(fake, 0o755)
    pat = os.path.join(root, "pat")
    log = os.path.join(root, "log")
    env = dict(os.environ)
    env.update({"PASS_CLI": fake, "PASS_PAT_FILE": pat, "SETUP_LOG": log,
                "PROTON_PASS_PERSONAL_ACCESS_TOKEN": "pst_PARENT::parentkey"})
    env.pop("SETUP_LOGIN_FAIL", None)
    return root, pat, log, env


def entries(log):
    return [json.loads(line) for line in open(log)] if os.path.exists(log) else []


def session_kinds(seen):
    full, verify = set(), set()
    for row in seen:
        if row["args"] == ["login"]:
            (verify if row["pat_env"] else full).add(row["session"])
    return full, verify


def assert_cleaned(seen):
    sessions = {row["session"] for row in seen if row["session"]}
    assert sessions and all(not os.path.exists(path) for path in sessions), sessions
    for path in sessions:
        assert any(row["session"] == path and row["args"] == ["logout", "--force"] for row in seen), seen
    return sessions


def run(env, *args):
    return subprocess.run([sys.executable, SERVER, "setup", *args], env=env, capture_output=True, text=True, timeout=30)


def test_setup_surfaces_the_url_stores_only_the_agent_token_and_deletes_the_account_session():
    root, pat, log, env = workspace()
    result = run(env, "--vault", "Bots", "--name", "cursor-agent", "--expiration", "1y", "--role", "editor")
    blob = result.stdout + result.stderr
    assert result.returncode == 0, blob
    assert "pst_" not in blob and "supersecretkey" not in blob and "parentkey" not in blob, blob
    assert "https://account.proton.me/authorize?token=browser-approval" in result.stderr
    assert "deleted" in result.stderr
    assert open(pat).read().strip() == CREATED
    assert stat.S_IMODE(os.stat(pat).st_mode) == 0o600
    meta = json.load(open(pat + ".meta"))
    assert meta == {"name": "cursor-agent", "vaults": ["Bots"], "roles": {"Bots": "editor"}, "role": "editor",
                    "expires_at": 2000000000, "expiration": "1y"}, meta
    assert stat.S_IMODE(os.stat(pat + ".meta").st_mode) == 0o600
    assert "fresh agent login" in result.stderr
    seen = entries(log)
    assert "pst_" not in open(log).read() and "supersecretkey" not in open(log).read()
    full, verify = session_kinds(seen)
    assert len(full) == 1 and len(verify) == 1 and full.isdisjoint(verify)
    assert all(row["pat_env"] is False for row in seen if row["session"] in full)
    checked = [row for row in seen if row["session"] in verify and row["args"][:1] != ["logout"]]
    assert checked and all(row["pat_env"] is True for row in checked)
    assert all(row["mode"] == "0o700" for row in seen if row["args"] == ["login"]), seen
    assert_cleaned(seen)
    assert not any(row["args"][:2] == ["agent", "create"] and "--vault" in row["args"] for row in seen), seen
    grant = next(row["args"] for row in seen if row["args"][:3] == ["agent", "access", "grant"])
    assert grant == ["agent", "access", "grant", "cursor-agent", "--vault-name", "Bots", "--role", "editor"], grant
    share = next(row for row in seen if row["args"][:2] == ["share", "list"])
    assert share["args"] == ["share", "list", "--only-vaults=true", "--output", "json"] and share["session"] in verify
    assert all(row["args"][:1] != ["info"] for row in seen)
    assert not any(arg == "revoke" for row in seen for arg in row["args"])


def test_failed_web_login_leaves_no_token_and_no_session_directory():
    root, pat, log, env = workspace()
    env["SETUP_LOGIN_FAIL"] = "1"
    result = run(env, "--vault", "Bots")
    assert result.returncode != 0
    assert "pst_" not in result.stdout + result.stderr
    assert not os.path.exists(pat)
    sessions = {row["session"] for row in entries(log)}
    assert sessions and all(not os.path.exists(path) for path in sessions)


def test_renew_repeats_browser_approval_and_replaces_the_token_without_printing_it():
    root, pat, log, env = workspace()
    assert run(env, "--vault", "Bots").returncode == 0
    os.remove(log)
    result = run(env, "--renew", "--expiration", "3m")
    blob = result.stdout + result.stderr
    assert result.returncode == 0, blob
    assert "pst_" not in blob and "newsecretkey" not in blob and "supersecretkey" not in blob
    assert "https://account.proton.me/authorize?token=browser-approval" in result.stderr
    assert open(pat).read().strip() == RENEWED
    meta = json.load(open(pat + ".meta"))
    assert meta["expiration"] == "3m" and meta["expires_at"] == 2000000000 and meta["vaults"] == ["Bots"]
    assert meta["roles"] == {"Bots": "editor"} and meta["role"] == "editor"
    assert "token" not in meta
    seen = entries(log)
    assert all(row["pat_env"] is False for row in seen), seen
    assert not any(row["args"][:2] == ["share", "list"] for row in seen)
    assert_cleaned(seen)
    assert any(row["args"][:2] == ["agent", "renew"] for row in seen)


def test_usage_does_not_print_a_token():
    result = run(dict(os.environ), )
    assert result.returncode != 0
    assert "usage:" in result.stderr
    assert "--grant" in result.stderr
    assert "pst_" not in result.stdout + result.stderr


def test_grant_verifies_the_new_role_and_updates_per_vault_roles():
    root, pat, log, env = workspace()
    assert run(env, "--vault", "Bots", "--role", "viewer").returncode == 0
    os.remove(log)
    result = run(env, "--grant", "--vault", "Bots", "--role", "editor")
    blob = result.stdout + result.stderr
    assert result.returncode == 0, blob
    assert "pst_" not in blob and "supersecretkey" not in blob and "parentkey" not in blob, blob
    assert "https://account.proton.me/authorize?token=browser-approval" in result.stderr
    assert "fresh agent login" in result.stderr
    assert "manage who has access" not in result.stderr
    assert open(pat).read().strip() == CREATED
    meta = json.load(open(pat + ".meta"))
    assert meta["name"] == "cursor-agent" and meta["roles"] == {"Bots": "editor"} and meta["role"] == "editor"
    assert meta["vaults"] == ["Bots"] and meta["expires_at"] == 2000000000
    seen = entries(log)
    assert "pst_" not in open(log).read()
    grant = [row["args"] for row in seen if row["args"][:3] == ["agent", "access", "grant"]]
    assert grant == [["agent", "access", "grant", "cursor-agent", "--vault-name", "Bots", "--role", "editor"]], grant
    assert not any(row["args"][:2] == ["agent", "create"] or row["args"][:2] == ["agent", "renew"] for row in seen)
    assert not any(arg == "revoke" or row["args"][:1] == ["info"] for row in seen for arg in row["args"])
    full, verify = session_kinds(seen)
    assert len(full) == 1 and len(verify) == 1 and full.isdisjoint(verify)
    assert all(row["pat_env"] is False for row in seen if row["session"] in full)
    share = next(row for row in seen if row["args"][:2] == ["share", "list"])
    assert share["args"] == ["share", "list", "--only-vaults=true", "--output", "json"] and share["session"] in verify
    assert all(row["mode"] == "0o700" for row in seen if row["args"] == ["login"])
    assert_cleaned(seen)

    os.remove(log)
    again = run(env, "--grant", "--vault", "Bots", "--role", "manager")
    blob = again.stdout + again.stderr
    assert again.returncode == 0, blob
    assert "manage who has access" in again.stderr
    assert "pst_" not in blob and "supersecretkey" not in blob
    meta = json.load(open(pat + ".meta"))
    assert meta["roles"] == {"Bots": "manager"} and meta["role"] == "manager"
    assert open(pat).read().strip() == CREATED

    os.remove(log)
    other = run(env, "--grant", "--vault", "Other", "--role", "viewer")
    blob = other.stdout + other.stderr
    assert other.returncode == 0, blob
    assert "pst_" not in blob
    meta = json.load(open(pat + ".meta"))
    assert meta["roles"] == {"Bots": "manager", "Other": "viewer"} and meta["vaults"] == ["Bots", "Other"], meta
    assert "role" not in meta
    assert_cleaned(entries(log))


def test_verify_mismatch_fails_and_deletes_both_sessions():
    root, pat, log, env = workspace()
    assert run(env, "--vault", "Bots", "--role", "editor").returncode == 0
    before = open(pat + ".meta").read()
    os.remove(log)
    env["SETUP_SHARE_ROLE"] = "viewer"
    result = run(env, "--grant", "--vault", "Bots", "--role", "manager")
    blob = result.stdout + result.stderr
    assert result.returncode != 0, blob
    assert "role check failed" in blob and "share_role" in blob, blob
    assert "'viewer'" in blob and "'manager'" in blob, blob
    assert "Metadata was not updated" in blob
    assert "pst_" not in blob and "supersecretkey" not in blob and "parentkey" not in blob
    assert open(pat + ".meta").read() == before
    assert open(pat).read().strip() == CREATED
    seen = entries(log)
    assert "pst_" not in open(log).read()
    full, verify = session_kinds(seen)
    assert len(full) == 1 and len(verify) == 1 and full.isdisjoint(verify)
    assert any(row["args"][:2] == ["share", "list"] and row["session"] in verify for row in seen)
    assert_cleaned(seen)


def test_editor_not_allowed_explains_the_personal_vault_and_deletes_the_session():
    root, pat, log, env = workspace()
    assert run(env, "--vault", "Bots", "--role", "viewer").returncode == 0
    before = open(pat + ".meta").read()
    os.remove(log)
    env["SETUP_GRANT_NOT_ALLOWED"] = "1"
    result = run(env, "--grant", "--vault", "Personal", "--role", "editor")
    blob = result.stdout + result.stderr
    assert result.returncode != 0, blob
    assert "NotAllowed" in blob and "dedicated vault" in blob and "manage who has access" in blob, blob
    assert "pst_" not in blob and "supersecretkey" not in blob
    assert open(pat + ".meta").read() == before
    seen = entries(log)
    assert not any(row["args"][:2] == ["share", "list"] for row in seen)
    assert session_kinds(seen)[1] == set()
    assert_cleaned(seen)

    os.remove(log)
    result = run(env, "--grant", "--vault", "Personal", "--role", "manager")
    blob = result.stdout + result.stderr
    assert result.returncode != 0, blob
    assert "NotAllowed" in blob and "dedicated vault" not in blob, blob
    assert "pst_" not in blob
    assert open(pat + ".meta").read() == before
    assert_cleaned(entries(log))


def test_grant_requires_metadata_one_vault_and_a_role():
    root, pat, log, env = workspace()
    missing = run(env, "--grant", "--vault", "Bots", "--role", "editor")
    assert missing.returncode != 0 and "metadata" in missing.stderr, missing.stderr
    assert entries(log) == []
    assert "pst_" not in missing.stdout + missing.stderr
    for args in (("--grant", "--vault", "Bots"), ("--grant", "--role", "editor"),
                 ("--grant", "--vault", "A", "--vault", "B", "--role", "editor"),
                 ("--grant", "--vault", "Bots", "--role", "editor", "--name", "other")):
        result = run(dict(os.environ), *args)
        assert result.returncode != 0, args
        assert "pst_" not in result.stdout + result.stderr


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
        raise SystemExit(f"{failed} of {len(tests)} setup tests failed")
    print(f"{len(tests)} setup tests OK")
