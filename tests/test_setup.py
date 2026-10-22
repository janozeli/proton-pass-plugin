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
        print("Agent access granted successfully")
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
    assert meta == {"name": "cursor-agent", "expires_at": 2000000000, "expiration": "1y", "vaults": ["Bots"], "role": "editor"}, meta
    assert stat.S_IMODE(os.stat(pat + ".meta").st_mode) == 0o600
    seen = entries(log)
    assert seen and all(row["pat_env"] is False for row in seen), seen
    assert all(row["mode"] == "0o700" for row in seen if row["args"] == ["login"]), seen
    sessions = {row["session"] for row in seen}
    assert sessions and all(not os.path.exists(path) for path in sessions), sessions
    assert not any(row["args"][:2] == ["agent", "create"] and "--vault" in row["args"] for row in seen), seen
    grant = next(row["args"] for row in seen if row["args"][:3] == ["agent", "access", "grant"])
    assert grant == ["agent", "access", "grant", "cursor-agent", "--vault-name", "Bots", "--role", "editor"], grant
    assert all(row["args"][:1] != ["info"] for row in seen)


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
    assert "token" not in meta
    sessions = {row["session"] for row in entries(log)}
    assert sessions and all(not os.path.exists(path) for path in sessions)
    assert any(row["args"][:2] == ["agent", "renew"] for row in entries(log))


def test_usage_does_not_print_a_token():
    result = run(dict(os.environ), )
    assert result.returncode != 0
    assert "usage:" in result.stderr
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
