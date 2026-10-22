"""Guided setup: web-login in a throwaway directory, then keep only an agent token.

Public pass-cli `login` prints an approval URL and waits. This command shows
that URL, creates or renews a vault-scoped agent, or changes one vault role,
writes the token to the PAT file, then logs out and deletes the full-account
directory. A grant is checked with a second temporary login. Token values are
never printed.
"""
import fcntl, json, os, pty, re, select, shutil, stat, subprocess, sys, tempfile, time

EXPIRATIONS = {"1h": 3600, "1d": 86400, "1w": 604800, "1m": 30 * 86400, "3m": 90 * 86400,
               "6m": 180 * 86400, "1y": 365 * 86400}
ROLES = {"viewer", "editor", "manager"}
TOKEN_PREFIX = "PROTON_PASS_PERSONAL_ACCESS_TOKEN="
DROP_ENV = ("PROTON_PASS_PERSONAL_ACCESS_TOKEN", "PROTON_PASS_PERSONAL_ACCESS_TOKEN_FILE",
            "PROTON_PASS_EXTRA_PASSWORD", "PROTON_PASS_EXTRA_PASSWORD_FILE")
# The owner's primary Personal vault rejects editor with NotAllowed. viewer and
# manager succeed. A later grant on the same vault changes the role in place.
# agent access revoke --share-id returned NotExists for the owner share id and
# the agent share id, so this command never revokes.
EDITOR_HINT = (
    "Proton Pass rejected editor on this vault. "
    "The owner's primary Personal vault allows viewer and manager, not editor. "
    "Grant editor on a dedicated vault, or grant manager. "
    "Manager can also manage who has access to the vault."
)
USAGE = """usage: python3 proton_pass_mcp.py setup --vault NAME [--vault NAME] [--name cursor-agent] [--expiration 1y] [--role editor|viewer|manager]
       python3 proton_pass_mcp.py setup --renew [--expiration 1y]
       python3 proton_pass_mcp.py setup --grant --vault NAME --role viewer|editor|manager

Web login prints an approval URL. Approve it in your browser. If the account
has a Proton Pass extra password, type it at the prompt on this terminal.
The full-account session is deleted when setup finishes. The token is written
to the PAT file and is not printed.
--grant changes one vault role for the agent named in the metadata. It checks
the new role with a fresh agent login and does not print the token."""


class SetupError(Exception):
    pass


def redact(text):
    text = re.sub(r"PROTON_PASS_PERSONAL_ACCESS_TOKEN=\S+", "PROTON_PASS_PERSONAL_ACCESS_TOKEN=[redacted]", text)
    return re.sub(r"pst_[A-Za-z0-9_-]+(?:::[^\s\"']+)?", "[redacted]", text)


def parse_args(argv):
    opts = {"vaults": [], "name": None, "expiration": "1y", "role": "editor",
            "renew": False, "grant": False, "role_set": False, "expiration_set": False}
    args = list(argv)
    index = 0
    while index < len(args):
        arg = args[index]
        if arg in ("--renew", "--grant"):
            opts["renew" if arg == "--renew" else "grant"] = True
            index += 1
            continue
        if arg not in ("--vault", "--name", "--expiration", "--role"):
            raise SetupError(USAGE)
        if index + 1 >= len(args):
            raise SetupError(USAGE)
        value = args[index + 1]
        if arg == "--vault":
            opts["vaults"].append(value)
        elif arg == "--name":
            opts["name"] = value
        elif arg == "--expiration":
            opts["expiration"] = value
            opts["expiration_set"] = True
        else:
            opts["role"] = value
            opts["role_set"] = True
        index += 2
    if opts["expiration"] not in EXPIRATIONS:
        raise SetupError("expiration must be one of: " + ", ".join(EXPIRATIONS))
    if opts["role"] not in ROLES:
        raise SetupError("role must be one of: viewer, editor, manager")
    if opts["grant"] and opts["renew"]:
        raise SetupError("pass either --grant or --renew")
    if opts["renew"] and (opts["vaults"] or opts["role_set"] or opts["name"]):
        raise SetupError("renew keeps the vault grants already on the agent; do not pass --vault")
    if opts["grant"]:
        if opts["name"]:
            raise SetupError("grant uses the agent name recorded in the metadata; do not pass --name")
        if opts["expiration_set"]:
            raise SetupError("grant does not change the token lifetime; do not pass --expiration")
        if len(opts["vaults"]) != 1 or not opts["role_set"]:
            raise SetupError(USAGE)
    if not opts["renew"] and not opts["grant"] and not opts["vaults"]:
        raise SetupError(USAGE)
    for vault in opts["vaults"]:
        if not vault or vault.startswith("-") or any(ord(c) < 32 for c in vault):
            raise SetupError("vault is invalid")
    if not opts["grant"] and not opts["renew"]:
        name = opts["name"] or "cursor-agent"
        if not re.fullmatch(r"[A-Za-z0-9._-]{1,64}", name):
            raise SetupError("name is invalid")
        opts["name"] = name
    return opts


def pat_path():
    return os.path.abspath(os.path.expanduser(os.environ.get("PASS_PAT_FILE", "~/.config/pass-agent/pat")))


def meta_path():
    return pat_path() + ".meta"


def pass_cli():
    return os.path.expanduser(os.environ.get("PASS_CLI", "~/.local/bin/pass-cli"))


def child_env(session_dir):
    env = os.environ.copy()
    for key in DROP_ENV:
        env.pop(key, None)
    env["PROTON_PASS_SESSION_DIR"] = session_dir
    env["PROTON_PASS_AGENT_REASON"] = "proton-pass plugin setup"
    env["PYTHONUNBUFFERED"] = "1"
    return env


def private_dir():
    path = tempfile.mkdtemp(prefix="proton-pass-setup-")
    os.chmod(path, 0o700)
    mode = stat.S_IMODE(os.stat(path).st_mode)
    if mode != 0o700 or not os.path.isdir(path) or os.path.islink(path):
        shutil.rmtree(path, ignore_errors=True)
        raise SetupError("the temporary session directory is not mode 0700")
    return path


def write_private(path, text):
    path = os.path.abspath(path)
    parent = os.path.dirname(path)
    os.makedirs(parent, exist_ok=True)
    if os.path.islink(path):
        raise SetupError("refusing to write through a symlink")
    fd, tmp = tempfile.mkstemp(dir=parent, prefix=".tmp-")
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w") as handle:
            handle.write(text if text.endswith("\n") else text + "\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp, path)
    except Exception:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    os.chmod(path, 0o600)
    if stat.S_IMODE(os.stat(path).st_mode) & 0o077:
        raise SetupError("could not keep the token file private")


def checked_name(name):
    if not isinstance(name, str) or not re.fullmatch(r"[A-Za-z0-9._-]{1,64}", name):
        raise SetupError("name is invalid")
    return name


def read_meta():
    path = meta_path()
    try:
        st = os.lstat(path)
    except OSError:
        raise SetupError("no agent metadata; run setup --vault NAME first")
    if stat.S_ISLNK(st.st_mode) or not stat.S_ISREG(st.st_mode) or st.st_uid != os.getuid() or st.st_mode & 0o077:
        raise SetupError("agent metadata is not a private file owned by this user")
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        with os.fdopen(fd) as handle:
            data = json.load(handle)
    except (OSError, ValueError):
        raise SetupError("agent metadata cannot be read")
    if not isinstance(data, dict) or not data.get("name") or not data.get("vaults"):
        raise SetupError("agent metadata is missing the agent name; run setup --vault NAME")
    data["name"] = checked_name(data["name"])
    return data


def read_pat():
    path = pat_path()
    try:
        st = os.lstat(path)
    except OSError:
        raise SetupError("PAT file cannot be read")
    if stat.S_ISLNK(st.st_mode) or not stat.S_ISREG(st.st_mode) or st.st_uid != os.getuid() or st.st_mode & 0o077:
        raise SetupError("PAT file is not a private file owned by this user")
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        with os.fdopen(fd) as handle:
            raw = handle.read().strip()
    except OSError:
        raise SetupError("PAT file cannot be read")
    if raw.startswith(TOKEN_PREFIX):
        raw = raw[len(TOKEN_PREFIX):].strip().strip('"')
    if not raw.startswith("pst_") or "::" not in raw or any(c.isspace() for c in raw):
        raise SetupError("PAT file does not hold an agent token")
    return raw


def stored_roles(meta):
    roles = {}
    raw = meta.get("roles") if isinstance(meta, dict) else None
    if isinstance(raw, dict):
        for key, value in raw.items():
            if isinstance(key, str) and isinstance(value, str) and value.strip().lower() in ROLES:
                roles[key] = value.strip().lower()
    if roles:
        return roles
    fallback = meta.get("role") if isinstance(meta, dict) else None
    fallback = fallback.strip().lower() if isinstance(fallback, str) else ""
    if fallback not in ROLES:
        fallback = "editor"
    for key in (meta.get("vaults") if isinstance(meta, dict) else None) or []:
        if isinstance(key, str) and key:
            roles[key] = fallback
    return roles


def write_meta(name, roles, expires_at, expiration):
    body = {"name": name, "vaults": list(roles), "roles": roles}
    if len(set(roles.values())) == 1:
        body["role"] = next(iter(roles.values()))
    if isinstance(expires_at, int) and not isinstance(expires_at, bool):
        body["expires_at"] = expires_at
    if expiration in EXPIRATIONS:
        body["expiration"] = expiration
    write_private(meta_path(), json.dumps(body))


def extract_json(text):
    stripped = text.strip()
    try:
        return json.loads(stripped)
    except ValueError:
        pass
    positions = [(stripped.find(ch), ch) for ch in "[{"]
    positions = [(index, ch) for index, ch in positions if index >= 0]
    if not positions:
        raise SetupError("pass-cli agent command failed")
    start, opener = min(positions)
    end = stripped.rfind("]" if opener == "[" else "}")
    if end < start:
        raise SetupError("pass-cli agent command failed")
    try:
        return json.loads(stripped[start:end + 1])
    except ValueError:
        raise SetupError("pass-cli agent command failed")


def extract_token(text):
    data = extract_json(text)
    raw = data.get("token") if isinstance(data, dict) else None
    if not isinstance(raw, str):
        raise SetupError("pass-cli agent command did not return a token")
    if raw.startswith(TOKEN_PREFIX):
        raw = raw[len(TOKEN_PREFIX):]
    raw = raw.strip().strip('"')
    if not raw.startswith("pst_") or "::" not in raw or any(c.isspace() for c in raw):
        raise SetupError("pass-cli agent command did not return a token")
    return raw


def expire_from_list(text, name, fallback):
    try:
        data = extract_json(text)
    except SetupError:
        return fallback
    rows = data if isinstance(data, list) else data.get("agents", []) if isinstance(data, dict) else []
    for row in rows:
        if isinstance(row, dict) and row.get("name") == name and isinstance(row.get("expire_time"), int):
            return row["expire_time"]
    return fallback


def run_login(cli, env):
    master, slave = pty.openpty()
    proc = subprocess.Popen([cli, "login"], env=env, stdin=subprocess.DEVNULL, stdout=slave, stderr=None, close_fds=True)
    os.close(slave)
    flags = fcntl.fcntl(master, fcntl.F_GETFL)
    fcntl.fcntl(master, fcntl.F_SETFL, flags | os.O_NONBLOCK)
    buf = bytearray()
    url = None
    deadline = time.monotonic() + 600
    try:
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                proc.kill()
                raise SetupError("web login timed out after 10 minutes")
            ready, _, _ = select.select([master], [], [], min(0.5, remaining))
            if ready:
                try:
                    chunk = os.read(master, 4096)
                except OSError:
                    chunk = b""
                if chunk:
                    buf.extend(chunk)
                    if url is None:
                        match = re.search(r"https://\S+", buf.decode("utf-8", "replace"))
                        if match:
                            url = match.group(0).rstrip(").,")
                            if "pst_" in url:
                                proc.kill()
                                raise SetupError("web login printed a value that is not an approval URL")
                            print(f"\nOpen this URL and approve access:\n\n{url}\n\nWaiting for the browser approval to finish...\n",
                                  file=sys.stderr, flush=True)
            if proc.poll() is not None:
                while True:
                    try:
                        chunk = os.read(master, 4096)
                    except OSError:
                        break
                    if not chunk:
                        break
                    buf.extend(chunk)
                break
    finally:
        os.close(master)
        proc.wait(timeout=5)
    if proc.returncode != 0:
        detail = redact(buf.decode("utf-8", "replace")).strip()
        message = "web login failed"
        if detail and "pst_" not in detail:
            message = f"web login failed: {detail[-500:]}"
        raise SetupError(message)
    if url is None:
        raise SetupError("web login did not print an approval URL")
    print("Browser login finished.", file=sys.stderr, flush=True)
    return url


def run_capture(cli, args, env):
    try:
        result = subprocess.run([cli, *args], env=env, stdin=subprocess.DEVNULL, capture_output=True,
                                text=True, errors="replace", timeout=120)
    except (OSError, subprocess.TimeoutExpired):
        raise SetupError(f"pass-cli {args[0]} failed")
    if result.returncode != 0:
        detail = redact((result.stderr or "") + (result.stdout or "")).strip()
        message = f"pass-cli {args[0]} failed"
        if detail and "pst_" not in detail:
            message = f"{message}: {detail[-500:]}"
        raise SetupError(message)
    return result.stdout


def grant_access(cli, env, name, vault, role):
    try:
        run_capture(cli, ["agent", "access", "grant", name, "--vault-name", vault, "--role", role], env)
    except SetupError as exc:
        if role == "editor" and "notallowed" in str(exc).casefold():
            raise SetupError(f"{exc}. {EDITOR_HINT}")
        raise


def verify_roles(cli, env, expected):
    """Log in with the agent PAT and require each vault's share_role to match."""
    run_capture(cli, ["login"], env)
    try:
        data = extract_json(run_capture(cli, ["share", "list", "--only-vaults=true", "--output", "json"], env))
    except SetupError:
        raise SetupError("pass-cli share list did not return vault shares. Metadata was not updated.")
    rows = data.get("shares") if isinstance(data, dict) else data if isinstance(data, list) else None
    if not isinstance(rows, list):
        raise SetupError("pass-cli share list did not return vault shares. Metadata was not updated.")
    found = {}
    for row in rows:
        if not isinstance(row, dict):
            continue
        share_type = row.get("share_type")
        if isinstance(share_type, str) and share_type.lower() != "vault":
            continue
        vault_name = row.get("name") if isinstance(row.get("name"), str) else row.get("vault_name")
        actual = row.get("share_role")
        if isinstance(vault_name, str) and isinstance(actual, str):
            found.setdefault(vault_name, []).append(actual.strip())
    problems = []
    for vault, role in expected.items():
        actuals = found.get(vault) or []
        if not actuals:
            problems.append(f"vault {vault!r} is missing from share list")
        elif any(actual.casefold() != role.casefold() for actual in actuals):
            shown = ", ".join(repr(actual) for actual in actuals)
            problems.append(f"vault {vault!r} share_role is {shown}, expected {role!r}")
    if problems:
        raise SetupError("role check failed: " + "; ".join(problems) + ". Metadata was not updated.")


def logout(cli, env, session_dir):
    for args in (["logout"], ["logout", "--force"]):
        try:
            subprocess.run([cli, *args], env=env, stdin=subprocess.DEVNULL, capture_output=True, timeout=60)
        except (OSError, subprocess.TimeoutExpired):
            pass
    shutil.rmtree(session_dir, ignore_errors=True)


def configured_message(name, roles, expires_at, verified):
    listed = ", ".join(f"{vault} ({roles[vault]})" for vault in roles)
    lines = [
        f"Agent {name!r} is configured for {listed}.",
        f"Token file: {pat_path()} (mode 0600). The token value was not printed.",
    ]
    if isinstance(expires_at, int) and not isinstance(expires_at, bool):
        when = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(expires_at))
        days = max(0, int((expires_at - time.time()) // 86400))
        lines.append(
            f"Expiration: {when} (about {days} days). This is the token lifetime, not the 2-hour pass-cli login session."
        )
    if verified:
        lines.append("Vault roles were checked with a fresh agent login.")
        lines.append("A running server logs in again before it reads vault roles, so this change is visible without a restart.")
    if "manager" in roles.values():
        lines.append("Manager can also manage who has access to the vault.")
    lines.append("The full-account session directory was deleted.")
    script = os.path.abspath(os.path.join(os.path.dirname(__file__), "proton_pass_mcp.py"))
    lines.append("When fewer than 14 days remain, session_info warns. Renew with browser approval:")
    lines.append(f"  python3 {script} setup --renew")
    return "\n".join(lines)


def run(opts):
    cli = pass_cli()
    full_dir = verify_dir = None
    full_env = verify_env = None
    message = None
    try:
        if opts["grant"] or opts["renew"]:
            meta = read_meta()
            name = meta["name"]
            token = read_pat() if opts["grant"] else None
        else:
            meta = None
            name = opts["name"]
            token = None
        full_dir = private_dir()
        full_env = child_env(full_dir)
        run_login(cli, full_env)
        if opts["grant"]:
            vault, role = opts["vaults"][0], opts["role"]
            grant_access(cli, full_env, name, vault, role)
            roles = stored_roles(meta)
            roles[vault] = role
            verify_dir = private_dir()
            verify_env = child_env(verify_dir)
            verify_env["PROTON_PASS_PERSONAL_ACCESS_TOKEN"] = token
            token = None
            verify_roles(cli, verify_env, {vault: role})
            expires_at = meta.get("expires_at")
            write_meta(name, roles, expires_at, meta.get("expiration"))
            message = configured_message(name, roles, expires_at, verified=True)
        elif opts["renew"]:
            stdout = run_capture(cli, ["agent", "renew", name, "--expiration", opts["expiration"]], full_env)
            token = extract_token(stdout)
            listed = run_capture(cli, ["agent", "list", "--output", "json"], full_env)
            expires_at = expire_from_list(listed, name, int(time.time()) + EXPIRATIONS[opts["expiration"]])
            roles = stored_roles(meta)
            if not roles:
                raise SetupError("agent metadata is missing vault roles; run setup --vault NAME")
            write_private(pat_path(), token)
            token = None
            write_meta(name, roles, expires_at, opts["expiration"])
            message = configured_message(name, roles, expires_at, verified=False)
        else:
            role = opts["role"]
            roles = {vault: role for vault in opts["vaults"]}
            stdout = run_capture(cli, ["agent", "create", name, "--expiration", opts["expiration"]], full_env)
            for vault in roles:
                grant_access(cli, full_env, name, vault, role)
            # agent create shows the token once. Save it before the role check
            # so a failed check does not throw away the only copy.
            token = extract_token(stdout)
            listed = run_capture(cli, ["agent", "list", "--output", "json"], full_env)
            expires_at = expire_from_list(listed, name, int(time.time()) + EXPIRATIONS[opts["expiration"]])
            write_private(pat_path(), token)
            verify_dir = private_dir()
            verify_env = child_env(verify_dir)
            verify_env["PROTON_PASS_PERSONAL_ACCESS_TOKEN"] = token
            token = None
            try:
                verify_roles(cli, verify_env, roles)
            except SetupError as exc:
                raise SetupError(f"{exc} The agent token was saved.")
            write_meta(name, roles, expires_at, opts["expiration"])
            message = configured_message(name, roles, expires_at, verified=True)
    finally:
        if verify_dir is not None and verify_env is not None:
            verify_env.pop("PROTON_PASS_PERSONAL_ACCESS_TOKEN", None)
            logout(cli, verify_env, verify_dir)
        if full_dir is not None and full_env is not None:
            logout(cli, full_env, full_dir)
    if any(path and os.path.exists(path) for path in (full_dir, verify_dir)):
        raise SetupError("the session directory could not be deleted")
    print(message, file=sys.stderr)


def main(argv=None):
    try:
        run(parse_args(sys.argv[1:] if argv is None else argv))
    except SetupError as exc:
        sys.exit("proton-pass: " + redact(str(exc)))
