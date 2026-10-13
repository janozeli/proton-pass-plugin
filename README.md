# Proton Pass plugin

Stdio MCP server for [Cursor](https://cursor.com/docs/plugins). It wraps the official [`pass-cli`](https://protonpass.github.io/pass-cli/) and ships with a skill that tells the agent which tool to call. The server is Python's standard library. `fill_login` also needs Playwright.

The agent can list vaults, search items, and read item metadata. It never receives a password, a note, or a TOTP seed. Three tools release a credential. `fill_login` types a login into a browser tab, `get_totp` returns the current code, and `run_approved` runs one program with secrets in its environment. Each release waits until you type `approve` in a terminal that the agent cannot write to.

The approval helper and `run_approved` need Linux. The helper checks the caller's uid with `SO_PEERCRED`, and `run_approved` runs the program inside [bubblewrap](https://github.com/containers/bubblewrap) (`bwrap`).

## Install

Install `pass-cli` from the [pass-cli docs](https://protonpass.github.io/pass-cli/). The default path is `~/.local/bin/pass-cli`. For `run_approved`, install bubblewrap (`sudo apt install bubblewrap` on Debian and Ubuntu). On Ubuntu 24.04 and later, `bwrap` also needs unprivileged user namespaces, which AppArmor blocks by default (`kernel.apparmor_restrict_unprivileged_userns`).

Create a personal access token in Proton Pass and grant it viewer access only to the vaults the agent should read. Store the token in a file that only you can read:

```bash
mkdir -p ~/.config/pass-agent
umask 077
printf '%s\n' 'YOUR_TOKEN' > ~/.config/pass-agent/pat
```

`umask 077` creates the file as mode 0600. Mode 0400 works too. The server refuses a token file that the group or other users can access, a symlink, or a file another user owns.

To load the plugin locally, copy this repository to `~/.cursor/plugins/local/proton-pass` and run **Developer: Reload Window**. The folder must be a real directory. Cursor skips a symlink that points outside `~/.cursor/plugins/local`. After the reload, the Proton Pass skill and the `proton-pass` MCP server show up under **Customize**.

`fill_login` needs the Playwright Python package (`pip install playwright`) and a Chrome process started with `--remote-debugging-port`.

## Start the approval helper

Run the helper in a terminal that you keep open:

```bash
python3 ~/.cursor/plugins/local/proton-pass/server/proton_pass_mcp.py approve
```

The helper listens on `approve.sock` in the session directory. It reads your answer from its own terminal (`/dev/tty`), not from a pipe. For each request it prints the item title, the exact origin or the exact argv, and the agent's reason:

```text
proton-pass release request
  action:  run
  argv:    '/usr/bin/psql'
           '--host=127.0.0.1'
           '--command=select 1'
  env:     'PGPASSWORD' = 'pass://SHARE_ID/ITEM_ID/password' (field 'password' of 'Dev database')
  network: off (type approve-net to allow it)
  reason:  'check the dev database is up'
Type approve to release. Anything else denies.
```

Every string on the prompt, including item titles from your vault, is printed with Python `repr`, so an escape sequence shows up as text and cannot redraw your terminal. Type `approve` to release the request. For a `run_approved` request, type `approve-net` to release it with network access. Any other line denies it. A request that gets no answer within 180 seconds is denied.

If the helper is not running, `fill_login`, `get_totp`, and `run_approved` fail with `approval unavailable`. The metadata tools keep working.

## Configure

`mcp.json` leaves configuration to the process environment. The server and the helper read these variables and expand `~`:

| Variable | Default | Role |
| --- | --- | --- |
| `PASS_CLI` | `~/.local/bin/pass-cli` | `pass-cli` binary |
| `PASS_PAT_FILE` | `~/.config/pass-agent/pat` | Personal access token file (mode 0600 or 0400) |
| `PROTON_PASS_SESSION_DIR` | `~/.local/share/pass-agent` | Session directory for this agent, separate from a normal `pass-cli` login. It also holds `approve.sock` |
| `PASS_CDP_PORT` | `9222` | Chrome remote-debugging port on `127.0.0.1` that `fill_login` connects to |

Set a variable in `mcp.json` under `mcpServers.proton-pass.env` when a default is wrong. Give the helper the same `PROTON_PASS_SESSION_DIR`, or the server will not find it. Do not put the token itself in `mcp.json` or in the repository.

## Tools

| Tool | Needs approval | What the model receives |
| --- | --- | --- |
| `list_vaults` | No | Vault names and ids |
| `search_items` | No | Title, type, vault, `share_id`, `item_id`. Trashed items are omitted |
| `describe_item` | No | URLs without `user:password@`, username, email, and booleans for password, TOTP, and note |
| `get_totp` | Yes | `{"code": "123456"}` |
| `fill_login` | Yes | `{"filled": ["username", "password"], "submitted": true}`. No URL and no password |
| `run_approved` | Yes | `{"exit_code": 0}`. No output |

Pass a short `reason`. The helper shows it to you, and Proton stores it in the audit log.

## Security model

The model is not a trusted caller. It may name an item and give a reason. It may not choose where a secret goes, and it may not read one. The tool schema is where that rule lives. No tool takes a command string, a URL to match, a CSS selector, a CDP port, or a working directory. At startup the server checks every tool and parameter name against a forbidden set (`get_secret`, `run_with_secrets`, `command`, `url_match`, `url`, `username_selector`, `password_selector`, `cdp_port`, `cwd`, `value`, `password`, `totp_uri`) and exits if one appears.

`fill_login` takes its targets only from the websites saved on the item. An origin uses the browser's spelling of scheme, host, and port. The host is lowercase punycode. IPv6 is in brackets. The port is omitted when it is 443 for `https` or 80 for `http`. A saved URL without a scheme counts as `https`. `http` matches only a saved `http` URL. Matching is equality, so `login.bank.com` does not match a saved `bank.com`. The server reads `http://127.0.0.1:<PASS_CDP_PORT>/json/version` and connects only to a browser websocket on `127.0.0.1`. Exactly one tab's main frame must match. If none or several match, nothing is typed. The server asks you, then runs one script in that main frame. The script compares `location.origin` again and types in the same turn, so a tab that navigated while you read the prompt receives nothing. The password goes only into the first visible `input[type=password]` in the main frame, never into a hidden field, an iframe, or a text box. With `submit: true` the server presses Enter and waits one second. If the tab has left the origin by then, it clears any password field in the tab. `"submitted": true` means Enter was pressed, not that the site accepted the login. Errors report the number of open tabs, never their URLs.

`run_approved` runs the argv you approved and nothing else. `argv[0]` must be an absolute path, and the server never adds `bash` or `-c`. A reference is exactly `pass://SHARE_ID/ITEM_ID/FIELD`. The server rejects `?`, `#`, `%`, an extra slash, and a leading `-`. `pass-cli` treats `?totp=uri` as a request for the TOTP seed and percent-decodes each segment, so those spellings never reach it. A `reason` that contains `pass://` is rejected. `pass-cli run` resolves a `pass://` value in any environment variable, including the audit reason. A reply from the helper can only allow or deny. It cannot change the argv. `pass-cli run` starts with stdin, stdout, and stderr on `/dev/null` and a fresh environment that holds only `PATH`, `PROTON_PASS_SESSION_DIR`, a fixed `PROTON_PASS_AGENT_REASON`, and the `pass://` bindings. The command is `pass-cli run -- bwrap --unshare-user --unshare-net --die-with-parent --unsetenv ... -- <argv>`. `bwrap` removes the session directory, the reason, the token, `PASS_PAT_FILE`, `PASS_CLI`, and `HOME` from the environment, and sets `HOME=/tmp` and `PATH=/usr/bin:/bin`. The program sees `/usr`, `/bin`, `/lib`, and `/lib64` read-only, plus `/etc/resolv.conf`, `/etc/hosts`, `/etc/nsswitch.conf`, and `/etc/ssl`. It also sees a fresh `/proc` and `/dev`, and an empty `/tmp` as its working directory. It cannot see your home directory, the session directory, or the token file. Without `approve-net` it has its own network namespace and cannot reach the host's ports. `approve-net` drops only `--unshare-net`. If `bwrap` is missing, the server refuses the request before asking you. If `bwrap` fails to start the program, the exit code is nonzero and nothing runs outside the sandbox. Output is discarded. Since no output comes back, a short secret or an encoded secret has no path to the model, and the server keeps no redaction list.

With `approve-net`, name lookup uses those `/etc` files and TLS uses `/etc/ssl`. The rest of `/etc` is not mounted. Without `approve-net` the network namespace is empty, so name lookup fails.

The session directory must be a real directory that you own. The server sets it to mode 0700, and it refuses to start if the directory or its `.session` file is a symlink. `share_id`, `item_id`, and vault names that start with `-` or contain a newline never reach `pass-cli`. Errors are fixed strings such as `pass-cli item failed`. They never include `pass-cli` stderr. The server logs in again only when `pass-cli` reports an unauthenticated client, an unauthorized token, or an expired session.

## What this does not stop

- Another process running as your user can bind the approval socket before the helper does, and it can read the token file from outside the sandbox. Such a process does not need this server to reach your vault.
- A release that is waiting for you does not notice when the agent cancels the request.
- The exit code is one byte that the model sees.
- With `approve-net`, an approved program can send its secrets to any network it can reach.
- `fill_login` without `submit` leaves the password in the page, where anything that can read the page can read it.

## Tests

Offline tests use a fake `pass-cli` that resolves `pass://` values and execs the `run` argv, and they speak MCP over stdio. The run tests need `bwrap` and `/usr/bin/python3`. `test_fill.py` drives a headless Chromium from Playwright (`python3 -m playwright install chromium`):

```bash
python3 tests/test_relogin.py
python3 tests/test_offline.py
python3 tests/test_tabs.py
python3 tests/test_fill.py
```

`tests/e2e_real.py` talks to a real vault and answers approvals itself. It prints no secret values. It needs the token file, `pass-cli`, and `bwrap`. CI runs the offline tests only.

## License

MIT
