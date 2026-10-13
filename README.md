# Proton Pass plugin

Stdio MCP server for [Cursor](https://cursor.com/docs/plugins). It wraps the official [`pass-cli`](https://protonpass.github.io/pass-cli/) and ships with a skill that tells the agent which tool to call. The server uses Python and `idna` (`pip install -r requirements.txt`). `fill_login` also needs Playwright.

The agent can list vaults, search items, and read item metadata. It never receives a password, a note, or a TOTP seed. Three tools release a credential. `fill_login` types a login into a browser tab, `get_totp` returns the current code, and `run_approved` runs one program with secrets in its environment. Each release waits until you type `approve` in a terminal that the agent cannot write to.

The approval helper and `run_approved` need Linux. The helper checks the caller's uid with `SO_PEERCRED`, and `run_approved` runs the program inside [bubblewrap](https://github.com/containers/bubblewrap) (`bwrap`).

## Install

Install `pass-cli` from the [pass-cli docs](https://protonpass.github.io/pass-cli/). The default path is `~/.local/bin/pass-cli`. For `run_approved`, install bubblewrap and libseccomp (`sudo apt install bubblewrap libseccomp2` on Debian and Ubuntu). On Ubuntu 24.04 and later, `bwrap` also needs unprivileged user namespaces, which AppArmor blocks by default (`kernel.apparmor_restrict_unprivileged_userns`).

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

Every string on the prompt, including item titles from your vault, is printed with Python `repr`, so an escape sequence shows up as text and cannot redraw your terminal. Type `approve` to release the request. For a `run_approved` request, type `approve-net` to release it with network access. Any other line denies it. A request that gets no answer within 180 seconds is denied. The helper monitors both the terminal and the client connection, discards disconnected requests, and proceeds to the next request even if no complete answer was typed.

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
| `describe_item` | No | Origins (scheme, host, and port), username, email, and booleans for password, TOTP, and note. No path, query, or fragment |
| `get_totp` | Yes | `{"code": "123456"}` |
| `fill_login` | Yes | `{"filled": ["username", "password"], "submitted": false}`. No URL and no password |
| `run_approved` | Yes | `{"exit_code": 0}`. No output |

Pass a short `reason`. The helper shows at most 300 characters of it, and at most 1024 characters of each argv element. Proton stores the reason in the audit log. A reason that still contains `pass://` after Unicode normalization is rejected.

## Security model

The model is not a trusted caller. It may name an item and give a reason. It may not choose where a secret goes, and it may not read one. The tool schema is where that rule lives. No tool takes a command string, a URL to match, a CSS selector, a CDP port, or a working directory. At startup the server checks every tool and parameter name against a forbidden set (`get_secret`, `run_with_secrets`, `command`, `url_match`, `url`, `username_selector`, `password_selector`, `cdp_port`, `cwd`, `value`, `password`, `totp_uri`) and exits if one appears.

`fill_login` takes its targets only from the websites saved on the item. An origin uses the browser's spelling of scheme, host, and port. The host is lowercase punycode using non-transitional UTS #46 processing. Unsupported or ambiguous URLs (including backslashes, controls, invalid IDNA and legacy IPv4 spellings) are rejected. IPv6 is in brackets. The port is omitted when it is 443 for `https` or 80 for `http`. A saved URL without a scheme counts as `https`. `http` matches only a saved `http` URL. Matching is equality, so `login.bank.com` does not match a saved `bank.com`. The server reads `http://127.0.0.1:<PASS_CDP_PORT>/json/version` and connects only to a browser websocket on `127.0.0.1`. Exactly one tab's main frame must match. If none or several match, nothing is typed. The server asks you, then types from an isolated world the page cannot hook. That world checks `location.origin` again before it writes the password, so a tab that navigated while you read the prompt receives nothing. The password goes only into the first visible `input[type=password]` in the main frame, never into a hidden field, an iframe, or a text box. Eligible inputs must have positive width and height. After username events, the server selects and validates the password field again. It reports a successful password fill only if the field remains connected, eligible, and contains the requested value after synchronous input, change, and focus handlers. Automatic submission (`submit: true`) is refused before approval or filling. A form's action does not determine its final destination: submit buttons can override it and page event handlers can change it or issue requests during filling. Omit `submit` or set it to `false`, then inspect and submit the form manually. `"submitted": false` means the server did not submit the form. Errors report the number of open tabs, never their URLs.

`run_approved` runs the argv you approved and nothing else. Every argument is limited to 1,024 characters and displayed in full; longer arguments are rejected before approval or secret access. `argv[0]` must be an absolute path, and the server never adds `bash` or `-c`. A reference is exactly `pass://SHARE_ID/ITEM_ID/FIELD`. The server rejects `?`, `#`, `%`, an extra slash, and a leading `-`. `pass-cli` treats `?totp=uri` as a request for the TOTP seed and percent-decodes each segment, so those spellings never reach it. A `reason` that contains `pass://` after Unicode normalization is rejected. `pass-cli run` resolves a `pass://` value in any environment variable, including the audit reason. A reply from the helper can only allow or deny. It cannot change the argv. `pass-cli run` starts with stdin, stdout, and stderr on `/dev/null`. Its environment is an allowlist: `PATH`, `PROTON_PASS_SESSION_DIR`, a fixed `PROTON_PASS_AGENT_REASON`, and the bindings under names `PP0`, `PP1`, and so on. The names you approved are not in that environment, so a linker variable such as `LD_AUDIT` cannot run code before `bwrap` starts. Inside the sandbox a trusted Python trampoline first installs a libseccomp filter that denies `add_key`, `request_key`, and `keyctl` with `EPERM`, including with `approve-net`. The filter rejects non-native syscall ABIs and remains active across exec and child processes. If the library is unavailable or filter setup fails, the approved program is never executed. The trampoline then renames `PP0` to the approved name and drops every other variable. The command is `pass-cli run -- bwrap --unshare-user --unshare-pid --unshare-ipc --unshare-net --die-with-parent --unsetenv ... -- <argv>`. `bwrap` removes the session directory, the reason, the token, `PASS_PAT_FILE`, `PASS_CLI`, and `HOME` from the environment, and sets `HOME=/tmp` and `PATH=/usr/bin:/bin`. The program sees `/usr`, `/bin`, `/lib`, and `/lib64` read-only, plus `/etc/resolv.conf`, `/etc/hosts`, `/etc/nsswitch.conf`, and `/etc/ssl`. It also sees a private `/proc`, a fresh `/dev`, and an empty `/tmp` as its working directory. Host processes are not in that `/proc`. System V IPC objects live in a private IPC namespace, including with `approve-net`. It cannot see your home directory, the session directory, or the token file. Without `approve-net` it has its own network namespace and cannot reach the host's ports. `approve-net` drops only `--unshare-net`. If `bwrap` is missing, the server refuses the request before asking you. If `bwrap` fails to start the program, the exit code is nonzero and nothing runs outside the sandbox. Output is discarded. Since no output comes back, a short secret or an encoded secret has no path to the model, and the server keeps no redaction list.

`run_approved` requires a file-based kernel core-dump policy. It refuses external collectors (`core_pattern` beginning with `|` or `@`), including systemd-coredump: the kernel can bypass `RLIMIT_CORE` for a collector, and discarding the dump does not guarantee that sensitive process metadata stays out of logs. The server checks the policy before accessing the item and again immediately before starting `pass-cli run`. That child receives soft and hard `RLIMIT_CORE` limits of zero, inherited by the sandbox and its descendants. An unreadable policy or failure to apply the limits refuses execution. The host administrator must keep this policy in place while programs run; the plugin never changes host sysctls.

With `approve-net`, name lookup uses those `/etc` files and TLS uses `/etc/ssl`. The rest of `/etc` is not mounted. Without `approve-net` the network namespace is empty, so name lookup fails.

The session directory must be a real directory that you own. The server sets it to mode 0700, and it refuses to start if the directory or its `.session` file is a symlink. `share_id`, `item_id`, and vault names that start with `-` or contain a newline never reach `pass-cli`. Errors are fixed strings such as `pass-cli item failed`. They never include `pass-cli` stderr. The server logs in again only when `pass-cli` reports an unauthenticated client, an unauthorized token, or an expired session.

## What this does not stop

- Another process running as your user can bind the approval socket before the helper does, and it can read the token file from outside the sandbox. Such a process does not need this server to reach your vault.
- Agent cancellation over MCP is not implemented; closing the approval connection or reaching its deadline cancels the terminal request.
- The exit code is one byte that the model sees.
- With `approve-net`, an approved program can send its secrets to any network it can reach.
- `fill_login` without `submit` leaves the password in the page, where anything that can read the page can read it.

## Tests

Offline tests use a fake `pass-cli` that resolves `pass://` values and execs the `run` argv, and they speak MCP over stdio. The run tests need `bwrap`, `libseccomp.so.2`, `/usr/bin/python3`, and kernel keyring support, plus a file-based `core_pattern`. Run them in a disposable VM or CI runner configured with `kernel.core_pattern=core`; do not change a shared host's dump policy for tests. `test_core.py` also tests refusal on hosts with external collectors, and performs synthetic crash checks only under a file-based policy. `test_fill.py` drives a headless Chromium from Playwright (`python3 -m playwright install chromium`):

```bash
python3 tests/test_core.py
python3 tests/test_relogin.py
python3 tests/test_offline.py
python3 tests/test_tabs.py
python3 tests/test_fill.py
```

`tests/e2e_real.py` talks to a real vault and answers approvals itself. It prints no secret values. It needs the token file, `pass-cli`, and `bwrap`. CI runs the offline tests only.

## License

MIT
