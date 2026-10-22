# Proton Pass plugin

Stdio MCP server for [Cursor](https://cursor.com/docs/plugins). It wraps the official [`pass-cli`](https://protonpass.github.io/pass-cli/) and ships with a skill that tells the agent which tool to call. The server uses Python and `idna` (`pip install -r requirements.txt`). `fill_login` also needs Playwright.

The agent can list vaults, search items, and read item metadata. It never receives a password, a note, or a TOTP seed back from a tool. A generated TOTP code is single-use and lasts about 30 seconds, so `get_totp` and `fill_login` may return that code. `fill_login` types a login into a browser tab and can type the current code into a 2FA field. `create_login` stores a login after you approve and returns only the new item id. `save_totp` stores a TOTP the same way. `pass-cli` cannot edit a login TOTP in place, so `save_totp` creates a new item, deletes the old one, and returns both `item_id` and `replaced_item_id`. `run_approved` runs one program with secrets in its environment. Each release waits until you type `approve` in a terminal that the agent cannot write to.

The approval helper and `run_approved` need Linux. The helper checks the caller's uid with `SO_PEERCRED`, and `run_approved` runs the program inside [bubblewrap](https://github.com/containers/bubblewrap) (`bwrap`).

## Install

Install `pass-cli` from the [pass-cli docs](https://protonpass.github.io/pass-cli/). The default path is `~/.local/bin/pass-cli`. For `run_approved`, install bubblewrap and libseccomp (`sudo apt install bubblewrap libseccomp2` on Debian and Ubuntu). On Ubuntu 24.04 and later, `bwrap` also needs unprivileged user namespaces, which AppArmor blocks by default (`kernel.apparmor_restrict_unprivileged_userns`).

`fill_login` needs the Playwright Python package (`pip install playwright`) and a Chrome process started with `--remote-debugging-port`. The port does not have to be 9222.

To load the plugin locally, copy this repository to `~/.cursor/plugins/local/proton-pass` and run **Developer: Reload Window**. The folder must be a real directory. Cursor skips a symlink that points outside `~/.cursor/plugins/local`. After the reload, the Proton Pass skill and the `proton-pass` MCP server show up under **Customize**.

### Create the agent token

Do not paste a token. Setup starts `pass-cli login` in a temporary directory (mode 0700), prints the approval URL, creates a vault-scoped agent token, writes only that token to the PAT file, then logs out and deletes the full-account session. The token value is never printed.

Public `pass-cli login` with no flags is web login, from the [login command](https://github.com/protonpass/pass-cli/blob/main/docs/public/docs/commands/login.md): it prints a URL, you approve it in a browser, and the CLI continues. That flow supports SSO, two-factor authentication, and hardware security keys. If the account has a Proton Pass extra password, type it at the prompt on this terminal after the browser step. Setup drops `PROTON_PASS_EXTRA_PASSWORD` and `PROTON_PASS_EXTRA_PASSWORD_FILE` from the login environment so a leftover value is not used. The public `login` command has no `--interactive` flag. That flag is compiled only into internal builds (`#[cfg(feature = "internal")]`), and this setup does not pass it. `login --pat` (alias `--personal-access-token`) accepts `pst_<token>::<key>` and is how the server later logs in with the agent token. Setup does not use it for the account login.

`pass-cli agent create <name> --expiration <1h|1d|1w|1m|3m|6m|1y>` prints JSON whose `token` field is `PROTON_PASS_PERSONAL_ACCESS_TOKEN=pst_...::key`. That is the only time pass-cli shows the value. `agent create --vault` grants the Viewer role only, so setup creates the agent with no `--vault` and then runs `agent access grant <name> --vault-name <name> --role <role>`. The default role is `editor`, which `create_login` and `save_totp` need. `--role viewer` keeps the token read-only. `--role manager` is the other grant the CLI accepts. Manager can also manage who has access to the vault.

After those grants, setup logs in with the new agent token in a second temporary directory (mode 0700), runs `share list --only-vaults=true --output json`, and checks that each vault's `share_role` matches the requested role, ignoring case. The same check runs for `setup --grant`. If a role does not match, setup exits with an error and does not update `pat.meta`. The token from `agent create` is still saved, because pass-cli shows it only once. Both the full-account directory and the verification directory are logged out with `--force` and deleted, including when setup fails.

```bash
python3 ~/.cursor/plugins/local/proton-pass/server/proton_pass_mcp.py setup --vault "Bots" --name cursor-agent
```

Repeat `--vault` for more than one vault. `--expiration` defaults to `1y`. The PAT file is `~/.config/pass-agent/pat` (mode 0600). A sidecar `pat.meta` (mode 0600) stores the agent name, vaults, per-vault `roles`, and expiration timestamp. It does not store the token. `role` is also set when every vault has the same role. The server refuses a token file that the group or other users can access, a symlink, or a file another user owns. Metadata with any of those problems is ignored, so `session_info` reports no expiration.

The temporary directory is deleted after `pass-cli logout` and `logout --force`. The plugin's own `PROTON_PASS_SESSION_DIR` is a different directory and holds only the agent login.

When fewer than 14 days remain, `session_info` warns. Renewing repeats the browser approval. `agent renew` replaces the token immediately and keeps the existing grants:

```bash
python3 ~/.cursor/plugins/local/proton-pass/server/proton_pass_mcp.py setup --renew
```

`--renew` reads the agent name from `pat.meta` and cannot be combined with `--vault`. Pass `--expiration` to choose a new lifetime. The default is again `1y`.

Changing a vault role repeats the browser approval and runs `agent access grant` for the agent name stored in `pat.meta`. It does not create a token. A second grant on a vault that already has access changes the role in place (`viewer` to `manager` and back). `agent access revoke --share-id` returned `NotExists` for both the owner share id and the agent share id, so setup does not revoke.

```bash
python3 ~/.cursor/plugins/local/proton-pass/server/proton_pass_mcp.py setup --grant --vault "Bots" --role editor
```

`--grant` needs exactly one `--vault` and `--role viewer`, `editor`, or `manager`. It cannot be combined with `--name`, `--expiration`, or `--renew`. On success, `pat.meta` records that vault's new role.

The owner's primary vault named `Personal` rejects `--role editor` with `NotAllowed`. `viewer` and `manager` succeed there. The error says to grant `editor` on a dedicated vault, or to grant `manager`. Manager can also manage who has access to the vault.

A running server keeps the previous `share_role` in its session until it logs in again. `session_info` and the write check do that login themselves. A restart is not required. The server still never runs `pass-cli info`.

A token file you created by hand still logs in. `session_info` then leaves `expires_at` null and does not warn, because no expiration was recorded. Use `setup` so the warning and the renew command exist.

## Start the approval helper

Run the helper in a terminal that you keep open:

```bash
python3 ~/.cursor/plugins/local/proton-pass/server/proton_pass_mcp.py approve
```

The helper listens on `approve.sock` in the session directory. It reads your answer from its own terminal (`/dev/tty`), not from a pipe. For each request it prints the item title, the exact origin, the write change, or the exact argv, and the agent's reason. A write request shows `create login` or `attach TOTP by replacing the login`. It does not show the password or the TOTP seed.

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

If the helper is not running, `fill_login`, `get_totp`, `create_login`, `save_totp`, and `run_approved` fail with `approval unavailable`. `list_vaults`, `search_items`, `describe_item`, and `session_info` keep working.

## Configure

`mcp.json` leaves configuration to the process environment. The server and the helper read these variables and expand `~`:

| Variable | Default | Role |
| --- | --- | --- |
| `PASS_CLI` | `~/.local/bin/pass-cli` | `pass-cli` binary |
| `PASS_PAT_FILE` | `~/.config/pass-agent/pat` | Personal access token file (mode 0600 or 0400) |
| `PROTON_PASS_SESSION_DIR` | `~/.local/share/pass-agent` | Session directory for this agent, separate from a normal `pass-cli` login. It also holds `approve.sock` |
| `PASS_CDP_PORT` | unset | Optional Chrome remote-debugging port on `127.0.0.1`. A `fill_login` `cdp_port` argument wins over this. When both are unset, `fill_login` discovers a loopback Chrome |

Set a variable in `mcp.json` under `mcpServers.proton-pass.env` when a default is wrong. Give the helper the same `PROTON_PASS_SESSION_DIR`, or the server will not find it. Do not put the token itself in `mcp.json` or in the repository.

## Tools

| Tool | Needs approval | What the model receives |
| --- | --- | --- |
| `list_vaults` | No | Vault names and ids |
| `search_items` | No | Title, type, vault, `share_id`, `item_id`. Trashed items are omitted |
| `describe_item` | No | Origins (scheme, host, and port), username, email, and booleans for password, TOTP, and note. No path, query, or fragment |
| `session_info` | No | Agent-token identity, name, each vault's role and `read` or `write` access, `expires_at`, `days_remaining`, and a warning when fewer than 14 days remain. Includes `renew_command`. Logs out and back in before reading roles. Does not call `pass-cli info` |
| `get_totp` | Yes | `{"code": "123456"}`. The code is not a secret. The seed is not returned |
| `fill_login` | Yes | `{"filled": ["username", "password"], "submitted": false}`. When a 2FA field was filled, `filled` also contains `"totp"`, plus `"totp"` (the code) and `"totp_submitted"`. If 2FA field detection fails, `"totp"` is `"detect_failed"` and the password fill is still returned. No URL, password, or seed |
| `create_login` | Yes | `{"item_id": "..."}`. The password and any seed are stored and not returned |
| `save_totp` | Yes | `{"item_id": "...", "replaced_item_id": "..."}`. The item id changes. A delete failure is an error whose text is JSON and still includes `replaced_item_id`. The seed and password are not returned |
| `run_approved` | Yes | `{"exit_code": 0}`. No output |

Pass a short `reason`. The helper shows at most 300 characters of it, and at most 1024 characters of each argv element. Proton stores the reason in the audit log. A reason that still contains `pass://` after Unicode normalization is rejected.

## Security model

The model is not a trusted caller. It may name an item and give a reason. It may not choose where a secret goes, and it may not read one back. The tool schema is where that rule lives. No tool takes a command string, a URL to match, a CSS selector, or a working directory. `fill_login` accepts an optional `cdp_port` integer. It is only a port: the server still connects to `127.0.0.1` and rejects a websocket whose host is anything else. At startup the server checks every tool and parameter name against a forbidden set (`get_secret`, `run_with_secrets`, `command`, `url_match`, `url`, `username_selector`, `password_selector`, `cwd`, `value`, `totp_uri`) and exits if one appears. `create_login` is the one tool with a `password` argument, so a password the caller already has can be stored. The result is only `item_id`. TOTP input is named `otpauth_uri` or `seed`, never `totp_uri`, and neither value is returned.

`fill_login` takes its targets only from the websites saved on the item. An origin uses the browser's spelling of scheme, host, and port. The host is lowercase punycode using non-transitional UTS #46 processing. Unsupported or ambiguous URLs (including backslashes, controls, invalid IDNA and legacy IPv4 spellings) are rejected. IPv6 is in brackets. The port is omitted when it is 443 for `https` or 80 for `http`. A saved URL without a scheme counts as `https`. `http` matches only a saved `http` URL. Matching is equality, so `login.bank.com` does not match a saved `bank.com`. An optional `cdp_port` argument is validated with `parse_port` and is the only port that is probed. It wins over `PASS_CDP_PORT` and over auto-discovery. When `cdp_port` is omitted, `PASS_CDP_PORT` is that port. When both are unset, the server looks for Chrome, Chromium, Edge, or Brave on `127.0.0.1`: process command lines that contain `--remote-debugging-port`, and `DevToolsActivePort` files under the usual Chrome, Chromium, Edge, and Brave config directories plus `/tmp` and `/dev/shm`. A candidate is used only after `http://127.0.0.1:<port>/json/version` returns a browser websocket whose host is `127.0.0.1`. One verified browser is used. When several are listening, the one with a page whose origin matches the item is used. If none or more than one still matches, nothing is typed, and the error lists the candidate ports. It never guesses and never includes tab URLs. A websocket whose host is not `127.0.0.1` is rejected. Exactly one tab's main frame must match. If none or several match, nothing is typed. The server asks you, then types from an isolated world the page cannot hook. That world checks `location.origin` again before it writes the password, so a tab that navigated while you read the prompt receives nothing. The password goes only into the first visible `input[type=password]` in the main frame, never into a hidden field, an iframe, or a text box. Eligible inputs must have positive width and height, must not be effectively disabled (including by a fieldset), and must accept browser focus. Immediately before each credential write, the isolated world calls `focus({preventScroll: true})` and requires the deep active element to be that input, walking open and CDP-accessible closed shadow roots. The focus verdict and write run synchronously in the same browser task; modal order and inert ancestors are not modeled separately. Inputs in those shadow roots are supported; if a root is unavailable, its inputs are skipped. After username events, the server selects and validates the password field again. After all synchronous input, change, and focus handlers, it reports a successful password fill only if the field remains connected, eligible, in the same form, and contains the requested value. It reports the username only if that field also remains connected, eligible, of a supported username type, in the password field's form, and contains the requested value. Automatic submission (`submit: true`) is refused before approval or filling. A form's action does not determine its final destination: submit buttons can override it and page event handlers can change it or issue requests during filling. Omit `submit` or set it to `false`, then inspect and submit the password form manually. `"submitted": false` means the server did not submit the password form. `auto_2fa` defaults to true. After the username and password are in place, if the page shows a one-time-code field and the item has a TOTP URI, the server generates the current code and types it. If fewer than 3 seconds remain in the step, it waits for the next code. A code field in its own form may be submitted (`totp_submitted` is true). A code field in the password form is filled and left unsubmitted, because submitting that form would send the password. Set `auto_2fa` to false to skip this. Detection walks open shadow roots only, so a one-time-code field inside a closed shadow root is skipped; use `get_totp` for that page. The returned code is not a secret. The seed never appears in the result or in an error. If detection of the 2FA field fails, the password fill is still returned and `totp` is `detect_failed`. A page with no 2FA field omits `totp`. Errors report the number of open tabs, never their URLs.

`run_approved` runs the argv you approved and nothing else. Every argument is limited to 1,024 characters and displayed in full; longer arguments are rejected before approval or secret access. `argv[0]` must be an absolute path, and the server never adds `bash` or `-c`. A reference is exactly `pass://SHARE_ID/ITEM_ID/FIELD`. The server rejects `?`, `#`, `%`, an extra slash, and a leading `-`. `pass-cli` treats `?totp=uri` as a request for the TOTP seed and percent-decodes each segment, so those spellings never reach it. A `reason` that contains `pass://` after Unicode normalization is rejected. `pass-cli run` resolves a `pass://` value in any environment variable, including the audit reason. A reply from the helper can only allow or deny. It cannot change the argv. `pass-cli run` starts with stdin, stdout, and stderr on `/dev/null`. Its environment is an allowlist: `PATH`, `PROTON_PASS_SESSION_DIR`, a fixed `PROTON_PASS_AGENT_REASON`, and the bindings under names `PP0`, `PP1`, and so on. The names you approved are not in that environment, so a linker variable such as `LD_AUDIT` cannot run code before `bwrap` starts. Inside the sandbox a trusted Python trampoline first installs a libseccomp filter that denies `add_key`, `request_key`, and `keyctl` with `EPERM`, including with `approve-net`. The filter rejects non-native syscall ABIs and remains active across exec and child processes. If the library is unavailable or filter setup fails, the approved program is never executed. The trampoline then renames `PP0` to the approved name and drops every other variable. The command is `pass-cli run -- bwrap --unshare-user --unshare-pid --unshare-ipc --unshare-net --die-with-parent --unsetenv ... -- <argv>`. `bwrap` removes the session directory, the reason, the token, `PASS_PAT_FILE`, `PASS_CLI`, and `HOME` from the environment, and sets `HOME=/tmp` and `PATH=/usr/bin:/bin`. The program sees `/usr`, `/bin`, `/lib`, and `/lib64` read-only, plus `/etc/resolv.conf`, `/etc/hosts`, `/etc/nsswitch.conf`, and `/etc/ssl`. It also sees a private `/proc`, a fresh `/dev`, and an empty `/tmp` as its working directory. Host processes are not in that `/proc`. System V IPC objects live in a private IPC namespace, including with `approve-net`. It cannot see your home directory, the session directory, or the token file. Without `approve-net` it has its own network namespace and cannot reach the host's ports. `approve-net` drops only `--unshare-net`. If `bwrap` is missing, the server refuses the request before asking you. If `bwrap` fails to start the program, the exit code is nonzero and nothing runs outside the sandbox. Output is discarded. Since no output comes back, a short secret or an encoded secret has no path to the model, and the server keeps no redaction list.

`run_approved` requires a file-based kernel core-dump policy. It refuses external collectors (`core_pattern` beginning with `|` or `@`), including systemd-coredump: the kernel can bypass `RLIMIT_CORE` for a collector, and discarding the dump does not guarantee that sensitive process metadata stays out of logs. The server checks the policy before accessing the item and again immediately before starting `pass-cli run`. That child receives soft and hard `RLIMIT_CORE` limits of zero, inherited by the sandbox and its descendants. An unreadable policy or failure to apply the limits refuses execution. The host administrator must keep this policy in place while programs run; the plugin never changes host sysctls.

With `approve-net`, name lookup uses those `/etc` files and TLS uses `/etc/ssl`. The rest of `/etc` is not mounted. Without `approve-net` the network namespace is empty, so name lookup fails.

The session directory must be a real directory that you own. The server creates it mode 0700. A directory this user owns with a looser mode is changed to 0700. The server refuses to start if the directory is owned by someone else, or if the directory or its `.session` file is a symlink. Give each bot its own `PROTON_PASS_SESSION_DIR`. `pass-cli` itself refuses a `.session` file that the group can read and does not change that mode. `share_id`, `item_id`, and vault names that start with `-` or contain a newline never reach `pass-cli`. Errors are fixed strings such as `pass-cli item failed`. They never include `pass-cli` stderr, a password, or a TOTP seed. The server never runs `pass-cli info`. A logged-out response from that command can delete the agent session. `session_info` uses `vault list` and `share list --only-vaults=true`, plus the local `pat.meta` expiration. Before reading vault roles, `session_info` and the write check log out and back in with the agent token. `pass-cli` keeps `share_role` in the session, and a grant does not update that cache; only a new login sees the new role. Logout removes `PROTON_PASS_SESSION_DIR/.session` and leaves `approve.sock` in place. The server also logs in again when `pass-cli` reports an unauthenticated client, an unauthorized token, or an expired session. An agent login lasts about two hours. The `1h`..`1y` value is the token lifetime, which is what `session_info` reports.

`create_login` and `save_totp` check the vault role before approval. Viewer, an unknown role, and a custom role are read-only. The error says reading and filling still work and that creating or editing needs Editor, Manager, or Owner. `pass-cli item update` cannot change a login's `totp_uri` (it creates a custom field and leaves the login TOTP unchanged, and editing an existing TOTP field is unsupported). `save_totp` therefore creates a new login from the title, username, email, password, and URLs, then deletes the old item. The approval prompt states that the item id will change and names the item that will be deleted. Success returns `item_id` and `replaced_item_id`. If deleting the old item fails, the new item is deleted so the vault does not keep both. That error is JSON and includes `replaced_item_id` and `removed_item_id`. If the new item cannot be removed either, the error names both surviving ids so the duplicate is not silent. It refuses when the item has a note, extra fields, or passkeys, so those are not dropped. Passkeys are not copied: `LoginItem.passkeys` exists, but `item create login` stores an empty list, and pass-cli has no register command. A passkey is created by the site and the Proton Pass browser authenticator. A Chrome virtual authenticator would keep the credential in the browser, so this plugin does not create one.

## What this does not stop

- Another process running as your user can bind the approval socket before the helper does, and it can read the token file from outside the sandbox. Such a process does not need this server to reach your vault.
- Agent cancellation over MCP is not implemented; closing the approval connection or reaching its deadline cancels the terminal request.
- The exit code is one byte that the model sees.
- With `approve-net`, an approved program can send its secrets to any network it can reach.
- `fill_login` without `submit` leaves the password in the page, where anything that can read the page can read it.

## Tests

Offline tests use a fake `pass-cli` that resolves `pass://` values and execs the `run` argv, and they speak MCP over stdio. The run tests need `bwrap`, `libseccomp.so.2`, `/usr/bin/python3`, and kernel keyring support, plus a file-based `core_pattern`. Run them in a disposable VM or CI runner configured with `kernel.core_pattern=core`; do not change a shared host's dump policy for tests. `test_core.py` also tests refusal on hosts with external collectors, and performs synthetic crash checks only under a file-based policy. `test_fill.py` drives a headless Chromium from Playwright (`python3 -m playwright install chromium`). CI runs every `tests/test_*.py`:

```bash
for test in tests/test_*.py; do python3 "$test"; done
```

`test_totp.py` checks RFC 6238 vectors, including the wait when fewer than 3 seconds remain. `test_discover.py` checks command-line and `DevToolsActivePort` parsing, an explicit `PASS_CDP_PORT`, a `cdp_port` argument that wins over both, origin matching, and rejection of a websocket host other than `127.0.0.1`. `test_setup.py` uses a fake `pass-cli`: the approval URL is printed, a parent `PROTON_PASS_PERSONAL_ACCESS_TOKEN` is not forwarded, the PAT file receives only the agent token (mode 0600), `agent create` is not given `--vault`, the grant uses the requested role, create and `setup --grant` check `share_role` with a fresh agent login (a capitalized role still matches), a mismatched role fails without updating `pat.meta`, `NotAllowed` for `editor` names the Personal-vault limit, renew replaces the token, no token value is printed, `pass-cli info` is not called, and both session directories are removed on success and on failure. `test_write.py` checks that a stale cached `share_role` is refreshed by logout and login before `session_info` or a write, without calling `pass-cli info` and without deleting the session directory. `test_write.py` checks that `session_info` warns below 14 days, ignores metadata that is not private, still works after the report (the fake `info` command would have logged the session out), refuses a Viewer token before any write, waits for approval before `create_login` or `save_totp`, and that a failed delete either removes the new item or returns both ids. `test_fill.py` includes a headless Chrome on a port other than 9222 with `PASS_CDP_PORT` unset, a `cdp_port` argument that wins over `PASS_CDP_PORT`, a separate 2FA form that is submitted, a 2FA field inside the password form that is filled and not submitted, and a 2FA detection failure reported as `totp: detect_failed`.

These tests do not talk to Proton. A real account is still required to confirm that the printed web-login URL completes, that the extra-password prompt accepts the Proton Pass extra password when the account has one, that `agent create`, `agent access grant`, `agent renew`, and `agent list` succeed against the vault, that the written token logs in, and that `fill_login` types into a real item. `tests/e2e_real.py` covers a logged-in vault for `list_vaults`, `search_items`, `describe_item`, `run_approved`, and `get_totp`. It answers approvals itself and prints no secret values. It needs the token file, `pass-cli`, and `bwrap`. It does not run the browser login or `fill_login`. CI runs the offline tests only.

## License

MIT
