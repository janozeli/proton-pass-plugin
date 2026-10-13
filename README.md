# Proton Pass plugin

Stdio MCP server for [Cursor](https://cursor.com/docs/plugins). It wraps the official [`pass-cli`](https://protonpass.github.io/pass-cli/) and ships with a skill that tells the agent which tool to call. The server is Python's standard library. `fill_login` is the only tool that needs Playwright.

The agent can list vaults, search items, and fill a browser login without receiving the password. `get_totp` returns a short-lived code. `get_secret` returns a stored value only when the agent calls it on purpose.

## Install

Install `pass-cli` from the [pass-cli docs](https://protonpass.github.io/pass-cli/). The default path is `~/.local/bin/pass-cli`.

Create a personal access token in Proton Pass and grant it viewer access only to the vaults the agent should read. Store the token in a file the agent process can read and other users cannot:

```bash
mkdir -p ~/.config/pass-agent
umask 077
printf '%s\n' 'YOUR_TOKEN' > ~/.config/pass-agent/pat
```

`umask 077` creates the file as mode 0600. The server refuses a token file that is readable by the group or by others.

To load the plugin locally, copy this repository to `~/.cursor/plugins/local/proton-pass` and run **Developer: Reload Window**. The folder must be a real directory. Cursor skips a symlink that points outside `~/.cursor/plugins/local`. After the reload, the Proton Pass skill and the `proton-pass` MCP server show up under **Customize**.

`fill_login` needs the Playwright Python package (`pip install playwright`) and a Chrome process started with `--remote-debugging-port`.

## Configure

`mcp.json` leaves configuration to the process environment. The server uses these defaults, and expands `~`:

| Variable | Default | Role |
| --- | --- | --- |
| `PASS_CLI` | `~/.local/bin/pass-cli` | `pass-cli` binary |
| `PASS_PAT_FILE` | `~/.config/pass-agent/pat` | Personal access token file (mode 0600) |
| `PROTON_PASS_SESSION_DIR` | `~/.local/share/pass-agent` | Session directory for this agent, separate from a normal `pass-cli` login |
| `PASS_CDP_PORT` | `9222` | Chrome remote-debugging port when `fill_login` is called without `cdp_port` |

Set a variable in `mcp.json` under `mcpServers.proton-pass.env` when the default path is wrong. Do not put the token itself in `mcp.json` or in the repository.

The session directory is created mode 0700. A symlink at that path is refused. This keeps the agent session off the shared `/tmp` directory.

## Tools

| Tool | What the model receives |
| --- | --- |
| `list_vaults` | Vault names and ids |
| `search_items` | Title, type, vault, `share_id`, `item_id`. Trashed items are omitted |
| `describe_item` | URLs, username, email, and booleans for password, TOTP, and note. Not the secret values |
| `get_totp` | The current TOTP code |
| `fill_login` | Which fields were filled, and the page URL. Not the password |
| `run_with_secrets` | Exit code and command output. Secret values are `pass://SHARE_ID/ITEM_ID/FIELD` references |
| `get_secret` | The field value. The tool is the explicit opt-in |

Pass a short `reason` on calls that read an item. Proton stores it in the audit log.

## Security

The token should be a viewer. This server has no create, update, or delete tool. A token that can write is more access than the tools use.

Two tools are allowed to return secret material: `get_totp` and `get_secret`. Every other tool result, and every error string, is passed through one redaction step. That step removes the personal access token, and any password or TOTP URI of 5 or more characters that this process has already loaded. Shorter field values are left as-is, because replacing them would also rewrite unrelated output.

`run_with_secrets` does not resolve secrets in this process. It puts the `pass://` reference in the environment and runs `pass-cli run`, which injects the value and masks it in the child output. `pass-cli` itself does not mask values shorter than 5 characters. Masking covers text that comes back to the model. It does not stop the command from sending a secret to the network. The command is arbitrary `bash -c`.

`fill_login` chooses a tab by host, and by port when `url_match` includes one. A query parameter that only mentions the real host does not receive the password. The password is typed into the page over the Chrome DevTools port on `127.0.0.1`.

A bad line on stdin is a JSON-RPC parse error. The process stays up. Requests without an id are ignored, so a notification cannot run a tool.

## Tests

Offline tests use a fake `pass-cli` and speak MCP over stdio:

```bash
python3 tests/test_relogin.py
python3 tests/test_offline.py
python3 tests/test_tabs.py
```

`tests/e2e_real.py` talks to a real vault and a private Chrome. It prints no secret values. It needs the token file, `pass-cli`, Playwright, and Chrome. CI runs the offline tests only.

## License

MIT
