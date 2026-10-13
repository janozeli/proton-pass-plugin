# Proton Pass plugin (Cursor / Grok Bot)

Stdio MCP server (Python stdlib + Playwright for `fill_login`) wrapping the official [`pass-cli`](https://protonpass.github.io/pass-cli/), plus a skill.

Tools: `list_vaults`, `search_items`, `describe_item`, `get_totp`, `fill_login` (CDP), `run_with_secrets` (`pass-cli run`, masked), `get_secret` (explicitly returns the value).

## Requirements
- `pass-cli` (default `~/.local/bin/pass-cli`, override `PASS_CLI`)
- An agent personal access token in a file (default `~/.config/pass-agent/pat`, override `PASS_PAT_FILE`)
- `python3`; `playwright` (Python) only for `fill_login`

The server logs in with the token on demand and again whenever pass-cli reports the session expired.

## Tests
    cd tests && python3 test_relogin.py   # offline, fake pass-cli
    cd tests && python3 e2e_real.py       # real vault, private headless Chrome, never prints secrets
