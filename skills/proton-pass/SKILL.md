---
name: proton-pass
description: Use when a task needs a password, login, 2FA code, API key or other secret stored in the user's Proton Pass, or when the user mentions Proton Pass. Covers finding items and using secrets without exposing them in chat.
---

# Proton Pass

The `proton-pass` MCP server wraps the official `pass-cli` with a read-only agent token. The token file must be mode 0600. Sessions re-login when pass-cli says the client is not authenticated.

## Pick the tool

1. Find the item: `search_items` (title substring, optional `type: login`). It returns `share_id` + `item_id`.
2. Check it: `describe_item` shows URLs, username, `has_password`, `has_totp`. No secrets.
3. Use it, preferring tools that keep the secret out of the conversation:
   - Logging into a site in the browser: open the login page, then `fill_login` with the browser's CDP port (`cdp_port`). `url_match` is the tab's host or `host:port` (a full URL is matched by host). A different site that only mentions that host in the query string does not match. Use `submit: true` to press Enter. If Chrome was started with `--remote-debugging-port`, pass that port. The default is `PASS_CDP_PORT` or 9222.
   - 2FA prompt: `get_totp`, then type the code.
   - CLI or script needing a key: `run_with_secrets` with `env: {"API_KEY": "pass://SHARE_ID/ITEM_ID/password"}`. Output is masked.
   - `get_secret` returns the raw value. Use it only when the user explicitly asks to see a value, and never repeat it in chat.

Always pass a short `reason`; Proton logs it.

The token is read-only: creating, editing or deleting items is not possible.
