---
name: proton-pass
description: Use when a task needs a password, login, 2FA code, API key or other secret stored in the user's Proton Pass, or when the user mentions Proton Pass. Covers finding items and using secrets without exposing them in chat.
---

# Proton Pass

The `proton-pass` MCP server wraps the official `pass-cli` with a read-only agent token. You never receive a password, a note, or a TOTP seed. No tool returns one, so do not look for a way to read a secret value. If the user wants to see a password, tell them to open Proton Pass.

## Pick the tool

1. Find the item with `search_items` (title substring, optional `type: login`). It returns `share_id` and `item_id`.
2. Check it with `describe_item`. It shows the saved website URLs, the username, `has_password`, and `has_totp`.
3. Use the secret with one release tool. Each release waits until the user types `approve` in the approval helper's terminal:
   - To log into a site, open the item's saved URL in exactly one tab of the Chrome that was started with `--remote-debugging-port`, then call `fill_login` with `share_id`, `item_id`, and `reason`. Add `submit: true` to press Enter. The tab's origin (scheme, host, and port) must equal one of the item's saved websites. A subdomain or a different port does not match. `"submitted": true` means Enter was pressed. Check the page to see whether the login worked.
   - For a 2FA prompt, call `get_totp`, then type the code.
   - For a program that needs a key, call `run_approved` with `argv` (absolute path first, for example `["/usr/bin/psql", "--host=127.0.0.1", "--command=select 1"]`) and `env: {"PGPASSWORD": "pass://SHARE_ID/ITEM_ID/password"}`. A reference is exactly `pass://SHARE_ID/ITEM_ID/FIELD`, with no `?`, `#`, or `%`. The program runs in a sandbox that sees `/usr`, `/bin`, and `/lib`, plus `/etc/resolv.conf`, `/etc/hosts`, `/etc/nsswitch.conf`, and `/etc/ssl`, with an empty `/tmp` as its working directory. It cannot read files from the workspace or the home directory. It has no network unless the user types `approve-net`, so tell the user when it needs the network. Hostnames resolve only after `approve-net`. You get only the exit code. If you need the program's output or the workspace, this tool does not fit. Ask the user to run the program themselves.

Always pass a short `reason`. The user reads it in the approval prompt, and Proton logs it.

## Errors

- If a release fails with `approval unavailable`, ask the user to start the approval helper as the plugin README describes. Never start the helper yourself and never type into its terminal. Only the user may answer a release.
- If a release fails with `release denied`, the user said no or did not answer in time. Do not retry unless the user asks.
- If `fill_login` fails with `no open tab matches this item's websites (N tabs open)`, open one of the URLs that `describe_item` lists, then try again.
- If `fill_login` fails with `more than one open tab matches this item's websites (N tabs open)`, close the extra tabs on that site, then try again.
- If `run_approved` fails with `bwrap is not installed`, tell the user that `run_approved` needs bubblewrap.

The token is read-only. Creating, editing, or deleting items is not possible.
