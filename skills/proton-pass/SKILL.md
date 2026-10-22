---
name: proton-pass
description: "Use this skill FIRST, before asking the user for a password and before offering 1Password or a secure form, whenever a task needs a login, password, username, 2FA code, two-factor code, or passkey from Proton Pass. Trigger on: login, senha, usuário, código 2FA, dois fatores, passkey, password, username, Proton Pass."
---

# Proton Pass

Use this MCP server instead of running `pass-cli` yourself. If you are unsure which vaults the agent can read or change, call `session_info` first. Never run `pass-cli info`. That command can log out the agent session.

A generated TOTP code is not a secret. It is single-use and expires in about 30 seconds, so you may show it and pass it on. The TOTP seed, passwords, notes, and the agent token are secrets. No tool returns those. If the user wants to see a password, tell them to open Proton Pass.

## Setup

Do not ask the user to paste a token. Ask them to run this in their terminal, naming the vault the bots should use:

```bash
python3 ~/.cursor/plugins/local/proton-pass/server/proton_pass_mcp.py setup --vault "Bots" --name cursor-agent
```

`pass-cli login` with no flags is web login: it prints a URL, the user approves it in a browser, and the CLI continues. Setup shows that URL, creates a vault-scoped agent token (`pass-cli agent create` plus `agent access grant`), writes only that token into the PAT file, then runs `pass-cli logout` and deletes the temporary full-account session. It never prints the token. The default role is `editor` so `create_login` and `save_totp` work. `--role viewer` keeps the token read-only. Public `pass-cli` has no `--interactive` login; that flag exists only in internal builds and this setup does not use it.

`session_info` reports the token expiration recorded at setup. When fewer than 14 days remain it warns. Renewing repeats the browser approval and replaces the token:

```bash
python3 ~/.cursor/plugins/local/proton-pass/server/proton_pass_mcp.py setup --renew
```

Give each bot its own `PROTON_PASS_SESSION_DIR`. The server creates that directory mode 0700, owned by the user, and refuses a symlink or a directory owned by someone else. Do not point two bots at one session directory.

## Read-only vaults

`session_info` sets `access` to `read` when the Proton role is Viewer, and `write` for Editor, Manager, or Owner. Listing, searching, describing, `fill_login`, and `get_totp` work with read access. `create_login` and `save_totp` stop with an error that says reading and filling still work and that creating or editing needs write access. Tell the user that, and do not try `pass-cli` directly to get around it.

## Pick the tool

1. Call `session_info` when scope or token expiration is unclear.
2. Find the item with `search_items` (title substring, optional `type: login`). It returns `share_id` and `item_id`.
3. Check it with `describe_item`. It shows each saved website's origin (scheme, host, and port), the username, `has_password`, and `has_totp`. It does not show the path or the query.
4. Use one release tool. Each release waits until the user types `approve` in the approval helper's terminal:
   - To log into a site, open the item's saved origin in exactly one tab, then call `fill_login` with `share_id`, `item_id`, and `reason`. If `PASS_CDP_PORT` is set, that loopback port is used. Otherwise the server finds a Chrome listening on `127.0.0.1`. When several are running, it picks the one with a page on the item's origin. If more than one still matches, it lists the ports and does not guess. Omit `submit` or set it to `false`. Automatic password submission is refused before filling. The tab's origin must equal one of the item's saved websites. A subdomain or a different port does not match. `"submitted": false` means the password form was not submitted.
   - `auto_2fa` defaults to true. After the username and password are typed, if the page shows a one-time-code field and the item has TOTP, the current code is typed. If fewer than 3 seconds remain in the time step, the server waits for the next code. A code field in its own form is submitted (`totp_submitted: true`). A code field in the password form is filled and not submitted, because that would send the password. Set `auto_2fa` to false to skip this. The code in the result is not a secret.
   - For a code you will type yourself, call `get_totp`. You may show the digits.
   - To save a new login, call `create_login` with `title`, `reason`, and either `share_id` or `vault`, plus `password` or `generate_password: true`. Optional: `username`, `email`, `urls`, and `otpauth_uri` or `seed`. You get `item_id` only. The password and seed are not returned.
   - To add TOTP to an existing plain login, call `save_totp` with `otpauth_uri` or `seed`. `pass-cli item update` cannot change a login's TOTP. A login with no note, extra fields, or passkeys is recreated and the old item is deleted. Anything else is refused so those fields are not dropped. You get the new `item_id`. The seed is not returned.
   - For a program that needs a key, call `run_approved` with `argv` (absolute path first, for example `["/usr/bin/psql", "--host=127.0.0.1", "--command=select 1"]`) and `env: {"PGPASSWORD": "pass://SHARE_ID/ITEM_ID/password"}`. A reference is exactly `pass://SHARE_ID/ITEM_ID/FIELD`, with no `?`, `#`, or `%`. The program runs in a sandbox that sees `/usr`, `/bin`, and `/lib`, plus `/etc/resolv.conf`, `/etc/hosts`, `/etc/nsswitch.conf`, and `/etc/ssl`, with a private `/proc` and an empty `/tmp` as its working directory. Do not put a secret in `LD_AUDIT`, `LD_PRELOAD`, or another loader variable. Those names never reach the sandbox launcher. It cannot read files from the workspace or the home directory. It has no network unless the user types `approve-net`, so tell the user when it needs the network. Hostnames resolve only after `approve-net`. You get only the exit code. If you need the program's output or the workspace, this tool does not fit. Ask the user to run the program themselves.

Passkeys are created by the site and the Proton Pass browser authenticator, not by `pass-cli`. The CLI can show items that already contain passkeys, and `item create login` stores an empty passkey list. There is no command that registers a passkey. A Chrome virtual authenticator would keep the credential in the browser instead of in Proton Pass, so do not invent that path. Ask the user to create the passkey in Proton Pass.

Always pass a short `reason`. The user reads it in the approval prompt, and Proton logs it.

## Errors

- If a release fails with `approval unavailable`, ask the user to start the approval helper as the plugin README describes. Never start the helper yourself and never type into its terminal. Only the user may answer a release.
- If a release fails with `release denied`, the user said no or did not answer in time. Do not retry unless the user asks.
- If `fill_login` fails with `no open tab matches this item's websites (N tabs open)`, open one of the URLs that `describe_item` lists, then try again.
- If `fill_login` fails with `more than one open tab matches this item's websites (N tabs open)`, close the extra tabs on that site, then try again.
- If `fill_login` fails because more than one Chrome is listening, open the site in one of them or ask the user to set `PASS_CDP_PORT`.
- If `create_login` or `save_totp` says reading and filling still work, the token is read-only on that vault. Tell the user write access is required. Do not retry with another tool.
- If `save_totp` says the login cannot be recreated, it has a note, extra fields, or passkeys. Ask the user to add the TOTP in Proton Pass, or create a new login with `create_login`.
- If `run_approved` fails with `bwrap is not installed`, tell the user that `run_approved` needs bubblewrap.
- If `fill_login` fails with `automatic submission is unavailable; fill without submit and submit manually`, omit `submit` and ask the user to submit the form. Do not look for another tool that posts the password.
