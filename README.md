# Proton Pass for Grok Bot

Connect Proton Pass to the Bot's **shared cloud computer**, authenticate in the
Proton browser flow, and fill saved website logins without copying tokens or
returning passwords or OTPs to the model. Uses the official
[Proton Pass CLI](https://protonpass.github.io/pass-cli/) through an MCP stdio server.

## Natural Bot workflows

- **“Sign into this website with my work account.”** `find_login` matches the
  exact saved origin, optionally the exact username/email. It works even when
  the saved title is unrelated to the website. A unique match returns ready
  `fill_arguments`; multiple matches return `choose_account`. The Bot asks which
  account to use rather than choosing the first. `fill_login`/`fill_totp` keep
  the requested `website` restriction even when that item has other saved sites.
- **“Save a login for this signup.”** `create_login` generates its password using
  the official CLI by default. Optional `password_length` (16–128, default 20)
  and `password_symbols` (default true) adapt to site rules. It returns both
  IDs needed for filling. Creating an item is not website account registration.
- **“Use a disposable email for this signup.”** `create_alias` asks for approval
  and returns the new forwarding address plus item IDs. This needs write access
  and Proton alias eligibility; it does not read incoming messages.
- **“Use the API key stored in Proton for this program.”** `search_items` finds
  the item; `describe_item` returns `pass://` references, including section names
  for custom fields. The Bot passes references to `run_approved`, without seeing
  their values. That runner currently returns only an exit code and cannot
  access workspace files; see the limitations below.

`capabilities` describes these workflows and approval support without accessing
Proton. `session_info` reports `connected`, `disconnected`, `incomplete`, or
`unavailable` with recovery guidance. Cloud responses guide the Bot to `connect`;
legacy shell setup commands are returned only in terminal mode.

Names are not identifiers: searches use share IDs internally and reject an
ambiguous vault name. A write can omit its vault only when exactly one vault is
accessible. `search_items` and `find_login` support `limit` (0–100) and `offset`,
returning `next_offset`. Website discovery reads each accessible login under the
supplied audit reason, since CLI list results omit URLs. For large collections,
scope the search to a vault/share ID. It does not use a cached password index.

References use IDs and exact field names. Case-insensitive duplicate names and
names outside the runner's reference syntax are reported in
`unavailable_reference_fields`; the Bot must not guess a replacement. A write
timeout does not prove that nothing was saved: inspect existing items before
retrying. See the [CLI capability review](docs/pass-cli-integration.md) for the
full feature map and remaining integration work.

## Connect

1. Install this repository as a Cursor/Grok Bot plugin. Its `mcp.json` launches
   `server/bootstrap.py` on the computer where the stdio server runs.
2. Ask the Bot to connect Proton Pass, naming the vaults and access role you want.
   The `connect` tool asks for human confirmation through MCP elicitation.
3. Open the **Proton authorization link** presented by the Bot and sign in.
   Proton's CLI receives the authorization automatically. Do not paste a token,
   OTP or password into the conversation.
4. If your account requires an additional **Pass password**, the Bot provides a
   temporary loopback URL. Take over the **cloud computer's browser** and open it
   there. Enter the password in that page. Opening this URL on your own computer
   will not reach the cloud process.
5. The Bot polls `connection_status` until it reports `connected`. Setup keeps
   only a scoped agent token and removes both temporary account/verification
   sessions. All your Bots using this installation share the connection.

The extra-password form sends its value directly to the login process's
non-echoing PTY. It does not send it through MCP, a tool argument, or a chat.
The form binds only to `127.0.0.1`, uses an unguessable path, refuses foreign
Host/Origin headers, and has no external assets, request logging, or caching.
It closes when setup finishes or is cancelled. This is a shared-computer trust
model: it does **not** isolate credentials or that browser from another program
running as the same OS user. The Bot must leave the form to the human and must
not inspect or screenshot it.

### Permissions and recovery

- `viewer`: read and fill existing logins.
- `editor` (default): also create/edit items. Use a dedicated vault such as `Bots`.
- `manager`: also manage vault access. Proton's owner's primary `Personal` vault
  rejects `editor`; explicitly choose `viewer` or `manager` there.

The confirmation displays the requested vaults, role and lifetime before login.
`connect` mode `renew` renews the existing token; `grant` changes one vault's
access; `resume` completes saved pending grants after partial failure. Each uses
browser authorization and human confirmation. There is no automatic privilege
escalation. A newly issued token is persisted **before** grants, listing or role
verification can fail. Pending setup blocks ordinary tools until recovery.

Agent sessions last two hours; the plugin automatically logs in again using the
saved token on an expired-session response. The token's lifetime is separate
(default one year). `session_info` reports its expiry and warns within 14 days;
renewal requires browser authorization. Missing/revoked tokens are not recovered
by asking for their value in chat.

`cancel_connection` stops a pending login and removes its temporary sessions.
Once token/grant changes are being committed, cancellation is refused until the
transaction finishes, so a remote change is not silently abandoned.
`disconnect` asks for confirmation and removes the shared local token and login.
It does **not** revoke the remote Proton token: revoke that in Proton Pass if
needed. Disconnecting affects all Bots sharing the installation.

## Approvals and host requirements

The default approval mechanism is the host's **MCP form elicitation** support.
The server checks the capability advertised by the client at initialization.
Every release binds the confirmation to the operation, item, exact origin or
command, and reason. Decline, timeout, malformed replies or disconnect deny it.
Forms never ask for passwords, OTPs, seeds or tokens. Network access for a
sandboxed command requires a separate affirmative checkbox.

**A host that does not advertise elicitation cannot approve releases or start
connection setup.** The plugin fails closed and reports this requirement. It
never silently trusts an assistant's `approved=true` argument or launches a
terminal approval helper. The native 1Password cards are a product integration;
this plugin does not claim to provide those private interfaces.

Grok Bot's actual elicitation UI, human takeover, persistent disk and browser
CDP accessibility must be checked in the deployed host. A green local test is
not evidence of those host capabilities or a successful real Proton login.

## Cloud runtime

The launcher provisions a private Python environment with pinned `idna` and
Playwright dependencies and downloads Proton CLI **2.5.1** from Proton, checking
its pinned SHA-256. It does not install a separate browser: it attaches to the
Bot's existing Chromium browser over loopback CDP. Python 3 with `venv` support,
Linux x86_64/aarch64 and outbound access to Proton/PyPI are required.

Runtime data defaults to `/workspace/.proton-pass` when `/workspace` is writable,
otherwise `~/.local/share/proton-pass-plugin`. It is outside the versioned plugin
cache. Bootstrap is locked across processes, repeatable, and reconstructs a
missing Python environment without replacing the token. A changed Python version
or dependency lock creates a new environment. Bootstrap output goes to stderr;
stdout is reserved for MCP JSON-RPC.

The launcher defaults to Proton's `fs` key provider for persistence across
process/VM restarts: its key is stored alongside the encrypted session, protected
by filesystem permissions. This intentionally follows the user's shared cloud
computer model. An explicit key provider configuration takes precedence.

| Variable | Purpose |
| --- | --- |
| `PASS_STATE_DIR` | Persistent runtime/credential root for the launcher |
| `PASS_CLI` | Explicit installed CLI executable; skips the bundled CLI download |
| `PASS_PAT_FILE` | Override token path; defaults to `PASS_STATE_DIR/pat` in the launcher |
| `PROTON_PASS_SESSION_DIR` | Shared scoped CLI session directory; defaults to `PASS_STATE_DIR/session` |
| `PROTON_PASS_KEY_PROVIDER` | `fs` by default in the launcher; explicit `env`/`keyring` supported |
| `PROTON_PASS_ENCRYPTION_KEY` | Key for an explicitly selected `env` provider; never a tool argument |
| `PROTON_PASS_LINUX_KEYRING` | Optional `dbus`; corresponding D-Bus environment is forwarded only then |
| `PASS_CDP_PORT` | Optional loopback CDP port, overridden by a tool's `cdp_port` |
| `PASS_APPROVAL_MODE` | `mcp` default; `terminal` is explicit legacy compatibility |

All Bot processes using the same PAT file serialize credential operations and
session refreshes with an OS lock. A separate setup lock prevents simultaneous
browser setups. Connection status belongs to the MCP process that started it;
if that process restarts, use `session_info` to inspect the saved shared state.

## Tools

| Tool | Result visible to the model |
| --- | --- |
| `capabilities` | Supported workflows, limitations and host approval support; no login |
| `connect` | Connection ID and state; sometimes the Proton authorization URL |
| `connection_status` | State, authorization link or temporary cloud form link; no credentials |
| `cancel_connection` | Cancellation status |
| `disconnect` | Local disconnect result and explicit remote-revocation status |
| `session_info` | Vault roles, token expiry, approval capability and recovery guidance |
| `list_vaults`, `search_items`, `describe_item` | Vault/item metadata; no secret values |
| `find_login` | Exact-origin candidates, account choice or fill arguments; no filling |
| `fill_login` | Fields filled, submission/detection status; no password or OTP |
| `fill_totp` | Fills a later OTP screen; result contains status only |
| `create_login` | Generated password stored in a vault; returns share and item IDs |
| `create_alias` | New forwarding email address and share/item IDs |
| `run_approved` | Exit code of a sandboxed command; no output |

There is **no `get_totp` tool**. `fill_login` and `fill_totp` report `totp: filled`
or `totp: detect_failed`, never digits. The cloud tool schema accepts no raw
password or TOTP seed. Import an existing secret through Proton itself.

Browser filling requires exactly one main-frame tab matching a saved website's
origin (scheme, host and port). Subdomains are not implicit matches. Port
discovery probes loopback Chrome CDP endpoints and refuses ambiguity. Filling
runs in an isolated world, rechecks the origin after approval, and refuses
hidden/disabled/inert/unfocusable password inputs. A password form is never
automatically submitted. An OTP form separate from a password form may be
submitted; a code in the password form is filled but left unsubmitted.

`run_approved` additionally requires Linux bubblewrap, libseccomp and a supported
core-dump policy. It deliberately refuses systems using an external core-dump
collector. The sandbox has a private process namespace, no workspace/home access,
no output, and no network unless separately approved. These optional system
requirements are not installed or modified by bootstrap.

## Legacy terminal operation

Direct `python3 server/proton_pass_mcp.py` execution uses the current interpreter
and needs `pip install -r requirements.txt`. `PASS_CLI` defaults to the executable
on PATH, then `~/.local/bin/pass-cli`. Direct execution retains the former token
and session paths (`~/.config/pass-agent/pat`, `~/.local/share/pass-agent`).

Explicit `PASS_APPROVAL_MODE=terminal` retains the `approve` helper for local
operators and exposes legacy secret-import tools (`save_totp` and raw-secret
arguments to `create_login`). It does not restore a tool that returns OTPs. This
mode is not the Grok Bot workflow. Legacy setup remains available:

```sh
python3 server/proton_pass_mcp.py setup --vault Bots --role editor
python3 server/proton_pass_mcp.py setup --renew
python3 server/proton_pass_mcp.py setup --grant --vault Bots --role viewer
```

## Validation and sources

The test suite uses fake Proton subprocesses plus real PTYs, stdio MCP, OS locks,
loopback HTTP and Chromium CDP. It checks browser login completion, cancellation,
extra-password delivery, host consent, partial setup recovery, OTP non-disclosure
and hostile page/origin cases. It does not consume real vault data.

Run `python3 tests/test_cloud.py`, `python3 tests/test_setup.py` and the other
`tests/test_*.py` entry points. Browser suites need
`python3 -m playwright install chromium`. Full sandbox tests run on the disposable
Ubuntu CI runner configured in `.github/workflows/test.yml`; do not weaken a
workstation's core-dump or namespace policy to run them.

- [Proton web login and extra password](https://protonpass.github.io/pass-cli/commands/login/)
- [Proton agent credentials](https://protonpass.github.io/pass-cli/commands/agent/)
- [Proton session key providers](https://protonpass.github.io/pass-cli/get-started/configuration/)
- [Proton CLI downloads and verification](https://protonpass.github.io/pass-cli/get-started/installation/)
- [Grok Bot computer and apps](https://docs.x.ai/grok-bot/computer-and-apps)
- [Cursor: connecting 1Password](https://cursor.com/help/grok-bot/connect-apps)
- [MCP elicitation](https://modelcontextprotocol.io/specification/2025-06-18/client/elicitation)
