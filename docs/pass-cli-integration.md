# Pass CLI capabilities and Bot integration

Reviewed 2026-10-27 against the official documentation, public source at
[`5d0cfbf`](https://github.com/protonpass/pass-cli/tree/5d0cfbf8b7875550ce2494dd322032c34a3a6a72),
and the hash-verified Linux **2.5.1 (`84186e7`)** binary used by bootstrap.
The binary's `--help` is the authority for the shipped command surface; public
source and docs may describe a different build. No production account or Bot
was used for this review.

## Product model

The human asks for an outcome: sign into a site, save a new login, make an alias,
or let a program use a credential. MCP tools handle item lookup, stable IDs,
CLI invocation and state. Passwords, OTPs and tokens stay out of conversations.
All Bots share the connection and durable filesystem by design.

Approvals describe the actual operation. Connection setup still depends on a
host with MCP form elicitation; we have not demonstrated that capability in
Grok Bot. Installing the plugin in a dashboard does not establish tool exposure.
Native 1Password behavior is a UX reference, not a public interface we can call.

## Feature map

| CLI feature | Natural Bot use | Integration state |
| --- | --- | --- |
| Web login, PAT/agent tokens, grant/renew | “Connect this vault once for my Bots” | Existing asynchronous `connect`, status, cancellation and recovery. Login stays with the human; scoped sessions refresh automatically. |
| Vault/share listing; item list/view | “Find the account for this website” | **0.5.0:** exact-origin `find_login`, account disambiguation, stable share IDs, paginated title search. Secrets are projected out of responses. |
| Password generation; login templates via stdin | “Save credentials for this signup” | **0.5.0:** CLI-generated password by default, length/symbol options, IDs returned for filling. Does not register an account at the website. |
| TOTP generation and item TOTP | “Complete this second-factor screen” | Existing `fill_totp`, with an optional pinned website. Codes go directly to the page. No raw-code tool. |
| Alias creation | “Create a forwarding address for signup” | **0.5.0:** `create_alias`, write-role check and human approval; returns address and IDs. Real-account plan/eligibility acceptance is pending. |
| `pass://` references; `run` | “Let this program use my API key” | **0.5.0:** references discovered from metadata, with section qualification and ambiguity handling. Existing `run_approved` consumes them. |
| `inject` templates and private output files | “Prepare credentials for a deployment” | Not exposed. A future tool must specify output ownership, file lifetime and overwrite policy. Rendering a template into chat would expose its secrets. |
| SSH key generation/import; `ssh-agent start/load/daemon` | “Use this deploy key for Git/SSH” | CLI has the primitives, including daemon status/stop. Not implemented as MCP lifecycle tools yet. Requires shared socket ownership, restart/expiry behavior and authorization scope. |
| Item update, move, trash/untrash, permanent delete | “Organize or maintain saved credentials” | Not generally exposed. Prefer recoverable trash over delete. Secret updates need a non-chat input path and partial-failure handling; the CLI's field-update arguments can contain plaintext. |
| Notes, cards, identity, Wi-Fi, custom items | “Use the field required by this task” | Metadata discovery and references cover selected fields, including custom sections. Arbitrary content retrieval and identity/card autofill are not implemented. |
| Vault/folder management, sharing, invites | “Organize access for people and agents” | Keep outside daily Bot tools for now. Some actions are unavailable to PAT/agent sessions even when the CLI exposes the command. |
| Agent monitoring | “Show what the shared connection accessed” | Pass CLI provides `agent monitor`, including current-agent mode. Reasons are passed to supported operations. There is no MCP audit-log reader yet; audit records are not guaranteed for every command. |
| HTML archive export, attachments | “Make an offline backup” | Separate human administrative workflow. Not part of routine credential use. |
| Passkeys | “Sign in using my passkey” | No WebAuthn sign-in command was found in the verified CLI command surface. CLI item data is not an authenticator. Keep the site's supported Proton authentication route. |

## What reduces friction now

The preferred website sequence is `find_login → fill_login → fill_totp` (only if
the site later asks for an OTP). A unique match returns `fill_arguments` with the
exact origin and both IDs; no manual ID copying is needed. Multiple accounts
require a choice, not a title heuristic. Discovery reads all logins in scope,
because an agent's CLI listing intentionally omits URLs. Scope it to a vault for
large collections. A failed read is an error, not a false “no matches”.

`search_items` uses IDs even when vault names repeat. `describe_item` builds
references from known CLI field names, including `Section.field`. It omits
case-insensitive collisions and names outside the runner's supported syntax.
References are handles, not values, and metadata remains untrusted text.

Writes can infer a vault only when exactly one is accessible. Password
generation uses Proton's implementation and happens after approval. Creation
returns the identifiers required for subsequent steps; it does not claim the
website accepted the credentials. After uncertain writes, inspect before retrying
because these CLI mutations are not idempotent.

## Important remaining design work

**Developer workflows need a deliberate execution contract.** `run_approved`
currently isolates a program, hides output and denies workspace access. This
fits a narrow operation whose exit status is sufficient, but not a general
deployment workflow. The CLI's native output masking is useful against
accidental echoes; it cannot guarantee that a program will not transform or
exfiltrate a secret. Do not silently replace the current runner with an
unrestricted shell and claim equivalent protection. A future workspace runner
should make the approved command, files, network destination and output policy
explicit and test those guarantees.

**SSH should use the native agent mechanism.** It can avoid repeated private-key
materialization, but an agent socket permits signing operations to whoever can
access it. Our shared-computer model accepts sharing between Bots; the remaining
work is lifecycle and the human's intended authorization scope, not artificial
isolation between Bots.

**Host approval remains a real integration dependency.** `capabilities` reports
the advertised support without touching Proton. If the host lacks elicitation,
the next decision is which documented host approval mechanism to support. A
model-supplied `approved=true` flag is not a substitute for human approval.

## Sources

- [Login](https://protonpass.github.io/pass-cli/commands/login/) and [agent access/auditing](https://protonpass.github.io/pass-cli/commands/agent/)
- [Items, aliases and templates](https://protonpass.github.io/pass-cli/commands/item/)
- [Password generation](https://protonpass.github.io/pass-cli/commands/password/)
- [Secret references](https://protonpass.github.io/pass-cli/commands/contents/secret-references/), [run](https://protonpass.github.io/pass-cli/commands/contents/run/) and [inject](https://protonpass.github.io/pass-cli/commands/contents/inject/)
- [SSH agent](https://protonpass.github.io/pass-cli/commands/ssh-agent/)
- [Folders](https://protonpass.github.io/pass-cli/commands/folder/), [vaults](https://protonpass.github.io/pass-cli/commands/vault/) and [export](https://protonpass.github.io/pass-cli/commands/export/)
- [CLI permission guards](https://github.com/protonpass/pass-cli/blob/5d0cfbf8b7875550ce2494dd322032c34a3a6a72/pass/src/permission/mod.rs)

Local test evidence and the outstanding target-host checklist are in
[grok-host-validation.md](grok-host-validation.md). No Bot should be contacted
for acceptance without the user's explicit instruction.
