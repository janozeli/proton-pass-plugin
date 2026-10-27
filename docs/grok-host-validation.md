# Deployed Grok Bot acceptance

Local subprocess/browser tests do not establish host support. Keep the PR a draft
until the following pass in the target Grok Bot account. Use a dedicated test
vault and dummy website credentials, not a production login.

1. Import the implementation branch and confirm its MCP server version is 0.5.0.
   Confirm the stdio process runs on the cloud computer and its state directory
   is on the persistent disk, outside the imported plugin checkout.
2. Call `capabilities`, then `session_info`. The latter's error/result must include `approval_available: true`.
   If false, stop: the current host is not advertising MCP form elicitation.
   Do not enable terminal mode or replace this check with model confirmation.
3. Call `connect` for the test vault with `viewer`. Confirm the host presents the
   server's confirmation, including the vault/role/lifetime. Declining must not
   start Proton login. Accept a fresh request and open its authorization URL.
4. The human signs into Proton. No token/code is pasted back to the Bot. If Pass
   has an extra password, take over the cloud browser and use its temporary local
   form; no screenshot or DOM read of that form is allowed by the Bot.
5. Poll until `connected`; inspect vault permissions with `session_info`. Ask a
   second MCP client process to inspect the same connection. Restart the MCP process and verify
   reuse. Cancel a separate pending renewal and verify the original token works.
6. Use `find_login` with the test site's origin. Two accounts must require a choice;
   a unique account must return IDs and the pinned website in `fill_arguments`.
   Open that origin in exactly one cloud browser tab. Approve
   `fill_login`. The tool must return fields/status only. Repeat on a later OTP
   screen using `fill_totp`; decline a request and verify nothing was filled.
7. Recreate the disposable cloud computer while retaining its documented durable
   disk. Verify bootstrap reconstructs runtime dependencies and the scoped login
   is recovered without copying a token. Do not terminate a production computer
   just to run this test.
8. Disconnect the test connection; another MCP client must report disconnected. Revoke
   the test agent token in Proton if it is no longer needed.

## Evidence collected during implementation

- Fake Proton CLI with real PTY/MCP/HTTP: connection, extra password, cancellation,
  SIGTERM cleanup, concurrent setup refusal, grant and renewal recovery, host
  approval denial and local disconnect covered by tests/test_cloud.py.
- Chromium: existing origin/field defenses and OTP-only filling covered by
  tests/test_fill.py. OTP values never appear in MCP results.
- Pinned CLI 2.5.1: actual web-login process reached account.proton.me and was
  cancelled before account authorization; no token was created.
- Bootstrap: clean installation plus repeat launch verified locally.
- Target Grok Bot account: **not yet verified**. No native 1Password API or
  undocumented Grok API is assumed by this implementation.

## 2026-10-27 implementation-only review

No Bot was contacted and no cloud installation was changed during this review.
The 0.5.0 workflows are tested through stdio MCP, a synthetic CLI fixture and
local Chromium. CLI syntax and password generation are also checked against the
hash-verified official 2.5.1 binary. Real alias creation and the target host's MCP
elicitation support remain unverified. Do not interpret this checklist as
authorization to contact Bots or to run production-account tests.
