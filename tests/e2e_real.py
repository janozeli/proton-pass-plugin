"""Opt-in metadata smoke test against an already connected real Proton account.

Never auto-approves a release, prints vault names/IDs, or extracts an OTP.
Actual browser filling and consent must be exercised from the deployed host.
"""
import os
from mcp_client import Client

if os.environ.get("PROTON_PASS_REAL_TEST") != "1":
    raise SystemExit("Set PROTON_PASS_REAL_TEST=1 only with an explicitly authorized test account.")

client = Client()
try:
    report = client.call("session_info")
    assert report["identity_type"] == "agent_token"
    vaults = client.call("list_vaults")
    print("Authenticated scoped connection; vault count:", len(vaults))
    tools = {tool["name"] for tool in client.rpc("tools/list")["tools"]}
    assert "get_totp" not in tools and "fill_totp" in tools
    print("Metadata-only smoke passed; human consent and browser filling remain host checks.")
finally:
    client.close()
