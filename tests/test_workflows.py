"""Real stdio MCP + fake CLI: discovery, consent and secret-free workflows."""
import json
import os
from pathlib import Path

from harness import PASSWORD, SEED, calls, error, install, item, server_env, write
from mcp_client import Client


def connected(consent=None, capabilities=None):
    root = install()
    client = Client(server_env(root, PASS_APPROVAL_MODE="mcp"),
                    capabilities={"elicitation": {}} if capabilities is None else capabilities,
                    consent=consent or (lambda _: {"action": "accept", "content": {"approve": True}}))
    return root, client


def catalog(root, duplicates=False):
    vaults, summaries, full = [], {}, {}
    for index, origin in enumerate(("https://bank.com", "https://bank.com", "https://bank.com.evil.test")):
        share, ident = f"share{index}", f"item{index}"
        name = "Duplicated" if duplicates else f"Vault{index}"
        vaults.append({"name": name, "share_id": share, "vault_id": f"v{index}"})
        summaries[share] = [{"title": "Work" if index == 0 else "Personal", "id": ident,
                             "share_id": share, "item_type": "login", "state": "Active", "modify_time": index}]
        data = item([origin + "/login?not-for-the-model"])["item"]
        data.update(id=ident, share_id=share)
        data["content"]["title"] = summaries[share][0]["title"]
        data["content"]["content"]["Login"]["email"] = f"account{index}@example.com"
        full[share + "/" + ident] = data
    write(root, "vaults.json", {"vaults": vaults})
    write(root, "items-by-share.json", summaries)
    write(root, "items-by-id.json", full)
    return full


def test_site_discovery_finds_nonmatching_titles_and_requires_account_choice():
    root, c = connected()
    catalog(root, duplicates=True)
    try:
        result = c.call("find_login", website="https://bank.com/sign-in", reason="Sign into requested bank", limit=1)
        assert result["state"] == "choose_account" and result["count"] == 2
        assert result["next_offset"] == 1 and "fill_arguments" not in result
        second = c.call("find_login", website="https://bank.com", reason="Choose account", offset=1)
        assert second["items"][0]["item_id"] != result["items"][0]["item_id"]
        selected = c.call("find_login", website="bank.com", account="account0@example.com", reason="Use work account")
        assert selected["state"] == "ready" and selected["items"][0]["title"] == "Work"
        assert selected["fill_arguments"] == {"share_id": "share0", "item_id": "item0", "website": "https://bank.com", "reason": "Use work account"}
        assert selected["available_tools"] == ["fill_login", "fill_totp"]
        assert not any(secret in json.dumps(selected) for secret in (PASSWORD, SEED, "private note", "not-for-the-model"))
        for website in ("https://sub.bank.com", "http://bank.com", "https://bank.com:8443"):
            assert c.call("find_login", website=website, reason="Check exact origin")["state"] == "not_found"
        assert not any(call[:3] == ["item", "create", "login"] for call in calls(root))
    finally:
        c.close()


def test_vault_search_uses_ids_paginates_and_refuses_duplicate_names():
    root, c = connected()
    catalog(root, duplicates=True)
    try:
        all_items = c.call("search_items")
        assert all_items["count"] == 3
        assert len({row["share_id"] for row in all_items["items"]}) == 3
        assert "ambiguous" in error(c, "search_items", vault="Duplicated")
        assert c.call("search_items", share_id="share0")["count"] == 1
        first = c.call("search_items", limit=1)
        last = c.call("search_items", offset=first["next_offset"], limit=2)
        assert first["items"] + last["items"] == all_items["items"]
        assert last["next_offset"] is None
        assert "both" in error(c, "search_items", share_id="share0", vault="Duplicated")
        assert "offset" in error(c, "search_items", offset=-1)
        assert "100" in error(c, "search_items", limit=101)
        assert all("--share-id" in cmd and "--vault-name" not in cmd for cmd in calls(root) if cmd[:2] == ["item", "list"])
    finally:
        c.close()


def test_metadata_references_keep_sections_and_omit_ambiguous_names_and_secrets():
    root, c = connected()
    data = item(["https://bank.com"])
    data["item"]["content"]["content"] = {"Custom": {"sections": [
        {"section_name": "Production", "section_fields": [{"name": "token", "content": {"Hidden": "SECRET-PROD"}}]},
        {"section_name": "Staging", "section_fields": [{"name": "token", "content": {"Hidden": "SECRET-STAGE"}}]},
    ]}}
    data["item"]["content"]["extra_fields"] = [
        {"name": "API", "content": {"Text": "SECRET-ONE"}},
        {"name": "api", "content": {"Hidden": "SECRET-TWO"}},
        {"name": "unsafe/field", "content": {"Hidden": "SECRET-THREE"}},
    ]
    write(root, "item.json", data)
    try:
        result = c.call("describe_item", share_id="share1", item_id="item1")
        assert result["references"]["Production.token"] == "pass://share1/item1/Production.token"
        assert result["references"]["Staging.token"] == "pass://share1/item1/Staging.token"
        assert set(result["unavailable_reference_fields"]) == {"API", "api", "unsafe/field"}
        assert "SECRET-" not in json.dumps(result) and "private note" not in json.dumps(result)
        data["item"]["content"]["content"] = {"Login": {"password": PASSWORD}}
        data["item"]["content"]["extra_fields"] = [{"name": "Password", "content": {"Hidden": "different"}}]
        write(root, "item.json", data)
        collision = c.call("describe_item", share_id="share1", item_id="item1")
        assert "password" not in collision["references"] and "Password" not in collision["references"]
    finally:
        c.close()


def test_creation_defaults_generate_and_returns_reusable_ids_only_after_consent():
    prompts = []
    def deny(prompt):
        prompts.append(prompt)
        return {"action": "decline"}
    root, c = connected(deny)
    write(root, "shares.json", {"shares": [{"id": "share1", "share_role": "Editor"}]})
    try:
        assert "denied" in error(c, "create_login", title="New site", reason="Requested signup")
        assert not Path(root, "created.json").exists()
        assert not any(cmd[:1] == ["password"] for cmd in calls(root))
        c.consent = lambda _: {"action": "accept", "content": {"approve": True}}
        result = c.call("create_login", title="New site", reason="Requested signup", password_length=32, password_symbols=False)
        assert result == {"share_id": "share1", "item_id": "item-new"}
        saved = json.loads(Path(root, "created.json").read_text())
        assert len(saved["password"]) == 32 and saved["password"].isalnum()
        assert saved["password"] not in json.dumps(result) + json.dumps(prompts) + json.dumps(calls(root))
        assert "16 and 128" in error(c, "create_login", title="New site", reason="r", password_length=1)
        assert "unknown argument password" in error(c, "create_login", title="New site", reason="r", password=PASSWORD)
    finally:
        c.close()


def test_alias_needs_write_access_and_consent_and_returns_only_address_and_ids():
    root, c = connected()
    try:
        assert "needs write access" in error(c, "create_alias", prefix="signup", reason="Create signup address")
        assert not Path(root, "alias-created").exists()
        write(root, "shares.json", {"shares": [{"id": "share1", "share_role": "Editor"}]})
        c.consent = lambda _: {"action": "decline"}
        assert "denied" in error(c, "create_alias", prefix="signup", reason="Create signup address")
        assert not Path(root, "alias-created").exists()
        c.consent = lambda _: {"action": "accept", "content": {"approve": True}}
        result = c.call("create_alias", prefix="signup", reason="Create signup address")
        assert result == {"share_id": "share1", "item_id": "alias-new", "email": "signup.random@passmail.net"}
        assert "prefix" in error(c, "create_alias", prefix="--help", reason="r")
    finally:
        c.close()


def test_capabilities_available_without_login_and_no_cloud_shell_setup_commands():
    root, c = connected(capabilities={})
    os.unlink(Path(root, "pat"))
    try:
        result = c.call("capabilities")
        assert result["approval"] == {"mechanism": "mcp_elicitation", "available": False}
        assert calls(root) == []
        info = json.loads(error(c, "session_info"))
        assert info["state"] == "disconnected" and info["next_step"] == "connect"
        assert "setup_command" not in info
        write(root, "pat.pending", {})
        pending = json.loads(error(c, "session_info"))
        assert pending["state"] == "incomplete" and pending["next_step"] == "connect mode resume"
    finally:
        c.close()


def test_discovery_rejects_credential_urls_and_never_labels_failed_reads_as_not_found():
    root, c = connected()
    try:
        assert "embedded credentials" in error(c, "find_login", website="https://user:secret@bank.com", reason="r")
        assert calls(root) == []
        write(root, "stderr", "upstream secret error")
        assert error(c, "find_login", website="bank.com", reason="r") == "pass-cli vault failed"
    finally:
        c.close()


if __name__ == "__main__":
    for name, test in list(globals().items()):
        if name.startswith("test_"):
            test()
            print(name, "OK")
