"""Real end-to-end against the user's Proton Pass via the MCP server. Never prints secret values.
Starts a fresh session dir (forces auto-login) and approves its own releases on the approval socket,
so run it only against your own account. test_fill.py covers the browser fill offline."""
import json, re, shutil, tempfile
from harness import Operator, session
from mcp_client import Client

d = tempfile.mkdtemp(prefix="pass-agent-e2e-")
c = Client({"PROTON_PASS_SESSION_DIR": session(d)})
op = Operator(d)
try:
    print("## list_vaults (fresh session dir -> auto login)")
    print(json.dumps([{"name": v["name"], "share_id": v["share_id"][:10] + "..."} for v in c.call("list_vaults")]))

    print("## search_items(type=login)")
    found = c.call("search_items", type="login", limit=200)
    print("count:", found["count"])

    target = totp = None
    for i in found["items"]:
        info = c.call("describe_item", share_id=i["share_id"], item_id=i["item_id"], reason="plugin e2e test")
        target = target or (i if info["has_password"] else None)
        totp = totp or (i if info["has_totp"] else None)
        if target and totp:
            break
    assert target, "no login with a password"

    print("## run_approved (sandbox, no network)")
    ref = f"pass://{target['share_id']}/{target['item_id']}/password"
    r = c.call("run_approved", argv=["/bin/sh", "-c", 'test -n "$PW"'], env={"PW": ref}, reason="plugin e2e test")
    print(json.dumps(r))
    assert r == {"exit_code": 0}, r
    assert op.prompts[-1]["env"] == [["PW", ref, target["title"], "password"]], op.prompts[-1]

    if totp:
        print("## get_totp")
        r = c.call("get_totp", share_id=totp["share_id"], item_id=totp["item_id"], reason="plugin e2e test")
        assert list(r) == ["code"] and re.fullmatch(r"[0-9]{6,8}", r["code"]), "unexpected get_totp result"
        print(f"code: {len(r['code'])} digits")
finally:
    op.close()
    c.close()
    shutil.rmtree(d, ignore_errors=True)
print("E2E OK")
