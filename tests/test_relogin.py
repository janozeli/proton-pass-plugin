"""Offline: a fake pass-cli that rejects calls until `login` runs proves auto re-login."""
import os, stat, tempfile
from mcp_client import Client

def test_relogin_on_expired_session():
    d = tempfile.mkdtemp()
    fake = os.path.join(d, "pass-cli")
    open(fake, "w").write(f"""#!/bin/bash
echo "$@" >> {d}/calls
if [ "$1" = login ]; then [ -n "$PROTON_PASS_PERSONAL_ACCESS_TOKEN" ] && touch {d}/ok; exit; fi
[ -f {d}/ok ] || {{ echo "Error: This operation requires an authenticated client" >&2; exit 1; }}
echo '{{"vaults":[{{"name":"V","vault_id":"v","share_id":"s"}}]}}'
""")
    os.chmod(fake, 0o755)
    open(f"{d}/pat", "w").write("fake-token")
    os.chmod(f"{d}/pat", 0o600)
    c = Client({"PASS_CLI": fake, "PASS_PAT_FILE": f"{d}/pat", "HOME": d})
    assert c.call("list_vaults")[0]["name"] == "V"
    calls = open(f"{d}/calls").read().split("\n")
    assert [l.split()[0] for l in calls if l] == ["vault", "login", "vault"], calls
    tools = {t["name"] for t in c.rpc("tools/list")["tools"]}
    assert tools == {"list_vaults", "search_items", "describe_item", "get_totp", "fill_login", "run_with_secrets", "get_secret"}
    c.close()
    print("test_relogin_on_expired_session OK; call sequence:", [l.split()[0] for l in calls if l])

if __name__ == "__main__":
    test_relogin_on_expired_session()
