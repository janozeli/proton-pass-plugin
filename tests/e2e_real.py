"""Real end-to-end against the user's Proton Pass via the MCP server. Never prints secret values.
Starts a fresh session dir (forces auto-login), a private headless Chrome on CDP 9333 and a local login page."""
import hashlib, http.server, json, os, shutil, subprocess, tempfile, threading, time, urllib.request
from mcp_client import Client
from playwright.sync_api import sync_playwright

sess = tempfile.mkdtemp(prefix="pass-agent-e2e-")
c = Client({"PROTON_PASS_SESSION_DIR": sess})
h = lambda s: hashlib.sha256(s.encode()).hexdigest()

print("## list_vaults (fresh session dir -> auto login)")
print(json.dumps([{"name": v["name"], "share_id": v["share_id"][:10] + "..."} for v in c.call("list_vaults")]))

print("## search_items(type=login, query='')")
r = c.call("search_items", query="", type="login", limit=3)
print("count:", r["count"]); [print(" -", i["title"], i["type"], i["item_id"][:10] + "...") for i in r["items"]]
print("## search_items(query='google')")
r2 = c.call("search_items", query="google", limit=5)
print("count:", r2["count"]); [print(" -", i["title"], i["type"]) for i in r2["items"]]

target = None
for i in c.call("search_items", type="login", limit=200)["items"]:
    d = c.call("describe_item", share_id=i["share_id"], item_id=i["item_id"], reason="plugin e2e test")
    if d["has_password"] and (d["username"] or d["email"]):
        target = i; break
print("## describe_item (secret-free view)")
print(json.dumps({k: (v if k not in ("username", "email") else (v[:2] + "***" if v else "")) for k, v in d.items() if k not in ("share_id", "item_id")}, ensure_ascii=False))
ids = {"share_id": target["share_id"], "item_id": target["item_id"]}

print("## run_with_secrets")
ref = f"pass://{ids['share_id']}/{ids['item_id']}/password"
r = c.call("run_with_secrets", command='echo "len=${#PW}"; echo "raw: $PW"', env={"PW": ref}, reason="plugin e2e test")
print(json.dumps(r, ensure_ascii=False))

# ground truth for verification only, hashed, never printed
truth_pw = subprocess.run([os.path.expanduser("~/.local/bin/pass-cli"), "item", "view", "--share-id", ids["share_id"], "--item-id", ids["item_id"], "--field", "password"],
                          env=dict(os.environ, PROTON_PASS_SESSION_DIR=sess, PROTON_PASS_AGENT_REASON="plugin e2e verify"), capture_output=True, text=True).stdout.rstrip("\n")
assert truth_pw and truth_pw not in json.dumps(r), "secret leaked in run_with_secrets output"
print("secret absent from tool output: True")

print("## fill_login into private headless Chrome")
web = tempfile.mkdtemp()
open(f"{web}/login.html", "w").write('<form><input type=email id=user><input type=password id=pw></form>')
srv = http.server.ThreadingHTTPServer(("127.0.0.1", 8765), lambda *a: http.server.SimpleHTTPRequestHandler(*a, directory=web))
threading.Thread(target=srv.serve_forever, daemon=True).start()
prof = tempfile.mkdtemp()
chrome = subprocess.Popen(["google-chrome", "--headless=new", "--remote-debugging-port=9333", f"--user-data-dir={prof}", "--no-first-run", "http://127.0.0.1:8765/login.html"],
                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
for _ in range(50):
    try: urllib.request.urlopen("http://127.0.0.1:9333/json/version"); break
    except Exception: time.sleep(0.2)
time.sleep(1.5)
try:
    r = c.call("fill_login", **ids, cdp_port=9333, url_match="127.0.0.1:8765", reason="plugin e2e test")
    print(json.dumps(r))
    assert truth_pw not in json.dumps(r)
    with sync_playwright() as p:
        b = p.chromium.connect_over_cdp("http://127.0.0.1:9333")
        pg = [x for ctx in b.contexts for x in ctx.pages if "8765" in x.url][0]
        got = pg.eval_on_selector("#pw", "e => e.value"); user = pg.eval_on_selector("#user", "e => e.value")
        b.close()
    print("password field matches vault (sha256 compare):", h(got) == h(truth_pw), "| username field non-empty:", bool(user))
    assert h(got) == h(truth_pw)
finally:
    chrome.kill(); srv.shutdown(); c.close(); shutil.rmtree(prof, ignore_errors=True); shutil.rmtree(sess, ignore_errors=True)
print("E2E OK")
