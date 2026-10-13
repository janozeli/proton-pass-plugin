import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "server"))
from proton_pass_mcp import browser_origin

cases = {
    "https://bank.com/login": "https://bank.com",
    "https://bank.com:443/login": "https://bank.com",
    "bank.com/login": "https://bank.com",
    "https://user:pw@Bank.COM/x": "https://bank.com",
    "http://bank.com:80/": "http://bank.com",
    "https://bank.com:8443/": "https://bank.com:8443",
    "http://127.0.0.1:8765/login.html": "http://127.0.0.1:8765",
    "http://[::1]:8080/": "http://[::1]:8080",
    "http://[::1]/": "http://[::1]",
    "https://Bücher.example/x": "https://xn--bcher-kva.example",
    "com": "https://com",
    "https://evil.com/?next=https://bank.com": "https://evil.com",
    "https://bank.com.evil.com/x": "https://bank.com.evil.com",
    "https://login.bank.com/a": "https://login.bank.com",
    "android://com.bank.app": None,
    "https://bank.com:99999/": None,
    "https://[broken/": None,
    "about:blank": None,
    "file:///etc/passwd": None,
    "data:text/html,<p>x</p>": None,
}
for url, want in cases.items():
    assert browser_origin(url) == want, (url, browser_origin(url))

assert browser_origin("https://login.bank.com/a") != browser_origin("bank.com")
assert browser_origin("https://evil.com/") != browser_origin("com")
assert browser_origin("http://bank.com/") != browser_origin("https://bank.com")
print("test_tabs OK")
