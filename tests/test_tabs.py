import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "server"))
from proton_pass_mcp import origin

saved = {
    "https://bank.com/login": "https://bank.com",
    "https://bank.com:443/login": "https://bank.com",
    "bank.com/login": "https://bank.com",
    "https://user:pw@Bank.COM/x": "https://bank.com",
    "http://bank.com:80/": "http://bank.com",
    "https://bank.com:8443/": "https://bank.com:8443",
    "http://127.0.0.1:8765/login.html": "http://127.0.0.1:8765",
    "http://[::1]:8080/": "http://[::1]:8080",
    "com": "https://com",
    "android://com.bank.app": None,
    "https://bank.com:99999/": None,
    "https://[broken/": None,
}
for url, want in saved.items():
    assert origin(url, saved=True) == want, (url, origin(url, saved=True))

pages = {
    "https://evil.com/?next=https://bank.com": "https://evil.com",
    "https://evil.com/login?redirect=bank.com": "https://evil.com",
    "https://bank.com.evil.com/x": "https://bank.com.evil.com",
    "https://login.bank.com/a": "https://login.bank.com",
    "https://bank.com/login?x=1": "https://bank.com",
    "bank.com/login": None,
    "about:blank": None,
    "file:///etc/passwd": None,
}
for url, want in pages.items():
    assert origin(url) == want, (url, origin(url))

assert origin("https://login.bank.com/a") != origin("bank.com", saved=True)
assert origin("https://evil.com/") != origin("com", saved=True)
assert origin("http://bank.com/") != origin("https://bank.com", saved=True)
assert origin("https://bank.com:443/x") == origin("bank.com", saved=True)
print("test_tabs OK")
