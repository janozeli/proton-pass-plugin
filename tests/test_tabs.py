"""Tab choice for fill_login. Host match, not a substring of the whole URL."""
import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "server"))
from proton_pass_mcp import tab_matches

assert tab_matches("https://evil.com/?next=https://bank.com", "bank.com", []) is False
assert tab_matches("https://evil.com/login?redirect=bank.com", "bank.com", []) is False
assert tab_matches("https://bank.com.evil.com/x", "bank.com", []) is False
assert tab_matches("https://notbank.com/", "", ["bank.com"]) is False
assert tab_matches("http://127.0.0.1:8765/login.html", "127.0.0.1:8765", []) is True
assert tab_matches("https://login.bank.com/a", "", ["bank.com"]) is True
assert tab_matches("https://bank.com/login?x=1", "https://bank.com/other", []) is True
print("test_tabs OK")
