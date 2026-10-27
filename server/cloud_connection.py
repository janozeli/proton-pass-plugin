"""Cancelable web authentication with no tokens or passwords in MCP messages.

An ephemeral loopback form handles the optional Pass extra password. It is opened
on the cloud computer, under human takeover, not on the user's local computer.
It is not a security boundary against other programs owned by the same user.
"""
import fcntl
import json
import os
import pty
import re
import secrets
import select
import signal
import subprocess
import sys
import termios
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

import setup_agent as setup
from shared_state import lock_file, unlock


class Connection:
    def __init__(self, opts, lock_fd):
        self.opts, self.lock_fd = opts, lock_fd
        self.id = secrets.token_hex(16)
        self.stop = threading.Event()
        self.changed = threading.Event()
        self.mutex = threading.Lock()
        self.state = "starting"
        self.auth_url = None
        self.error = None
        self.extra = None
        self.portal = None
        self.portal_url = None
        self.thread = threading.Thread(target=self.run, daemon=True)

    def status(self):
        with self.mutex:
            result = {"connection_id": self.id, "state": self.state}
            if self.state == "waiting_for_browser" and self.auth_url:
                result["authorization_url"] = self.auth_url
            if self.state == "waiting_for_extra_password":
                result.update({"cloud_computer_url": self.portal_url,
                               "instruction": "Take over the Bot's cloud browser and open this loopback page there. Enter the Pass extra password in that page, never in chat."})
            if self.error:
                result["error"] = self.error
            return result

    def update(self, state):
        with self.mutex:
            self.state = state
        self.changed.set()

    def cancel(self):
        with self.mutex:
            if self.state == "configuring":
                raise setup.SetupError("Credential changes are being committed; wait for connection_status before disconnecting.")
            if self.state in ("connected", "failed", "cancelled"):
                return self.status_unlocked()
            self.stop.set()
        return {"connection_id": self.id, "state": "cancelling"}

    def status_unlocked(self):
        return {"connection_id": self.id, "state": self.state}

    def start_portal(self):
        owner = self
        path = "/" + secrets.token_urlsafe(32)

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def valid(self):
                host = f"127.0.0.1:{self.server.server_port}"
                return (self.path == path and self.headers.get("Host") == host
                        and self.headers.get("Origin", "http://" + host) == "http://" + host)

            def reply(self, status, body):
                self.send_response(status)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Cache-Control", "no-store")
                self.send_header("Referrer-Policy", "no-referrer")
                self.send_header("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'")
                self.end_headers()
                self.wfile.write(body.encode())

            def do_GET(self):
                if not self.valid():
                    return self.reply(404, "Not found")
                self.reply(200, '<!doctype html><meta charset="utf-8"><title>Connect Proton Pass</title>'
                           '<main style="font:18px system-ui;max-width:520px;margin:60px auto;padding:24px">'
                           '<h1>Unlock Proton Pass</h1><p>Enter your additional Pass password. It is sent only to the local login process and is not returned to the Bot.</p>'
                           '<form method="post"><label>Pass extra password <input type="password" name="password" required autocomplete="off" maxlength="1024"></label>'
                           '<p><button>Unlock</button></p></form><p>Close this page after unlocking.</p></main>')

            def do_POST(self):
                if not self.valid() or self.headers.get("Content-Type") != "application/x-www-form-urlencoded":
                    return self.reply(403, "Denied")
                try:
                    length = int(self.headers.get("Content-Length", "0"))
                    if not 0 < length <= 8192:
                        raise ValueError()
                    password = parse_qs(self.rfile.read(length).decode(), strict_parsing=True)["password"][0]
                    if not password or len(password) > 1024 or any(ord(c) < 32 for c in password):
                        raise ValueError()
                except (ValueError, KeyError, UnicodeError):
                    return self.reply(400, "Invalid input")
                with owner.mutex:
                    if owner.state != "waiting_for_extra_password" or owner.extra is not None:
                        return self.reply(409, "This request has already finished or been submitted.")
                    owner.extra = password
                self.reply(200, "<title>Proton Pass</title><p>Submitted. Return to the Bot to check the connection.</p>")

        self.portal = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.portal.daemon_threads = True
        self.portal_url = f"http://127.0.0.1:{self.portal.server_port}{path}"
        threading.Thread(target=self.portal.serve_forever, daemon=True).start()

    def login(self, cli, env):
        master, slave = pty.openpty()
        attrs = termios.tcgetattr(slave)
        attrs[3] &= ~termios.ECHO
        termios.tcsetattr(slave, termios.TCSANOW, attrs)
        # Establish a controlling tty in a fresh Python process (no preexec_fn
        # in a threaded server). Password prompts using /dev/tty work here.
        proc = subprocess.Popen([sys.executable, __file__, "--login-child", cli],
                                stdin=slave, stdout=slave, stderr=slave, env=env,
                                start_new_session=True, close_fds=True)
        os.close(slave)
        os.set_blocking(master, False)
        deadline = time.monotonic() + 600
        buf = ""
        try:
            while True:
                if self.stop.is_set():
                    raise setup.SetupError("Connection cancelled.")
                if time.monotonic() >= deadline:
                    raise setup.SetupError("Browser login timed out; start a new connection.")
                if select.select([master], [], [], 0.1)[0]:
                    try:
                        chunk = os.read(master, 4096)
                    except OSError:
                        chunk = b""
                    buf = (buf + chunk.decode("utf-8", "replace"))[-16384:]
                    if not self.auth_url:
                        match = re.search(r'https://[^\s\x1b]+(?=[\s\x1b])', buf)
                        if match:
                            url = match.group().rstrip(").,")
                            parsed = urlsplit(url)
                            if parsed.hostname != "account.proton.me" or parsed.username or parsed.port not in (None, 443) or "pst_" in url:
                                raise setup.SetupError("Unexpected Proton authorization URL; connection refused.")
                            self.auth_url = url
                            self.update("waiting_for_browser")
                    if re.search(r'(?:extra|additional)[^\r\n]{0,60}password[^\r\n]*:', buf, re.I):
                        if self.portal is None:
                            self.start_portal()
                        self.update("waiting_for_extra_password")
                        buf = ""
                with self.mutex:
                    password, self.extra = self.extra, None
                if password is not None:
                    os.write(master, (password + "\n").encode())
                    password = None
                    self.update("waiting_for_browser")
                if proc.poll() is not None:
                    if proc.returncode or not self.auth_url:
                        raise setup.SetupError("Proton web login failed. Retry authentication; no credential was returned to the Bot.")
                    with self.mutex:
                        if self.stop.is_set():
                            raise setup.SetupError("Connection cancelled.")
                        self.state = "configuring"
                    return self.auth_url
        finally:
            if proc.poll() is None:
                os.killpg(proc.pid, signal.SIGKILL)
            proc.wait()
            os.close(master)
            self.extra = None

    def run(self):
        try:
            setup.run(self.opts, login_fn=self.login, report=lambda _: None)
            final_state = "connected"
        except Exception:
            # CLI stdout/stderr may contain secrets; neither is a tool result.
            self.error = ("Connection did not finish. If a token was issued, it was saved; use resume to complete its grants. Otherwise retry connect.")
            final_state = "cancelled" if self.stop.is_set() else "failed"
        finally:
            if self.portal:
                self.portal.shutdown()
                self.portal.server_close()
            unlock(self.lock_fd)
            self.update(final_state)


class Manager:
    def __init__(self):
        self.current = None
        self.mutex = threading.Lock()

    def start(self, opts):
        with self.mutex:
            if self.current and self.current.thread.is_alive():
                raise setup.SetupError("A connection is already in progress; use connection_status.")
            if not opts.get("renew") and not opts.get("grant") and not opts.get("resume") and os.path.exists(setup.pat_path()):
                raise setup.SetupError("A credential already exists. Use renew, grant or resume instead of creating another agent.")
            try:
                fd = lock_file(setup.pat_path() + ".setup.lock", blocking=False)
            except BlockingIOError:
                raise setup.SetupError("Another Bot is connecting this account. Finish that connection first.")
            self.current = Connection(opts, fd)
            self.current.thread.start()
            # Usually the URL arrives immediately; never hold an MCP call for login.
            self.current.changed.wait(2)
            return self.current.status()

    def get(self, connection_id=None):
        if self.current is None or (connection_id and connection_id != self.current.id):
            raise setup.SetupError("No matching connection in this MCP session. Use session_info to check the shared credential.")
        return self.current

    def close(self):
        if self.current:
            self.current.stop.set()
            self.current.thread.join()


if __name__ == "__main__" and len(sys.argv) == 3 and sys.argv[1] == "--login-child":
    fcntl.ioctl(0, termios.TIOCSCTTY, 0)
    os.execve(sys.argv[2], [sys.argv[2], "login"], dict(os.environ))
