#!/usr/bin/env python3
"""Idempotent, per-account cloud runtime. Never writes to the plugin cache."""
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import tempfile
import urllib.request
import venv

from shared_state import lock_file, unlock

ROOT = Path(__file__).resolve().parent.parent
CLI_VERSION = "2.5.1"
BINARIES = {
    "x86_64": "40e27645e0485f5f0db928b81469d1c5a7c8968a162956e940069476244c02b1",
    "aarch64": "03042c8ad70b21fa1da834f2e4e74484710ab3f05754af10c5035acdf68f3c87",
}


def prepare():
    default = "/workspace/.proton-pass" if os.path.isdir("/workspace") and os.access("/workspace", os.W_OK) else "~/.local/share/proton-pass-plugin"
    state = Path(os.path.expanduser(os.environ.get("PASS_STATE_DIR", default))).absolute()
    state.mkdir(mode=0o700, parents=True, exist_ok=True)
    if state.is_symlink() or state.stat().st_uid != os.getuid():
        raise RuntimeError("PASS_STATE_DIR must be a directory owned by this user")
    state.chmod(0o700)
    fd = lock_file(str(state / "bootstrap.lock"))
    try:
        digest = hashlib.sha256((ROOT / "requirements.txt").read_bytes() + sys.version.encode()).hexdigest()[:16]
        runtime = state / ("python-" + digest)
        python = runtime / "bin/python"
        ready = runtime / ".ready"
        if not ready.exists() or not python.exists():
            venv.EnvBuilder(with_pip=True, clear=True).create(runtime)
            subprocess.run([str(python), "-m", "pip", "install", "--disable-pip-version-check", "-r", str(ROOT / "requirements.txt")],
                           stdin=subprocess.DEVNULL, stdout=sys.stderr, stderr=sys.stderr, check=True, timeout=240)
            ready.touch(mode=0o600)
        cli = os.environ.get("PASS_CLI")
        if cli:
            cli = os.path.abspath(os.path.expanduser(cli))
            if not os.access(cli, os.X_OK):
                raise RuntimeError("Configured PASS_CLI is not executable")
        else:
            arch = platform.machine()
            if platform.system() != "Linux" or arch not in BINARIES:
                raise RuntimeError("Cloud runtime requires Linux x86_64/aarch64 or an explicit PASS_CLI")
            binary = state / ("pass-cli-" + CLI_VERSION)
            valid = binary.is_file() and not binary.is_symlink() and hashlib.sha256(binary.read_bytes()).hexdigest() == BINARIES[arch]
            if not valid:
                url = f"https://proton.me/download/pass-cli/{CLI_VERSION}/pass-cli-linux-{arch}"
                with urllib.request.urlopen(url, timeout=60) as response:
                    data = response.read(150 * 1024 * 1024)
                if hashlib.sha256(data).hexdigest() != BINARIES[arch]:
                    raise RuntimeError("Proton CLI integrity check failed")
                tmp_fd, tmp = tempfile.mkstemp(dir=state)
                try:
                    with os.fdopen(tmp_fd, "wb") as target:
                        target.write(data)
                        target.flush()
                        os.fsync(target.fileno())
                    os.chmod(tmp, 0o700)
                    os.replace(tmp, binary)
                finally:
                    if os.path.exists(tmp):
                        os.unlink(tmp)
            cli = str(binary)
        env = dict(os.environ)
        env["PASS_CLI"] = cli
        env.setdefault("PASS_PAT_FILE", str(state / "pat"))
        env.setdefault("PROTON_PASS_SESSION_DIR", str(state / "session"))
        # An explicit key provider wins. fs persists across VM process restarts,
        # and fits the user's shared-computer trust model (key beside ciphertext).
        env.setdefault("PROTON_PASS_KEY_PROVIDER", "fs")
        env.setdefault("PASS_APPROVAL_MODE", "mcp")
        return str(python), env
    finally:
        unlock(fd)


def main():
    try:
        python, env = prepare()
    except Exception as exc:
        sys.exit(f"proton-pass runtime setup failed: {type(exc).__name__}. Check network, Python venv support and PASS_STATE_DIR; no login was attempted.")
    os.execve(python, [python, str(ROOT / "server/proton_pass_mcp.py"), *sys.argv[1:]], env)


if __name__ == "__main__":
    main()
