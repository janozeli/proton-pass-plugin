"""Cross-process locks for all Bots using the same credential file."""
import contextlib
import fcntl
import os
import stat
import threading

_local = threading.local()
_mutex = threading.RLock()


def lock_file(path, blocking=True):
    os.makedirs(os.path.dirname(path), mode=0o700, exist_ok=True)
    fd = os.open(path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_uid != os.getuid() or st.st_mode & 0o077:
            raise OSError("lock file must be private and owned by this user")
        fcntl.flock(fd, fcntl.LOCK_EX | (0 if blocking else fcntl.LOCK_NB))
        return fd
    except BaseException:
        os.close(fd)
        raise


def unlock(fd):
    fcntl.flock(fd, fcntl.LOCK_UN)
    os.close(fd)


@contextlib.contextmanager
def operation_lock():
    # Reentrant within a worker; flock coordinates independent MCP processes.
    with _mutex:
        if getattr(_local, "depth", 0):
            _local.depth += 1
            try:
                yield
            finally:
                _local.depth -= 1
            return
        path = os.path.abspath(os.path.expanduser(os.environ.get("PASS_PAT_FILE", "~/.config/pass-agent/pat")))
        fd = lock_file(path + ".operations.lock")
        _local.depth = 1
        try:
            yield
        finally:
            _local.depth = 0
            unlock(fd)
