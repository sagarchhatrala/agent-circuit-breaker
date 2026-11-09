"""Cooperative thread/process locks for local JSONL decision logs."""

from contextlib import contextmanager
from functools import wraps
import os
from pathlib import Path
import threading


_registry = {}
_registry_lock = threading.Lock()
_held = threading.local()


@contextmanager
def log_lock(path: Path):
    """Serialize cooperating writers; the lock is not a hostile-host boundary."""
    identity = str(path.resolve())
    with _registry_lock:
        lock = _registry.setdefault(identity, threading.RLock())
    with lock:
        held = getattr(_held, "paths", set())
        if identity in held:
            yield
            return
        path.parent.mkdir(parents=True, exist_ok=True)
        descriptor = os.open(identity + ".lock", os.O_CREAT | os.O_RDWR, 0o600)
        with os.fdopen(descriptor, "r+b") as handle:
            if os.name == "nt":
                import msvcrt
                if os.fstat(descriptor).st_size == 0:
                    handle.write(b"0")
                    handle.flush()
                handle.seek(0)
                msvcrt.locking(descriptor, msvcrt.LK_LOCK, 1)
            else:
                import fcntl
                fcntl.flock(descriptor, fcntl.LOCK_EX)
            _held.paths = held | {identity}
            try:
                yield
            finally:
                _held.paths = held
                if os.name == "nt":
                    handle.seek(0)
                    msvcrt.locking(descriptor, msvcrt.LK_UNLCK, 1)
                else:
                    fcntl.flock(descriptor, fcntl.LOCK_UN)


def locked_log(method):
    @wraps(method)
    def wrapped(self, *args, **kwargs):
        with log_lock(self.path):
            return method(self, *args, **kwargs)
    return wrapped
