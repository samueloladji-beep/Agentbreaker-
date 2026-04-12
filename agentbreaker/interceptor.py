import builtins
import threading
import urllib.request
import urllib.parse
import subprocess
import os
from typing import Optional, Callable

_local = threading.local()

def _get_monitor():
    return getattr(_local, "monitor", None)

def _set_monitor(monitor):
    _local.monitor = monitor

def _clear_monitor():
    _local.monitor = None


class FileInterceptor:
    """Intercepts file open() calls."""

    def __init__(self):
        self._original_open = builtins.open
        self._active = False

    def install(self, monitor):
        if self._active:
            return
        self._active = True
        original = self._original_open

        def patched_open(file, mode="r", *args, **kwargs):
            m = _get_monitor()
            if m and isinstance(file, str) and not file.startswith("/proc"):
                if "w" in mode or "a" in mode or "x" in mode:
                    action_type = "file_write"
                    # Take snapshot before write for rollback
                    snapshot = None
                    if os.path.exists(file):
                        try:
                            with original(file, "rb") as f:
                                snapshot = f.read()
                        except Exception:
                            snapshot = None
                    decision = m._intercept("file_write", file, {"mode": mode})
                    if decision == "BLOCK":
                        from .exceptions import BehaviorViolationError
                        raise BehaviorViolationError(
                            agent_id=m.agent_id,
                            violation=f"File write blocked by policy: {file}",
                            action_type="file_write"
                        )
                    if snapshot is not None:
                        m._register_file_snapshot(file, snapshot)
                elif "r" in mode:
                    m._intercept("file_read", file, {"mode": mode})
            return original(file, mode, *args, **kwargs)

        builtins.open = patched_open

    def uninstall(self):
        if self._active:
            builtins.open = self._original_open
            self._active = False


class HttpInterceptor:
    """Intercepts urllib HTTP calls."""

    def __init__(self):
        self._original_urlopen = urllib.request.urlopen
        self._active = False

    def install(self, monitor):
        if self._active:
            return
        self._active = True
        original = self._original_urlopen

        def patched_urlopen(url, *args, **kwargs):
            m = _get_monitor()
            if m:
                resource = url if isinstance(url, str) else getattr(url, "full_url", str(url))
                # Skip calls to Vaultak backend itself
                if "vaultak.com" not in resource:
                    decision = m._intercept("api_call", resource, {"method": "HTTP"})
                    if decision == "BLOCK":
                        from .exceptions import BehaviorViolationError
                        raise BehaviorViolationError(
                            agent_id=m.agent_id,
                            violation=f"HTTP call blocked by policy: {resource}",
                            action_type="api_call"
                        )
            return original(url, *args, **kwargs)

        urllib.request.urlopen = patched_urlopen

    def uninstall(self):
        if self._active:
            urllib.request.urlopen = self._original_urlopen
            self._active = False


class SubprocessInterceptor:
    """Intercepts subprocess calls."""

    def __init__(self):
        self._original_run = subprocess.run
        self._original_popen = subprocess.Popen
        self._active = False

    def install(self, monitor):
        if self._active:
            return
        self._active = True
        orig_run = self._original_run
        orig_popen = self._original_popen

        def patched_run(args, *a, **kw):
            m = _get_monitor()
            if m:
                cmd = args[0] if isinstance(args, (list, tuple)) else args
                decision = m._intercept("execute", str(cmd), {"args": str(args)})
                if decision == "BLOCK":
                    from .exceptions import BehaviorViolationError
                    raise BehaviorViolationError(
                        agent_id=m.agent_id,
                        violation=f"Subprocess blocked by policy: {cmd}",
                        action_type="execute"
                    )
            return orig_run(args, *a, **kw)

        def patched_popen(args, *a, **kw):
            m = _get_monitor()
            if m:
                cmd = args[0] if isinstance(args, (list, tuple)) else args
                m._intercept("execute", str(cmd), {"args": str(args)})
            return orig_popen(args, *a, **kw)

        subprocess.run = patched_run
        subprocess.Popen = patched_popen

    def uninstall(self):
        if self._active:
            subprocess.run = self._original_run
            subprocess.Popen = self._original_popen
            self._active = False


# Try to intercept requests library if installed
class RequestsInterceptor:
    def __init__(self):
        self._active = False
        self._original_send = None

    def install(self, monitor):
        try:
            import requests
            from requests import Session
            original_send = Session.send

            def patched_send(self_session, request, **kwargs):
                m = _get_monitor()
                if m and "vaultak.com" not in request.url:
                    decision = m._intercept("api_call", request.url, {"method": request.method})
                    if decision == "BLOCK":
                        from .exceptions import BehaviorViolationError
                        raise BehaviorViolationError(
                            agent_id=m.agent_id,
                            violation=f"HTTP request blocked: {request.url}",
                            action_type="api_call"
                        )
                return original_send(self_session, request, **kwargs)

            Session.send = patched_send
            self._original_send = original_send
            self._Session = Session
            self._active = True
        except ImportError:
            pass

    def uninstall(self):
        if self._active and self._original_send:
            self._Session.send = self._original_send
            self._active = False


# Global interceptor instances
_file_interceptor = FileInterceptor()
_http_interceptor = HttpInterceptor()
_subprocess_interceptor = SubprocessInterceptor()
_requests_interceptor = RequestsInterceptor()


def install_all(monitor):
    _set_monitor(monitor)
    _file_interceptor.install(monitor)
    _http_interceptor.install(monitor)
    _subprocess_interceptor.install(monitor)
    _requests_interceptor.install(monitor)


def uninstall_all():
    _clear_monitor()
    _file_interceptor.uninstall()
    _http_interceptor.uninstall()
    _subprocess_interceptor.uninstall()
    _requests_interceptor.uninstall()
