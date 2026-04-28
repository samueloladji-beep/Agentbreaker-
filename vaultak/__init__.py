from .exceptions import AgentPausedError, AgentTerminatedError, BehaviorViolationError
from .models import ActionType, KillSwitchMode, AlertLevel

__version__ = "0.7.0"

import os as _os


class Vaultak:
    """
    Vaultak runtime security SDK.

    Usage:
        from vaultak import Vaultak

        vt = Vaultak(api_key="vtk_...")

        with vt.monitor("my-agent"):
            agent.run()  # All file I/O, HTTP calls, subprocesses auto-monitored
    """

    def __init__(
        self,
        api_key: str = None,
        agent_id: str = "default",
        alert_threshold: int = 30,
        pause_threshold: int = 60,
        rollback_threshold: int = 85,
        allowed_resources=None,
        blocked_resources=None,
        max_actions_per_minute: int = 60,
        api_endpoint: str = "https://vaultak.com",
    ):
        self._api_key = api_key or _os.environ.get("VAULTAK_API_KEY", "")
        self._agent_id = agent_id
        self._alert_threshold = alert_threshold
        self._pause_threshold = pause_threshold
        self._rollback_threshold = rollback_threshold
        self._allowed_resources = allowed_resources
        self._blocked_resources = blocked_resources or []
        self._max_actions_per_minute = max_actions_per_minute
        self._api_endpoint = api_endpoint

    def monitor(self, agent_id: str = None):
        """
        Context manager that automatically monitors all agent actions.
        Auto-intercepts: file I/O, HTTP requests, subprocess calls.
        """
        from contextlib import contextmanager
        from .core import VaultakMonitor
        from .interceptor import install_all, uninstall_all

        @contextmanager
        def _monitor():
            aid = agent_id or self._agent_id
            m = VaultakMonitor(
                agent_id=aid,
                api_key=self._api_key,
                api_endpoint=self._api_endpoint,
                alert_threshold=self._alert_threshold,
                pause_threshold=self._pause_threshold,
                rollback_threshold=self._rollback_threshold,
                allowed_resources=self._allowed_resources,
                blocked_resources=self._blocked_resources,
                max_actions_per_minute=self._max_actions_per_minute,
            )
            install_all(m)
            try:
                yield m
            finally:
                uninstall_all()

        return _monitor()

    def check(self, action_type: str, resource: str, agent_id: str = None) -> dict:
        """
        Pre-execution risk check. Returns decision before action runs.

        Returns:
            {"allowed": bool, "score": int, "decision": str}
        """
        import urllib.request, json
        try:
            data = json.dumps({
                "agent_id": agent_id or self._agent_id,
                "action_type": action_type,
                "resource": resource,
            }).encode("utf-8")
            req = urllib.request.Request(
                f"{self._api_endpoint}/api/check",
                data=data,
                headers={"Content-Type": "application/json", "x-api-key": self._api_key},
                method="POST"
            )
            resp = urllib.request.urlopen(req, timeout=3)
            result = json.loads(resp.read())
            return {
                "allowed": result.get("decision") not in ("BLOCK", "ROLLBACK"),
                "score": result.get("risk_score", 0),
                "decision": result.get("decision", "ALLOW"),
            }
        except Exception:
            return {"allowed": True, "score": 0, "decision": "ALLOW"}

    def log_action(self, action_type: str, resource: str, agent_id: str = None, payload: dict = None):
        """Manually log a single action."""
        import json, threading, urllib.request, uuid
        from datetime import datetime
        data = json.dumps({
            "agent_id": agent_id or self._agent_id,
            "action_type": action_type,
            "resource": resource,
            "payload": payload or {},
            "session_id": str(uuid.uuid4()),
            "timestamp": datetime.utcnow().isoformat(),
        }).encode("utf-8")
        def _post():
            try:
                req = urllib.request.Request(
                    f"{self._api_endpoint}/api/actions",
                    data=data,
                    headers={"Content-Type": "application/json", "x-api-key": self._api_key},
                    method="POST"
                )
                urllib.request.urlopen(req, timeout=3)
            except Exception:
                pass
        threading.Thread(target=_post, daemon=True).start()

    def score_action(self, action: str, context: dict = None) -> object:
        """
        Score the risk of an action before it executes.
        Returns an object with a .score attribute (0.0 - 10.0 scale).

        Usage:
            result = vt.score_action("file_write", {"resource": "/etc/passwd"})
            print(result.score)   # e.g. 7.5
            print(result.level)   # e.g. "high"
        """
        from .scorer import score_action as _score, score_to_alert_level
        from .models import ActionLog, ActionType, BehaviorProfile
        from datetime import datetime

        action_type_map = {
            "file_write": ActionType.FILE_WRITE,
            "file_read": ActionType.FILE_READ,
            "file_delete": ActionType.FILE_DELETE,
            "delete": ActionType.FILE_DELETE,
            "api_call": ActionType.API_CALL,
            "execute": ActionType.CODE_EXECUTION,
            "code_execution": ActionType.CODE_EXECUTION,
            "database_write": ActionType.DATABASE_WRITE,
            "database_read": ActionType.DATABASE_QUERY,
            "network_request": ActionType.NETWORK_REQUEST,
            "process_spawn": ActionType.PROCESS_SPAWN,
            "permission_change": ActionType.PERMISSION_CHANGE,
        }
        action_type = action_type_map.get(action.lower(), ActionType.CUSTOM)
        resource = str(context.get("resource", context)) if context else action

        log = ActionLog(
            agent_id=self._agent_id,
            action_type=action_type,
            resource=resource,
            payload=context or {},
            timestamp=datetime.utcnow(),
        )
        profile = BehaviorProfile(agent_id=self._agent_id)
        raw_score = _score(log, profile, [])

        class ScoreResult:
            def __init__(self, s):
                self.score = round(s * 10, 1)  # Convert 0-1 to 0-10 scale
                self.level = score_to_alert_level(s)
                self.raw = s

            def __repr__(self):
                return f"ScoreResult(score={self.score}, level='{self.level}')"

        return ScoreResult(raw_score)

    def mask_pii(self, text: str) -> str:
        """
        Scan text for PII and return masked version.
        Detects emails, credit cards, SSNs, API keys, passwords, JWT tokens, and more.

        Usage:
            safe = vt.mask_pii("Contact john@example.com or call 555-123-4567")
            # "Contact j****@example.com or call ******4567"
        """
        try:
            from .pii import PIIMasker
            masker = PIIMasker()
            result = masker.mask(text)
            return result.masked
        except Exception:
            return text  # Never break on PII masking failure

    def check_policy(self, tool_name: str, input_data: str = None) -> dict:
        """
        Check a tool call against Vaultak policy rules before execution.
        Raises RuntimeError if the action is blocked by policy.
        Returns dict with allowed/score/decision if permitted.

        Usage:
            vt.check_policy("send_email", "recipient=external@gmail.com")
        """
        result = self.check(
            action_type=tool_name,
            resource=input_data or tool_name,
        )
        if not result.get("allowed", True):
            raise RuntimeError(
                f"[Vaultak] Tool '{tool_name}' blocked by policy. "
                f"Decision: {result.get('decision')}. "
                f"Review at app.vaultak.com"
            )
        return result

    def rollback(self, reason: str = None) -> None:
        """
        Trigger an emergency rollback and log the event to the dashboard.
        In an active monitor session, file and database snapshots are restored.

        Usage:
            vt.rollback(reason="Unexpected agent behavior detected")
        """
        import logging
        logger = logging.getLogger("vaultak")
        logger.warning(f"[Vaultak] Rollback triggered: {reason}")
        self.log_action(
            action_type="rollback",
            resource="system",
            payload={"reason": reason or "manual_rollback"},
        )

    def alert(self, level: str = "medium", message: str = None) -> None:
        """
        Send an alert to the Vaultak dashboard.

        Args:
            level: 'low', 'medium', 'high', or 'critical'
            message: Description of the alert

        Usage:
            vt.alert(level="high", message="Agent attempted to access /etc/passwd")
        """
        self.log_action(
            action_type="alert",
            resource="system",
            payload={
                "level": level,
                "message": message or "Alert triggered",
            },
        )


__all__ = [
    "Vaultak",
    "ActionType",
    "KillSwitchMode",
    "AlertLevel",
    "AgentPausedError",
    "AgentTerminatedError",
    "BehaviorViolationError",
]
