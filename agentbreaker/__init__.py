from .core import AgentBreaker
from .models import ActionLog, BehaviorProfile, AlertLevel, AgentConfig, KillSwitchMode, ActionType
from .exceptions import AgentTerminatedError, BehaviorViolationError, AgentPausedError

__version__ = "0.5.1"

class Vaultak:
    """
    Vaultak runtime security SDK.

    Usage:
        from vaultak import Vaultak, ActionType, KillSwitchMode

        vt = Vaultak(
            api_key="vtk_your_api_key_here",
            allowed_action_types=[ActionType.FILE_READ, ActionType.API_CALL],
            allowed_resources=["/tmp/*"],
            blocked_resources=["prod.*", "*.env"],
            max_actions_per_minute=20,
            max_risk_score=0.7,
            mode=KillSwitchMode.PAUSE
        )

        with vt.monitor("my-agent"):
            agent.run()
    """

    def __init__(
        self,
        api_key: str,
        agent_id: str = "default",
        mode: KillSwitchMode = KillSwitchMode.ALERT,
        allowed_action_types=None,
        allowed_resources=None,
        blocked_resources=None,
        max_actions_per_minute: int = 60,
        max_risk_score: float = 1.0,
        risk_threshold: float = 0.7,
        rollback_limit: int = 5,
        api_endpoint: str = "https://vaultak.com",
    ):
        from .models import AlertLevel
        self._api_key = api_key
        self._api_endpoint = api_endpoint
        self._default_agent_id = agent_id
        self._mode = mode
        self._allowed_action_types = allowed_action_types
        self._allowed_resources = allowed_resources
        self._blocked_resources = blocked_resources or []
        self._max_actions_per_minute = max_actions_per_minute
        self._max_risk_score = max_risk_score
        self._risk_threshold = risk_threshold
        self._rollback_limit = rollback_limit
        self._breakers = {}

    def _get_breaker(self, agent_id: str) -> AgentBreaker:
        if agent_id not in self._breakers:
            config = AgentConfig(
                agent_id=agent_id,
                name=agent_id,
                kill_switch_mode=self._mode,
                allowed_action_types=self._allowed_action_types,
                allowed_resources=self._allowed_resources,
                blocked_resources=self._blocked_resources,
                max_actions_per_minute=self._max_actions_per_minute,
                max_risk_score=self._max_risk_score,
                rollback_window=self._rollback_limit,
                api_key=self._api_key,
                api_endpoint=self._api_endpoint,
            )
            self._breakers[agent_id] = AgentBreaker(config)
        return self._breakers[agent_id]

    def monitor(self, agent_id: str = None):
        """Context manager that monitors an entire agent session."""
        from contextlib import contextmanager

        @contextmanager
        def _monitor():
            aid = agent_id or self._default_agent_id
            breaker = self._get_breaker(aid)
            yield breaker

        return _monitor()

    def watch(self, agent_id: str, action_type: str, resource: str, payload=None, rollback_fn=None):
        """Context manager that monitors a single agent action."""
        return self._get_breaker(agent_id).watch(action_type, resource, payload, rollback_fn)

    def log_action(self, agent_id: str, action_type: str, resource: str, payload=None):
        """Explicitly log a single agent action."""
        import uuid, json, threading, urllib.request
        data = json.dumps({
            "agent_id": agent_id,
            "action_type": action_type,
            "resource": resource,
            "payload": payload or {},
            "session_id": str(uuid.uuid4()),
        }).encode("utf-8")
        def _post():
            try:
                req = urllib.request.Request(
                    f"{self._api_endpoint}/api/actions",
                    data=data,
                    headers={"Content-Type": "application/json", "X-API-Key": self._api_key},
                    method="POST"
                )
                urllib.request.urlopen(req, timeout=3)
            except Exception:
                pass
        threading.Thread(target=_post, daemon=True).start()

    def approve(self, agent_id: str = None):
        """Resume a paused agent."""
        aid = agent_id or self._default_agent_id
        self._get_breaker(aid).approve()

    def audit_trail(self, agent_id: str = None):
        """Get the full audit trail for an agent."""
        aid = agent_id or self._default_agent_id
        return self._get_breaker(aid).get_audit_trail()


__all__ = [
    "Vaultak",
    "AgentBreaker",
    "AgentConfig",
    "ActionLog",
    "BehaviorProfile",
    "AlertLevel",
    "KillSwitchMode",
    "ActionType",
    "AgentTerminatedError",
    "BehaviorViolationError",
    "AgentPausedError",
]
