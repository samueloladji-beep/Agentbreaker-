import json
import logging
import threading
import uuid
from collections import deque
from contextlib import contextmanager
from datetime import datetime
from typing import Any, Callable, Deque, Dict, Generator, List, Optional
import urllib.request

from .exceptions import AgentPausedError, AgentTerminatedError, BehaviorViolationError
from .models import ActionLog, ActionType, AgentConfig, AlertLevel, BehaviorProfile, KillSwitchMode
from .scorer import score_action, score_to_alert_level

logger = logging.getLogger("agentbreaker")

class AgentBreaker:
    def __init__(self, config: AgentConfig):
        self.config = config
        self.profile = BehaviorProfile(agent_id=config.agent_id)
        self._session_id = str(uuid.uuid4())
        self._action_history: Deque[ActionLog] = deque(maxlen=1000)
        self._recent_window: Deque[ActionLog] = deque(maxlen=100)
        self._action_times: Deque[datetime] = deque(maxlen=1000)
        self._paused = False
        self._terminated = False
        self._rollback_callbacks: List[Callable] = []
        self._lock = threading.Lock()
        logger.info(f"AgentBreaker initialized for agent '{config.agent_id}' in {config.kill_switch_mode.value} mode")

    @contextmanager
    def watch(self, action_type: str, resource: str, payload: Optional[Dict[str, Any]] = None, rollback_fn: Optional[Callable] = None) -> Generator:
        self._check_not_terminated()
        self._check_not_paused()
        action = self._build_action(action_type, resource, payload or {})
        if rollback_fn:
            self._rollback_callbacks.append(rollback_fn)
        with self._lock:
            recent = list(self._recent_window)
        action.risk_score = score_action(action, self.profile, recent)
        action.flagged = action.risk_score >= self._alert_threshold()
        if action.flagged:
            action.flag_reason = f"Risk score {action.risk_score:.2f} exceeds threshold {self._alert_threshold():.2f}"
        self._check_allowed_action_type(action)
        self._check_allowed_resource(action)
        self._check_blocked_resource(action)
        self._check_max_risk_score(action)
        self._check_rate_limit()
        try:
            yield action
            with self._lock:
                self.profile.update_from_action(action)
                self._action_history.append(action)
                self._recent_window.append(action)
                self._action_times.append(datetime.utcnow())
            self._send_to_backend(action)
            if action.flagged:
                self._trigger_kill_switch(action)
        except Exception as e:
            action.flag_reason = f"Action raised exception: {str(e)}"
            self._send_to_backend(action)
            raise

    def approve(self):
        self._paused = False
        logger.info(f"Agent '{self.config.agent_id}' approved and resumed.")

    def terminate(self, reason: str = "Manual termination"):
        self._terminated = True
        logger.warning(f"Agent '{self.config.agent_id}' terminated: {reason}")

    def get_audit_trail(self):
        return [a.to_dict() for a in self._action_history]

    def get_profile(self):
        return self.profile.to_dict()

    def _build_action(self, action_type: str, resource: str, payload: Dict) -> ActionLog:
        try:
            atype = ActionType(action_type)
        except ValueError:
            atype = ActionType.CUSTOM
        return ActionLog(agent_id=self.config.agent_id, action_id=str(uuid.uuid4()), session_id=self._session_id, action_type=atype, resource=resource, payload=payload)

    def _alert_threshold(self) -> float:
        thresholds = {AlertLevel.LOW: 0.15, AlertLevel.MEDIUM: 0.35, AlertLevel.HIGH: 0.55, AlertLevel.CRITICAL: 0.75}
        return thresholds.get(self.config.alert_level_threshold, 0.55)

    def _trigger_kill_switch(self, action: ActionLog):
        mode = self.config.kill_switch_mode
        level = score_to_alert_level(action.risk_score)
        logger.warning(f"[KILL SWITCH] Agent '{self.config.agent_id}' | Mode: {mode.value} | Level: {level} | Reason: {action.flag_reason}")
        if mode == KillSwitchMode.PAUSE:
            self._paused = True
            raise AgentPausedError(agent_id=self.config.agent_id, reason=action.flag_reason or "Anomalous behavior detected")
        elif mode == KillSwitchMode.ROLLBACK:
            self._execute_rollback(action)
            self._paused = True
            raise AgentPausedError(agent_id=self.config.agent_id, reason=f"Rolled back {len(self._rollback_callbacks)} actions. {action.flag_reason}")

    def _execute_rollback(self, trigger_action: ActionLog):
        n = self.config.rollback_window
        callbacks = self._rollback_callbacks[-n:]
        for fn in reversed(callbacks):
            try:
                fn()
            except Exception as e:
                logger.error(f"Rollback failed: {e}")
        for action in list(self._action_history)[-n:]:
            action.rolled_back = True

    def _check_not_terminated(self):
        if self._terminated:
            raise AgentTerminatedError(self.config.agent_id, reason="Agent has been permanently terminated")

    def _check_not_paused(self):
        if self._paused:
            raise AgentPausedError(self.config.agent_id, reason="Agent is paused awaiting human approval")

    def _check_allowed_resource(self, action: ActionLog):
        if not self.config.matches_allowed_resource(action.resource):
            raise BehaviorViolationError(agent_id=self.config.agent_id, violation=f"Resource not in allowlist: {action.resource}", action_type=action.action_type.value)

    def _check_blocked_resource(self, action: ActionLog):
        if self.config.matches_blocked_resource(action.resource):
            raise BehaviorViolationError(agent_id=self.config.agent_id, violation=f"Access to blocked resource: {action.resource}", action_type=action.action_type.value)

    def _check_allowed_action_type(self, action: ActionLog):
        if self.config.allowed_action_types is not None:
            if action.action_type not in self.config.allowed_action_types:
                raise BehaviorViolationError(agent_id=self.config.agent_id, violation=f"Action type not in allowlist: {action.action_type.value}", action_type=action.action_type.value)

    def _check_max_risk_score(self, action: ActionLog):
        if action.risk_score > self.config.max_risk_score:
            raise BehaviorViolationError(agent_id=self.config.agent_id, violation=f"Risk score {action.risk_score:.2f} exceeds max allowed {self.config.max_risk_score:.2f}", action_type=action.action_type.value)

    def _check_rate_limit(self):
        now = datetime.utcnow()
        with self._lock:
            recent_times = [t for t in self._action_times if (now - t).total_seconds() < 60]
        if len(recent_times) >= self.config.max_actions_per_minute:
            raise BehaviorViolationError(agent_id=self.config.agent_id, violation=f"Rate limit exceeded: {self.config.max_actions_per_minute} actions/minute", action_type="rate_limit")

    def _send_to_backend(self, action: ActionLog):
        if not self.config.api_endpoint:
            return
        def _post():
            try:
                url = f"{self.config.api_endpoint}/api/actions"
                data = json.dumps(action.to_dict()).encode("utf-8")
                req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json", "X-API-Key": self.config.api_key or ""}, method="POST")
                urllib.request.urlopen(req, timeout=2)
            except Exception as e:
                logger.debug(f"Failed to send to backend: {e}")
        threading.Thread(target=_post, daemon=True).start()
