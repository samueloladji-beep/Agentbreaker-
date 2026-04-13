from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional
import fnmatch

class AlertLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

class KillSwitchMode(str, Enum):
    ALERT = "alert"
    PAUSE = "pause"
    ROLLBACK = "rollback"

class ActionType(str, Enum):
    FILE_READ = "file_read"
    FILE_WRITE = "file_write"
    FILE_DELETE = "file_delete"
    API_CALL = "api_call"
    DATABASE_QUERY = "database_query"
    DATABASE_WRITE = "database_write"
    CODE_EXECUTION = "code_execution"
    NETWORK_REQUEST = "network_request"
    PERMISSION_CHANGE = "permission_change"
    PROCESS_SPAWN = "process_spawn"
    CUSTOM = "custom"

@dataclass
class ActionLog:
    agent_id: str
    action_type: ActionType
    resource: str
    payload: Dict[str, Any]
    timestamp: datetime = field(default_factory=datetime.utcnow)
    action_id: Optional[str] = None
    session_id: Optional[str] = None
    risk_score: float = 0.0
    flagged: bool = False
    flag_reason: Optional[str] = None
    rolled_back: bool = False

    def to_dict(self):
        return {
            "agent_id": self.agent_id,
            "action_id": self.action_id,
            "session_id": self.session_id,
            "action_type": self.action_type.value,
            "resource": self.resource,
            "payload": self.payload,
            "timestamp": self.timestamp.isoformat(),
            "risk_score": self.risk_score,
            "flagged": self.flagged,
            "flag_reason": self.flag_reason,
            "rolled_back": self.rolled_back,
        }

@dataclass
class BehaviorProfile:
    agent_id: str
    observed_action_types: List[str] = field(default_factory=list)
    observed_resources: List[str] = field(default_factory=list)
    baseline_established: bool = False
    baseline_sample_count: int = 0
    created_at: datetime = field(default_factory=datetime.utcnow)
    updated_at: datetime = field(default_factory=datetime.utcnow)
    MINIMUM_SAMPLES_FOR_BASELINE = 50

    def update_from_action(self, action):
        if action.action_type.value not in self.observed_action_types:
            self.observed_action_types.append(action.action_type.value)
        if action.resource not in self.observed_resources:
            self.observed_resources.append(action.resource)
        self.baseline_sample_count += 1
        if self.baseline_sample_count >= self.MINIMUM_SAMPLES_FOR_BASELINE:
            self.baseline_established = True
        self.updated_at = datetime.utcnow()

    def to_dict(self):
        return {
            "agent_id": self.agent_id,
            "observed_action_types": self.observed_action_types,
            "observed_resources": self.observed_resources,
            "baseline_established": self.baseline_established,
            "baseline_sample_count": self.baseline_sample_count,
        }

@dataclass
class AgentConfig:
    agent_id: str
    name: str
    kill_switch_mode: KillSwitchMode = KillSwitchMode.ALERT
    alert_level_threshold: AlertLevel = AlertLevel.HIGH
    max_actions_per_minute: int = 60
    max_risk_score: float = 1.0
    rollback_window: int = 10
    allowed_action_types: Optional[List[ActionType]] = None
    allowed_resources: Optional[List[str]] = None
    blocked_resources: List[str] = field(default_factory=list)
    api_endpoint: Optional[str] = None
    api_key: Optional[str] = None

    def matches_allowed_resource(self, resource: str) -> bool:
        if self.allowed_resources is None:
            return True
        return any(fnmatch.fnmatch(resource, pattern) for pattern in self.allowed_resources)

    def matches_blocked_resource(self, resource: str) -> bool:
        return any(fnmatch.fnmatch(resource, pattern) for pattern in self.blocked_resources)

    def to_dict(self):
        return {
            "agent_id": self.agent_id,
            "name": self.name,
            "kill_switch_mode": self.kill_switch_mode.value,
            "max_actions_per_minute": self.max_actions_per_minute,
            "max_risk_score": self.max_risk_score,
            "allowed_action_types": [a.value for a in self.allowed_action_types] if self.allowed_action_types else None,
            "allowed_resources": self.allowed_resources,
            "blocked_resources": self.blocked_resources,
        }
