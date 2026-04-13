from typing import List
from .models import ActionLog, ActionType, BehaviorProfile

ACTION_RISK_WEIGHTS = {
    ActionType.FILE_READ: 0.1,
    ActionType.FILE_WRITE: 0.35,
    ActionType.FILE_DELETE: 0.75,
    ActionType.API_CALL: 0.2,
    ActionType.DATABASE_QUERY: 0.15,
    ActionType.DATABASE_WRITE: 0.45,
    ActionType.CODE_EXECUTION: 0.8,
    ActionType.NETWORK_REQUEST: 0.25,
    ActionType.PERMISSION_CHANGE: 0.9,
    ActionType.PROCESS_SPAWN: 0.7,
    ActionType.CUSTOM: 0.3,
}

HIGH_RISK_RESOURCE_PATTERNS = [
    "/etc/", "/root/", "~/.ssh/", "/.env", "/proc/", "/sys/",
    "production", "prod_", "_prod", "credentials", "secrets",
    "password", "api_key", "private_key",
]

SUSPICIOUS_KEYWORDS = [
    "drop table", "delete from", "rm -rf", "chmod 777", "sudo",
    "eval(", "exec(", "__import__", "os.system", "subprocess",
    "base64", "ignore previous", "disregard instructions",
]

def score_action(action: ActionLog, profile: BehaviorProfile, recent_actions: List[ActionLog]) -> float:
    score = 0.0
    base_risk = ACTION_RISK_WEIGHTS.get(action.action_type, 0.3)
    score += base_risk * 0.3
    resource_lower = action.resource.lower()
    resource_risk = 0.0
    for pattern in HIGH_RISK_RESOURCE_PATTERNS:
        if pattern in resource_lower:
            resource_risk = min(resource_risk + 0.2, 1.0)
    score += resource_risk * 0.25
    payload_str = str(action.payload).lower()
    payload_risk = 0.0
    for keyword in SUSPICIOUS_KEYWORDS:
        if keyword in payload_str:
            payload_risk = min(payload_risk + 0.25, 1.0)
    score += payload_risk * 0.25
    if profile.baseline_established:
        if action.action_type.value not in profile.observed_action_types:
            score += 0.15
        if action.resource not in profile.observed_resources:
            score += 0.05
    if len(recent_actions) >= 10:
        velocity_risk = min(len(recent_actions) / 60.0, 1.0)
        score += velocity_risk * 0.05
    return min(score, 1.0)

def score_to_alert_level(score: float) -> str:
    if score >= 0.75:
        return "critical"
    elif score >= 0.5:
        return "high"
    elif score >= 0.25:
        return "medium"
    return "low"
