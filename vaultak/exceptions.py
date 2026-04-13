class AgentBreakerError(Exception):
    pass

class AgentTerminatedError(AgentBreakerError):
    def __init__(self, agent_id: str, reason: str, risk_score: float = 0.0):
        self.agent_id = agent_id
        self.reason = reason
        self.risk_score = risk_score
        super().__init__(f"Agent '{agent_id}' was terminated. Reason: {reason} (risk score: {risk_score:.2f})")

class BehaviorViolationError(AgentBreakerError):
    def __init__(self, agent_id: str, violation: str, action_type: str):
        self.agent_id = agent_id
        self.violation = violation
        self.action_type = action_type
        super().__init__(f"Agent '{agent_id}' behavior violation: {violation} (action: {action_type})")

class AgentPausedError(AgentBreakerError):
    def __init__(self, agent_id: str, reason: str):
        self.agent_id = agent_id
        self.reason = reason
        super().__init__(f"Agent '{agent_id}' is paused and awaiting human approval. Reason: {reason}")

class RollbackError(AgentBreakerError):
    pass
