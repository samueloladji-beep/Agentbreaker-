"""
Vaultak Sentry v0.2.0
Zero-code runtime security daemon for AI agents.

Key design principles:
- Policy-first: what is not explicitly authorized is unauthorized
- Agent-focused: filters out known safe system activity
- Configurable monitors: users choose what to enable
- No data exfiltration: Sentry never reads file contents or env values
"""

import os
import sys
import re
import time
import json
import fnmatch
import signal
import hashlib
import logging
import platform
import argparse
import threading
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, List, Dict, Set

try:
    import psutil
    HAS_PSUTIL = True
except ImportError:
    HAS_PSUTIL = False

try:
    from watchdog.observers import Observer
    from watchdog.events import FileSystemEventHandler
    HAS_WATCHDOG = True
except ImportError:
    HAS_WATCHDOG = False

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

VERSION      = "0.2.0"
API_BASE     = os.environ.get("VAULTAK_API_URL", "https://vaultak.com")
CONFIG_DIR   = Path.home() / ".vaultak"
CONFIG_FILE  = CONFIG_DIR / "config.json"
POLICY_DIR   = CONFIG_DIR / "policies"
LOG_FILE     = CONFIG_DIR / "sentry.log"

MODE_ALERT    = "alert"
MODE_PAUSE    = "pause"
MODE_ROLLBACK = "rollback"

# ── ANSI colors ───────────────────────────────────────────────────────────────
R="\033[91m"; Y="\033[93m"; G="\033[92m"; C="\033[96m"
P="\033[95m"; W="\033[97m"; D="\033[2m"; BD="\033[1m"; RS="\033[0m"

# ── Base risk weights per action type ─────────────────────────────────────────
RISK_WEIGHTS = {
    "permission_change": 0.90,
    "file_delete":       0.80,
    "code_execution":    0.75,
    "process_spawn":     0.70,
    "database_write":    0.65,
    "env_access":        0.60,
    "file_write":        0.50,
    "network_request":   0.45,
    "database_query":    0.30,
    "file_read":         0.20,
    "cpu_spike":         0.35,
    "memory_spike":      0.40,
}

# ── Safe system paths to ignore (not agent activity) ─────────────────────────
SAFE_PATH_PREFIXES = [
    # Python internals
    "/usr/lib/python", "/usr/local/lib/python",
    "/usr/share/python", "site-packages", "__pycache__",
    ".pyc", ".pyo",
    # Virtual environments
    "/venv/", "/.venv/", "/env/", "/.env/lib/",
    # System paths
    "/proc/self", "/dev/null", "/dev/urandom",
    "/usr/share/", "/usr/lib/", "/usr/bin/",
    # Package managers
    "pip", "setuptools", "wheel",
]

# ── Known safe external hosts (not agent drift) ───────────────────────────────
SAFE_HOSTS = {
    "api.openai.com", "api.anthropic.com",
    "huggingface.co", "api.cohere.ai",
    "generativelanguage.googleapis.com",
    "pypi.org", "files.pythonhosted.org",
    "github.com", "raw.githubusercontent.com",
}

# ── Known dangerous ports ─────────────────────────────────────────────────────
DANGEROUS_PORTS  = {22, 25, 465, 587}
SUSPICIOUS_PORTS = {4444, 1337, 31337, 9999}
DB_PORTS         = {3306, 5432, 27017, 6379, 1433, 5984}

CONFIG_DIR.mkdir(exist_ok=True)
POLICY_DIR.mkdir(exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler(LOG_FILE),
    ]
)
logger = logging.getLogger("vaultak-sentry")


# ══════════════════════════════════════════════════════════════════════════════
# POLICY COMPILER
# The heart of Vaultak Sentry. Defines what an agent is authorized to do.
# Anything outside the policy is unauthorized by default.
# ══════════════════════════════════════════════════════════════════════════════

class PolicyCompiler:
    """
    Compiles a human-readable agent policy into an enforcement ruleset.

    A policy answers: what is this agent authorized to do?
    Everything not in the policy is unauthorized.

    Policy fields:
      agent_id        : identifier for this agent
      allowed_paths   : glob patterns the agent may read/write
      blocked_paths   : glob patterns the agent must never touch
      allowed_hosts   : hostnames/IPs the agent may connect to
      blocked_hosts   : hostnames/IPs the agent must never connect to
      allowed_actions : list of permitted action types
      blocked_actions : list of forbidden action types
      allowed_ports   : ports the agent may connect to
      max_risk_score  : hard ceiling on risk score before violation
      allow_spawning  : whether agent may spawn child processes
      allow_env_access: whether agent may access environment variables
    """

    def __init__(self, policy_dict: dict):
        self.raw            = policy_dict
        self.agent_id       = policy_dict.get("agent_id", "unnamed-agent")
        self.allowed_paths  = policy_dict.get("allowed_paths",  [])
        self.blocked_paths  = policy_dict.get("blocked_paths",  [])
        self.allowed_hosts  = policy_dict.get("allowed_hosts",  [])
        self.blocked_hosts  = policy_dict.get("blocked_hosts",  [])
        self.allowed_actions= policy_dict.get("allowed_actions", [])
        self.blocked_actions= policy_dict.get("blocked_actions", [])
        self.allowed_ports  = set(policy_dict.get("allowed_ports", []))
        self.max_risk       = policy_dict.get("max_risk_score", 0.85)
        self.allow_spawning = policy_dict.get("allow_spawning",  True)
        self.allow_env      = policy_dict.get("allow_env_access", True)
        self._compile()

    def _compile(self):
        """Pre-compile patterns for fast matching."""
        self._allowed_path_res  = [self._to_pattern(p) for p in self.allowed_paths]
        self._blocked_path_res  = [self._to_pattern(p) for p in self.blocked_paths]
        self._allowed_host_res  = [self._to_pattern(h) for h in self.allowed_hosts]
        self._blocked_host_res  = [self._to_pattern(h) for h in self.blocked_hosts]

    def _to_pattern(self, pattern: str) -> str:
        """Convert glob pattern to regex-compatible form."""
        return pattern.replace("**", "DOUBLESTAR").replace("*", "[^/]*") \
                      .replace("DOUBLESTAR", ".*")

    def _matches(self, value: str, patterns: list) -> bool:
        value = value.lower()
        for p in patterns:
            if re.search(p, value, re.IGNORECASE):
                return True
        return False

    def evaluate(self, action_type: str, resource: str,
                 risk_score: float) -> tuple:
        """
        Evaluate an action against the policy.
        Returns (decision, reason) where decision is:
          'allow'  : explicitly authorized
          'flag'   : not in policy but below risk threshold
          'block'  : explicitly blocked or above risk threshold
        """

        # 1. Blocked actions take priority
        if action_type in self.blocked_actions:
            return "block", f"Action type '{action_type}' is blocked by policy"

        # 2. No-spawn policy
        if action_type == "process_spawn" and not self.allow_spawning:
            return "block", "Agent is not authorized to spawn child processes"

        # 3. No-env policy
        if action_type == "env_access" and not self.allow_env:
            return "block", "Agent is not authorized to access environment variables"

        # 4. Blocked path patterns
        if action_type in ("file_read", "file_write", "file_delete"):
            if self._matches(resource, self._blocked_path_res):
                return "block", f"Resource '{resource}' matches a blocked path pattern"

        # 5. Blocked host patterns
        if action_type == "network_request":
            host = resource.split(":")[0]
            if self._matches(host, self._blocked_host_res):
                return "block", f"Host '{host}' is blocked by policy"

        # 6. Risk ceiling
        if risk_score >= self.max_risk:
            return "block", f"Risk score {risk_score:.2f} exceeds ceiling {self.max_risk}"

        # 7. Explicit authorization checks
        if action_type in ("file_read", "file_write", "file_delete"):
            if self._allowed_path_res:
                if not self._matches(resource, self._allowed_path_res):
                    return "flag", f"Resource '{resource}' is outside authorized paths"
                return "allow", "Resource is within authorized paths"

        if action_type == "network_request":
            host = resource.split(":")[0]
            if self._allowed_host_res:
                if not self._matches(host, self._allowed_host_res):
                    return "flag", f"Host '{host}' is not in authorized host list"
                return "allow", "Host is authorized"

        if self.allowed_actions:
            if action_type not in self.allowed_actions:
                return "flag", f"Action '{action_type}' is not in authorized action list"

        return "allow", "Action is within policy"

    def summary(self) -> str:
        lines = [
            f"\n  {P}{BD}Policy: {self.agent_id}{RS}",
            f"  {D}{'─'*50}{RS}",
        ]
        if self.allowed_paths:
            lines.append(f"  {G}Authorized paths:{RS}")
            for p in self.allowed_paths:
                lines.append(f"    {G}✓{RS}  {p}")
        if self.blocked_paths:
            lines.append(f"  {R}Blocked paths:{RS}")
            for p in self.blocked_paths:
                lines.append(f"    {R}✗{RS}  {p}")
        if self.allowed_hosts:
            lines.append(f"  {G}Authorized hosts:{RS}")
            for h in self.allowed_hosts:
                lines.append(f"    {G}✓{RS}  {h}")
        if self.blocked_hosts:
            lines.append(f"  {R}Blocked hosts:{RS}")
            for h in self.blocked_hosts:
                lines.append(f"    {R}✗{RS}  {h}")
        if self.allowed_actions:
            lines.append(f"  {G}Authorized actions:{RS}  "
                         f"{', '.join(self.allowed_actions)}")
        if self.blocked_actions:
            lines.append(f"  {R}Blocked actions:{RS}    "
                         f"{', '.join(self.blocked_actions)}")
        lines.append(f"  {D}Max risk score:{RS}      {Y}{self.max_risk}{RS}")
        lines.append(f"  {D}Allow spawning:{RS}      "
                     f"{G if self.allow_spawning else R}"
                     f"{'yes' if self.allow_spawning else 'no'}{RS}")
        lines.append(f"  {D}Allow env access:{RS}    "
                     f"{G if self.allow_env else R}"
                     f"{'yes' if self.allow_env else 'no'}{RS}")
        return "\n".join(lines)

    def save(self, path: Path = None):
        if path is None:
            path = POLICY_DIR / f"{self.agent_id}.json"
        path.write_text(json.dumps(self.raw, indent=2))
        return path

    @classmethod
    def load(cls, path: Path) -> "PolicyCompiler":
        return cls(json.loads(path.read_text()))

    @classmethod
    def from_agent_id(cls, agent_id: str) -> Optional["PolicyCompiler"]:
        path = POLICY_DIR / f"{agent_id}.json"
        if path.exists():
            return cls.load(path)
        return None


# ══════════════════════════════════════════════════════════════════════════════
# POLICY TEMPLATES
# Pre-built policies for common agent types
# ══════════════════════════════════════════════════════════════════════════════

POLICY_TEMPLATES = {
    "data-pipeline": {
        "description": "Read-only data processing agent",
        "allowed_paths":   ["/data/readonly/**", "/tmp/output/**"],
        "blocked_paths":   ["*.env", "*.key", "*.pem", "/etc/**", "prod.*"],
        "allowed_actions": ["file_read", "file_write", "database_query", "api_call"],
        "blocked_actions": ["file_delete", "permission_change", "code_execution"],
        "allow_spawning":  False,
        "allow_env_access": False,
        "max_risk_score":  0.65,
    },
    "coding-agent": {
        "description": "Software engineering agent with code execution",
        "allowed_paths":   ["/workspace/**", "/tmp/**"],
        "blocked_paths":   ["*.env", "*.key", "/etc/**", "prod.*", "*.pem"],
        "allowed_actions": ["file_read", "file_write", "file_delete",
                           "code_execution", "process_spawn", "api_call"],
        "blocked_actions": ["permission_change"],
        "allow_spawning":  True,
        "allow_env_access": False,
        "max_risk_score":  0.75,
    },
    "customer-support": {
        "description": "Customer support agent with CRM access",
        "allowed_paths":   ["/data/customers/**"],
        "blocked_paths":   ["*.env", "*.key", "/etc/**", "prod.*"],
        "allowed_hosts":   ["api.openai.com", "api.anthropic.com",
                            "crm.internal", "api.internal"],
        "blocked_hosts":   ["*"],
        "allowed_actions": ["file_read", "api_call", "database_query"],
        "blocked_actions": ["file_write", "file_delete", "code_execution",
                           "process_spawn", "permission_change"],
        "allow_spawning":  False,
        "allow_env_access": False,
        "max_risk_score":  0.60,
    },
    "research-agent": {
        "description": "Web research agent with broad read access",
        "allowed_paths":   ["/tmp/**", "/research/**"],
        "blocked_paths":   ["*.env", "*.key", "prod.*", "/etc/**"],
        "allowed_hosts":   ["*"],
        "blocked_hosts":   ["169.254.*", "10.*", "192.168.*", "172.16.*"],
        "allowed_actions": ["file_read", "file_write", "network_request",
                           "api_call", "database_query"],
        "blocked_actions": ["file_delete", "code_execution",
                           "permission_change", "database_write"],
        "allow_spawning":  False,
        "allow_env_access": False,
        "max_risk_score":  0.70,
    },
    "hipaa-agent": {
        "description": "HIPAA-compliant healthcare agent",
        "allowed_paths":   ["/data/deidentified/**", "/reports/readonly/**"],
        "blocked_paths":   ["*.env", "*.key", "/data/phi/**",
                            "patients.identified.*", "prod.*"],
        "allowed_hosts":   ["api.internal", "ehr.internal"],
        "blocked_hosts":   ["*"],
        "allowed_actions": ["file_read", "database_query"],
        "blocked_actions": ["file_write", "file_delete", "code_execution",
                           "process_spawn", "permission_change",
                           "database_write", "network_request"],
        "allow_spawning":  False,
        "allow_env_access": False,
        "max_risk_score":  0.50,
    },
    "strict": {
        "description": "Maximum restriction policy",
        "allowed_paths":   ["/tmp/**"],
        "blocked_paths":   ["*.env", "*.key", "*.pem", "prod.*",
                            "/etc/**", "/root/**", "/home/**"],
        "allowed_hosts":   [],
        "blocked_hosts":   ["*"],
        "allowed_actions": ["file_read", "database_query"],
        "blocked_actions": ["file_delete", "code_execution", "process_spawn",
                           "permission_change", "database_write",
                           "network_request", "env_access"],
        "allow_spawning":  False,
        "allow_env_access": False,
        "max_risk_score":  0.50,
    },
}


# ══════════════════════════════════════════════════════════════════════════════
# System noise filter
# Filters out known safe system activity so we only see agent activity
# ══════════════════════════════════════════════════════════════════════════════

class NoiseFilter:
    def __init__(self, python_prefix: str = None):
        self.safe_prefixes = list(SAFE_PATH_PREFIXES)
        if python_prefix:
            self.safe_prefixes.append(python_prefix)
        # Add current Python executable path
        self.safe_prefixes.append(os.path.dirname(sys.executable))

    def is_system_noise(self, action_type: str, resource: str) -> bool:
        """Returns True if this event is known safe system activity."""
        resource_lower = resource.lower()

        # File events from Python internals are noise
        if action_type in ("file_read", "file_write"):
            for prefix in self.safe_prefixes:
                if prefix.lower() in resource_lower:
                    return True
            # Compiled Python files are noise
            if resource_lower.endswith((".pyc", ".pyo", ".pyd")):
                return True

        # Network events to known safe AI API hosts
        if action_type == "network_request":
            host = resource.split(":")[0].lower()
            if host in SAFE_HOSTS:
                return True
            # Loopback is not agent drift
            if host in ("127.0.0.1", "::1", "localhost"):
                return True

        return False


# ══════════════════════════════════════════════════════════════════════════════
# API client
# ══════════════════════════════════════════════════════════════════════════════

class VaultakAPI:
    def __init__(self, api_key: str, agent_id: str):
        self.api_key    = api_key
        self.agent_id   = agent_id
        self.headers    = {"x-api-key": api_key,
                           "Content-Type": "application/json"}
        self.session_id = hashlib.sha256(
            f"{agent_id}{datetime.now().isoformat()}".encode()
        ).hexdigest()[:16]

    def _post(self, path: str, data: dict):
        if not HAS_REQUESTS:
            return
        try:
            requests.post(f"{API_BASE}{path}", headers=self.headers,
                          json=data, timeout=2)
        except Exception:
            pass

    def check(self, action_type: str, resource: str,
              metadata: dict = None) -> dict:
        if not HAS_REQUESTS:
            return {"decision": "allow"}
        try:
            r = requests.post(
                f"{API_BASE}/api/check",
                headers=self.headers,
                json={"agent_id": self.agent_id, "action_type": action_type,
                      "resource": resource, "metadata": metadata or {},
                      "source": "sentry", "session_id": self.session_id},
                timeout=2,
            )
            return r.json() if r.status_code == 200 else {"decision": "allow"}
        except Exception:
            return {"decision": "allow"}

    def log_action(self, action_type: str, resource: str,
                   risk_score: float, decision: str,
                   reason: str = "", metadata: dict = None):
        self._post("/api/actions", {
            "agent_id":    self.agent_id,
            "action_type": action_type,
            "resource":    resource,
            "risk_score":  risk_score,
            "decision":    decision,
            "reason":      reason,
            "metadata":    metadata or {},
            "source":      "sentry",
            "session_id":  self.session_id,
            "timestamp":   datetime.now(timezone.utc).isoformat(),
        })

    def send_alert(self, message: str, severity: str = "high"):
        self._post("/api/alerts", {
            "agent_id":  self.agent_id,
            "message":   message,
            "severity":  severity,
            "source":    "sentry",
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })


# ══════════════════════════════════════════════════════════════════════════════
# Risk scorer
# ══════════════════════════════════════════════════════════════════════════════

def score_resource(resource: str) -> float:
    r = resource.lower()
    sensitive_indicators = [
        ".env", ".key", ".pem", ".p12", ".pfx", ".cert",
        "id_rsa", "passwd", "shadow", "secret", "credential",
        "token", "password", "api_key", "prod", "/etc/",
        "/root/", "production",
    ]
    for indicator in sensitive_indicators:
        if indicator in r:
            return 0.9
    if any(p in r for p in ["/tmp/", "/var/tmp/"]):
        return 0.1
    return 0.3

def compute_risk(action_type: str, resource: str) -> float:
    base  = RISK_WEIGHTS.get(action_type, 0.4)
    res   = score_resource(resource)
    score = min(1.0, (base * 0.7) + (res * 0.3))
    return round(score, 3)


# ══════════════════════════════════════════════════════════════════════════════
# Rollback manager
# ══════════════════════════════════════════════════════════════════════════════

class RollbackManager:
    def __init__(self, limit: int = 10):
        self.limit   = limit
        self.history = []
        self._lock   = threading.Lock()

    def record(self, action_type: str, resource: str, metadata: dict):
        with self._lock:
            self.history.append({
                "action_type": action_type, "resource": resource,
                "metadata": metadata,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "reversed": False,
            })
            if len(self.history) > self.limit:
                self.history.pop(0)

    def rollback(self) -> list:
        reversed_actions = []
        with self._lock:
            for entry in reversed(self.history):
                if entry["reversed"]:
                    continue
                success = self._attempt_reverse(entry)
                entry["reversed"] = True
                reversed_actions.append({**entry, "rollback_success": success})
        return reversed_actions

    def _attempt_reverse(self, entry: dict) -> bool:
        action   = entry["action_type"]
        resource = entry["resource"]
        try:
            backup = f"{resource}.vaultak_backup"
            if action == "file_write" and os.path.exists(backup):
                os.replace(backup, resource)
                return True
            if action == "file_delete" and os.path.exists(backup):
                os.replace(backup, resource)
                return True
        except Exception:
            pass
        return False


# ══════════════════════════════════════════════════════════════════════════════
# File system monitor
# ══════════════════════════════════════════════════════════════════════════════

class SentryFSHandler(FileSystemEventHandler):
    def __init__(self, sentry: "VaultakSentry"):
        self.sentry = sentry

    def _handle(self, event, action_type: str):
        if event.is_directory:
            return
        self.sentry.handle_event(action_type, event.src_path, {})

    def on_modified(self, event): self._handle(event, "file_write")
    def on_created(self, event):  self._handle(event, "file_write")
    def on_deleted(self, event):  self._handle(event, "file_delete")


# ══════════════════════════════════════════════════════════════════════════════
# Network monitor
# ══════════════════════════════════════════════════════════════════════════════

class NetworkMonitor:
    def __init__(self, sentry: "VaultakSentry", pid: int):
        self.sentry  = sentry
        self.pid     = pid
        self.seen: Set[tuple] = set()
        self.running = False

    def start(self):
        self.running = True
        threading.Thread(target=self._run, daemon=True).start()

    def stop(self): self.running = False

    def _run(self):
        while self.running:
            try:
                if HAS_PSUTIL:
                    proc = psutil.Process(self.pid)
                    for conn in proc.net_connections(kind="all"):
                        if not conn.raddr or not conn.raddr.ip:
                            continue
                        key = (conn.raddr.ip, conn.raddr.port)
                        if key in self.seen:
                            continue
                        self.seen.add(key)
                        ip, port = key
                        resource = f"{ip}:{port}"
                        metadata = {"ip": ip, "port": port,
                                    "status": conn.status}
                        if port in DB_PORTS:
                            action = "database_query"
                        else:
                            action = "network_request"
                        if port in DANGEROUS_PORTS:
                            metadata["warning"] = "dangerous_port"
                        if port in SUSPICIOUS_PORTS:
                            metadata["warning"] = "suspicious_port"
                        self.sentry.handle_event(action, resource, metadata)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                break
            except Exception:
                pass
            time.sleep(1.0)


# ══════════════════════════════════════════════════════════════════════════════
# Process monitor (optional, user can disable)
# ══════════════════════════════════════════════════════════════════════════════

class ProcessMonitor:
    def __init__(self, sentry: "VaultakSentry", pid: int,
                 monitor_env: bool = False):
        self.sentry      = sentry
        self.pid         = pid
        self.monitor_env = monitor_env
        self.seen: Set[int] = set()
        self.running     = False
        self._cpu_samples = []

    def start(self):
        self.running = True
        threading.Thread(target=self._run, daemon=True).start()

    def stop(self): self.running = False

    def _run(self):
        while self.running:
            try:
                if HAS_PSUTIL:
                    proc = psutil.Process(self.pid)

                    # Child process spawning
                    for child in proc.children(recursive=True):
                        if child.pid in self.seen:
                            continue
                        self.seen.add(child.pid)
                        try:
                            cmd = " ".join(child.cmdline())
                        except Exception:
                            cmd = str(child.pid)
                        self.sentry.handle_event("process_spawn", cmd,
                            {"child_pid": child.pid})

                    # CPU spike detection
                    cpu = proc.cpu_percent(interval=None)
                    self._cpu_samples.append(cpu)
                    if len(self._cpu_samples) > 10:
                        self._cpu_samples.pop(0)
                    avg = sum(self._cpu_samples) / len(self._cpu_samples)
                    if avg > 90:
                        self.sentry.handle_event("cpu_spike",
                            f"cpu:{avg:.1f}%", {"cpu_percent": avg})

                    # Memory spike detection
                    mem_mb = proc.memory_info().rss / 1024 / 1024
                    if mem_mb > 2048:
                        self.sentry.handle_event("memory_spike",
                            f"memory:{mem_mb:.0f}mb", {"rss_mb": mem_mb})

                    # Env access (only if user explicitly enables it)
                    if self.monitor_env and platform.system() == "Linux":
                        env_path = f"/proc/{self.pid}/environ"
                        if os.path.exists(env_path):
                            mtime = os.path.getmtime(env_path)
                            key_str = f"env:{mtime}"
                            if key_str not in self.seen:
                                self.seen.add(key_str)
                                self.sentry.handle_event("env_access",
                                    env_path, {})

            except (psutil.NoSuchProcess, psutil.AccessDenied):
                break
            except Exception:
                pass
            time.sleep(0.5)


# ══════════════════════════════════════════════════════════════════════════════
# VAULTAK SENTRY — main class
# ══════════════════════════════════════════════════════════════════════════════

class VaultakSentry:
    def __init__(
        self,
        api_key:       str,
        agent_id:      str,
        policy:        PolicyCompiler,
        mode:          str   = MODE_ALERT,
        watch_paths:   list  = None,
        verbose:       bool  = False,
        monitor_env:   bool  = False,
        monitor_procs: bool  = True,
        monitor_net:   bool  = True,
        monitor_fs:    bool  = True,
    ):
        self.api_key       = api_key
        self.agent_id      = agent_id
        self.policy        = policy
        self.mode          = mode
        self.watch_paths   = watch_paths or [str(Path.home()), "/tmp"]
        self.verbose       = verbose
        self.monitor_env   = monitor_env
        self.monitor_procs = monitor_procs
        self.monitor_net   = monitor_net
        self.monitor_fs    = monitor_fs
        self.pid           = None
        self.process       = None
        self.api           = VaultakAPI(api_key, agent_id)
        self.rollback_mgr  = RollbackManager()
        self.noise_filter  = NoiseFilter()
        self._violation    = threading.Event()
        self._lock         = threading.Lock()
        self.stats         = {
            "total": 0, "allowed": 0, "flagged": 0,
            "blocked": 0, "noise_filtered": 0,
        }
        self._print_banner()
        print(self.policy.summary())
        print()

    def _print_banner(self):
        print(f"\n{P}{BD}{'─'*58}{RS}")
        print(f"{P}{BD}  ◆  VAULTAK SENTRY  v{VERSION}  |  Zero-code AI Governance{RS}")
        print(f"{P}{BD}{'─'*58}{RS}")
        print(f"  {D}agent       {RS}{W}{self.agent_id}{RS}")
        print(f"  {D}mode        {RS}{C}{self.mode.upper()}{RS}")
        print(f"  {D}platform    {RS}{W}{platform.system()}{RS}")
        print(f"  {D}monitors    {RS}", end="")
        active = []
        if self.monitor_fs:    active.append("filesystem")
        if self.monitor_net:   active.append("network")
        if self.monitor_procs: active.append("processes")
        if self.monitor_env:   active.append("env")
        print(f"{G}{', '.join(active)}{RS}")
        print(f"  {D}dashboard   {RS}{C}app.vaultak.com{RS}")

    def handle_event(self, action_type: str, resource: str,
                     metadata: dict = None):
        # Filter system noise first
        if self.noise_filter.is_system_noise(action_type, resource):
            with self._lock:
                self.stats["noise_filtered"] += 1
            return

        with self._lock:
            self.stats["total"] += 1

        risk = compute_risk(action_type, resource)

        # Evaluate against policy
        decision, reason = self.policy.evaluate(action_type, resource, risk)

        # Update stats
        with self._lock:
            if decision == "allow":
                self.stats["allowed"] += 1
            elif decision == "flag":
                self.stats["flagged"] += 1
            else:
                self.stats["blocked"] += 1

        # Print event
        self._print_event(action_type, resource, risk, decision, reason)

        # Record for rollback if allowed
        if decision == "allow":
            self.rollback_mgr.record(action_type, resource, metadata or {})

        # Log to backend asynchronously
        threading.Thread(
            target=self.api.log_action,
            args=(action_type, resource, risk, decision, reason, metadata),
            daemon=True,
        ).start()

        # Handle violation
        if decision == "block":
            self._handle_violation(action_type, resource, risk, reason)

    def _print_event(self, action_type: str, resource: str,
                     risk: float, decision: str, reason: str):
        if not self.verbose and decision == "allow":
            return
        bar_len = int(risk * 20)
        bc = G if risk < 0.4 else Y if risk < 0.7 else R
        bar = f"{bc}{'█'*bar_len}{'░'*(20-bar_len)}{RS}"
        dec_str = (f"{G}ALLOW{RS}" if decision == "allow"
                   else f"{Y}FLAG{RS}"  if decision == "flag"
                   else f"{R}BLOCK{RS}")
        res_display = resource[:48] + ".." if len(resource) > 50 else resource
        print(f"\n  {D}{action_type:<22}{RS}{W}{res_display}{RS}")
        print(f"  {bar} {bc}{risk:.2f}{RS}  {dec_str}")
        if decision != "allow":
            print(f"  {D}reason: {RS}{reason}")

    def _handle_violation(self, action_type: str, resource: str,
                           risk: float, reason: str):
        print(f"\n  {R}{BD}{'─'*54}{RS}")
        print(f"  {R}{BD}  VIOLATION  |  {action_type.upper()}{RS}")
        print(f"  {R}{BD}{'─'*54}{RS}")
        print(f"  {D}resource  {RS}{R}{resource}{RS}")
        print(f"  {D}risk      {RS}{R}{risk:.2f}{RS}")
        print(f"  {D}reason    {RS}{reason}")
        print(f"  {D}mode      {RS}{P}{self.mode.upper()}{RS}\n")

        threading.Thread(
            target=self.api.send_alert,
            args=(f"Violation: {action_type} on {resource} | {reason}", "critical"),
            daemon=True,
        ).start()

        if self.mode == MODE_PAUSE:
            self._pause_agent()
        elif self.mode == MODE_ROLLBACK:
            self._do_rollback()
            self._pause_agent()

    def _pause_agent(self):
        print(f"  {Y}Pausing agent...{RS}")
        if self.process and self.process.poll() is None:
            try:
                if platform.system() != "Windows":
                    self.process.send_signal(signal.SIGSTOP)
                    print(f"  {G}Agent paused. Resume: "
                          f"kill -CONT {self.process.pid}{RS}")
                else:
                    self.process.terminate()
                    print(f"  {G}Agent terminated.{RS}")
            except Exception:
                pass
        self._violation.set()

    def _do_rollback(self):
        print(f"  {Y}Rolling back recent actions...{RS}")
        actions = self.rollback_mgr.rollback()
        for i, a in enumerate(actions, 1):
            status = f"{G}reversed{RS}" if a.get("rollback_success") else f"{Y}logged{RS}"
            print(f"  {Y}↩{RS}  [{i}/{len(actions)}]  "
                  f"{a['action_type']}  {a['resource'][:40]}  {status}")
        print(f"\n  {G}Rollback complete.{RS}\n")

    def _start_monitors(self) -> list:
        monitors = []

        if self.monitor_fs and HAS_WATCHDOG:
            observer = Observer()
            handler  = SentryFSHandler(self)
            for path in self.watch_paths:
                if os.path.exists(path):
                    observer.schedule(handler, path, recursive=True)
            observer.start()
            monitors.append(observer)

        if self.monitor_net and HAS_PSUTIL and self.pid:
            net = NetworkMonitor(self, self.pid)
            net.start()
            monitors.append(net)

        if self.monitor_procs and HAS_PSUTIL and self.pid:
            proc = ProcessMonitor(self, self.pid, self.monitor_env)
            proc.start()
            monitors.append(proc)

        return monitors

    def _stop_monitors(self, monitors: list):
        for mon in monitors:
            if hasattr(mon, "stop"):
                mon.stop()
            if hasattr(mon, "join"):
                try: mon.join(timeout=2)
                except Exception: pass

    def run(self, cmd: list):
        print(f"  {G}Starting:{RS}  {' '.join(cmd)}\n")
        self.process = subprocess.Popen(cmd, stdout=sys.stdout,
                                        stderr=sys.stderr)
        self.pid = self.process.pid
        print(f"  {D}PID: {self.pid}{RS}\n")
        monitors = self._start_monitors()
        try:
            while self.process.poll() is None:
                if self._violation.is_set():
                    break
                time.sleep(0.1)
        except KeyboardInterrupt:
            print(f"\n  {Y}Interrupted.{RS}")
            self.process.terminate()
        self._stop_monitors(monitors)
        self._print_summary()

    def attach(self, pid: int):
        print(f"  {G}Attaching to PID {pid}...{RS}\n")
        self.pid = pid
        if HAS_PSUTIL:
            try:
                psutil.Process(pid)
            except psutil.NoSuchProcess:
                print(f"  {R}Process {pid} not found.{RS}")
                return
        monitors = self._start_monitors()
        print(f"  {G}Monitoring PID {pid}. Ctrl+C to stop.{RS}\n")
        try:
            while True:
                if HAS_PSUTIL:
                    try: psutil.Process(pid)
                    except psutil.NoSuchProcess:
                        print(f"\n  {Y}Process {pid} has exited.{RS}")
                        break
                time.sleep(1)
        except KeyboardInterrupt:
            print(f"\n  {Y}Detached.{RS}")
        self._stop_monitors(monitors)
        self._print_summary()

    def _print_summary(self):
        s = self.stats
        print(f"\n  {P}{BD}{'─'*54}{RS}")
        print(f"  {BD}{W}Session Summary{RS}\n")
        for label, val, color in [
            ("Total events",     s["total"],          W),
            ("Allowed",          s["allowed"],         G),
            ("Flagged",          s["flagged"],          Y),
            ("Blocked",          s["blocked"],          R),
            ("Noise filtered",   s["noise_filtered"],   D),
        ]:
            print(f"  {D}{label:<22}{RS}{color}{BD}{val}{RS}")
        print(f"\n  {D}Full audit trail:{RS}  {C}app.vaultak.com{RS}")
        print(f"  {P}{BD}{'─'*54}{RS}\n")


# ══════════════════════════════════════════════════════════════════════════════
# Config and helpers
# ══════════════════════════════════════════════════════════════════════════════

def load_config() -> dict:
    if CONFIG_FILE.exists():
        try: return json.loads(CONFIG_FILE.read_text())
        except Exception: pass
    return {}

def save_config(cfg: dict):
    CONFIG_FILE.write_text(json.dumps(cfg, indent=2))

def get_api_key() -> Optional[str]:
    return load_config().get("api_key") or os.environ.get("VAULTAK_API_KEY")

def build_sentry_from_args(args, agent_id: str) -> VaultakSentry:
    api_key = get_api_key()
    if not api_key:
        print(f"{R}No API key. Run: vaultak-sentry auth --api-key vtk_...{RS}")
        sys.exit(1)

    # Load or build policy
    policy_data = {}
    if hasattr(args, "policy") and args.policy:
        if args.policy in POLICY_TEMPLATES:
            policy_data = {**POLICY_TEMPLATES[args.policy], "agent_id": agent_id}
            print(f"  {G}Using template policy:{RS} {args.policy}")
        else:
            p = Path(args.policy)
            if p.exists():
                policy_data = json.loads(p.read_text())
            else:
                print(f"{R}Policy file not found: {args.policy}{RS}")
                sys.exit(1)
    else:
        saved = PolicyCompiler.from_agent_id(agent_id)
        if saved:
            print(f"  {G}Loaded saved policy for:{RS} {agent_id}")
            policy_data = saved.raw
        else:
            policy_data = {"agent_id": agent_id}

    policy_data["agent_id"] = agent_id
    if hasattr(args, "block") and args.block:
        policy_data.setdefault("blocked_paths", []).extend(args.block)
    if hasattr(args, "allow") and args.allow:
        policy_data.setdefault("allowed_paths", []).extend(args.allow)
    if hasattr(args, "allow_hosts") and args.allow_hosts:
        policy_data.setdefault("allowed_hosts", []).extend(args.allow_hosts)
    if hasattr(args, "block_hosts") and args.block_hosts:
        policy_data.setdefault("blocked_hosts", []).extend(args.block_hosts)
    if hasattr(args, "max_risk") and args.max_risk:
        policy_data["max_risk_score"] = args.max_risk

    policy = PolicyCompiler(policy_data)
    return VaultakSentry(
        api_key       = api_key,
        agent_id      = agent_id,
        policy        = policy,
        mode          = args.mode if hasattr(args, "mode") else MODE_ALERT,
        watch_paths   = args.watch if hasattr(args, "watch") and args.watch else None,
        verbose       = args.verbose if hasattr(args, "verbose") else False,
        monitor_env   = args.monitor_env if hasattr(args, "monitor_env") else False,
        monitor_procs = not args.no_proc if hasattr(args, "no_proc") else True,
        monitor_net   = not args.no_net  if hasattr(args, "no_net")  else True,
        monitor_fs    = not args.no_fs   if hasattr(args, "no_fs")   else True,
    )


# ══════════════════════════════════════════════════════════════════════════════
# CLI commands
# ══════════════════════════════════════════════════════════════════════════════

def cmd_auth(args):
    cfg = load_config()
    cfg["api_key"] = args.api_key
    save_config(cfg)
    print(f"{G}API key saved to {CONFIG_FILE}{RS}")

def cmd_run(args):
    agent_id = args.name or "_".join(args.command[:2]).replace("/","_")[:32]
    sentry   = build_sentry_from_args(args, agent_id)
    sentry.run(args.command)

def cmd_attach(args):
    agent_id = args.name or f"pid_{args.pid}"
    sentry   = build_sentry_from_args(args, agent_id)
    sentry.attach(args.pid)

def cmd_policy(args):
    if args.action == "list":
        print(f"\n  {P}{BD}Available policy templates:{RS}\n")
        for name, tmpl in POLICY_TEMPLATES.items():
            print(f"  {G}{name:<20}{RS}  {tmpl.get('description','')}")
        saved = list(POLICY_DIR.glob("*.json"))
        if saved:
            print(f"\n  {P}{BD}Saved agent policies:{RS}\n")
            for p in saved:
                print(f"  {C}{p.stem}{RS}  ({p})")
        print()

    elif args.action == "create":
        if not args.agent_id:
            print(f"{R}Provide --agent-id{RS}")
            return
        policy_data: dict = {"agent_id": args.agent_id}
        if args.template:
            if args.template not in POLICY_TEMPLATES:
                print(f"{R}Unknown template: {args.template}{RS}")
                return
            policy_data = {**POLICY_TEMPLATES[args.template],
                           "agent_id": args.agent_id}
        if args.allow_paths:
            policy_data["allowed_paths"] = args.allow_paths
        if args.block_paths:
            policy_data["blocked_paths"] = args.block_paths
        if args.allow_hosts:
            policy_data["allowed_hosts"] = args.allow_hosts
        if args.max_risk:
            policy_data["max_risk_score"] = args.max_risk
        compiler = PolicyCompiler(policy_data)
        path = compiler.save()
        print(f"{G}Policy saved to {path}{RS}")
        print(compiler.summary())

    elif args.action == "show":
        if not args.agent_id:
            print(f"{R}Provide --agent-id{RS}")
            return
        compiler = PolicyCompiler.from_agent_id(args.agent_id)
        if not compiler:
            print(f"{R}No policy found for agent: {args.agent_id}{RS}")
            return
        print(compiler.summary())

    elif args.action == "delete":
        if not args.agent_id:
            print(f"{R}Provide --agent-id{RS}")
            return
        path = POLICY_DIR / f"{args.agent_id}.json"
        if path.exists():
            path.unlink()
            print(f"{G}Policy deleted: {args.agent_id}{RS}")
        else:
            print(f"{R}No policy found for: {args.agent_id}{RS}")

def cmd_status(args):
    cfg     = load_config()
    api_key = cfg.get("api_key", "not set")
    masked  = f"vtk_...{api_key[-6:]}" if api_key != "not set" else "not set"
    saved   = list(POLICY_DIR.glob("*.json"))
    print(f"\n  {P}{BD}Vaultak Sentry v{VERSION}{RS}")
    print(f"  {D}API key      {RS}{W}{masked}{RS}")
    print(f"  {D}Policies     {RS}{W}{len(saved)} saved{RS}")
    print(f"  {D}Config       {RS}{W}{CONFIG_FILE}{RS}")
    print(f"  {D}Platform     {RS}{W}{platform.system()} {platform.release()}{RS}")
    print(f"  {D}psutil       {RS}{G if HAS_PSUTIL  else R}{'ok' if HAS_PSUTIL  else 'missing: pip install psutil'}{RS}")
    print(f"  {D}watchdog     {RS}{G if HAS_WATCHDOG else R}{'ok' if HAS_WATCHDOG else 'missing: pip install watchdog'}{RS}\n")

def _add_common_args(p):
    p.add_argument("--mode", default=MODE_ALERT,
                   choices=[MODE_ALERT, MODE_PAUSE, MODE_ROLLBACK])
    p.add_argument("--policy",      default=None,
                   help="Template name or path to policy JSON file")
    p.add_argument("--allow",       nargs="*", help="Allowed path patterns")
    p.add_argument("--block",       nargs="*", help="Blocked path patterns")
    p.add_argument("--allow-hosts", nargs="*", help="Allowed hostnames")
    p.add_argument("--block-hosts", nargs="*", help="Blocked hostnames")
    p.add_argument("--max-risk",    type=float, default=None)
    p.add_argument("--watch",       nargs="*",  help="Paths to monitor")
    p.add_argument("--verbose",     action="store_true")
    p.add_argument("--monitor-env", action="store_true",
                   help="Enable environment variable access monitoring")
    p.add_argument("--no-proc",     action="store_true",
                   help="Disable process spawn monitoring")
    p.add_argument("--no-net",      action="store_true",
                   help="Disable network monitoring")
    p.add_argument("--no-fs",       action="store_true",
                   help="Disable file system monitoring")

def main():
    parser = argparse.ArgumentParser(
        prog="vaultak-sentry",
        description="Vaultak Sentry: Zero-code runtime security for AI agents",
    )
    parser.add_argument("--version", action="version",
                        version=f"%(prog)s {VERSION}")
    sub = parser.add_subparsers(dest="cmd", required=True)

    # auth
    p_auth = sub.add_parser("auth", help="Save your Vaultak API key")
    p_auth.add_argument("--api-key", required=True)

    # run
    p_run = sub.add_parser("run", help="Run any agent with monitoring")
    p_run.add_argument("command", nargs=argparse.REMAINDER)
    p_run.add_argument("--name", default=None)
    _add_common_args(p_run)

    # attach
    p_att = sub.add_parser("attach", help="Attach to a running process")
    p_att.add_argument("pid", type=int)
    p_att.add_argument("--name", default=None)
    _add_common_args(p_att)

    # policy
    p_pol = sub.add_parser("policy", help="Manage agent policies")
    p_pol.add_argument("action",
                       choices=["list", "create", "show", "delete"])
    p_pol.add_argument("--agent-id",    default=None)
    p_pol.add_argument("--template",    default=None,
                       choices=list(POLICY_TEMPLATES.keys()))
    p_pol.add_argument("--allow-paths", nargs="*")
    p_pol.add_argument("--block-paths", nargs="*")
    p_pol.add_argument("--allow-hosts", nargs="*")
    p_pol.add_argument("--max-risk",    type=float, default=None)

    # status
    sub.add_parser("status", help="Show configuration and status")

    args = parser.parse_args()
    dispatch = {
        "auth":   cmd_auth,
        "run":    cmd_run,
        "attach": cmd_attach,
        "policy": cmd_policy,
        "status": cmd_status,
    }
    dispatch[args.cmd](args)

if __name__ == "__main__":
    main()
