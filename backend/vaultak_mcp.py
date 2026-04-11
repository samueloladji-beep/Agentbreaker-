"""
Vaultak MCP Gateway
Intercepts Model Context Protocol (MCP) tool calls and applies
Vaultak security policies before tools execute.

MCP is the emerging standard for AI agent tool use.
This gateway sits between your agent and MCP servers,
enforcing policies on every tool call without code changes.

Architecture:
  Agent -> Vaultak MCP Gateway -> MCP Server -> Tools

Usage:
  # Start the gateway
  vaultak-mcp start --api-key vtk_... --target http://localhost:3000

  # Or use as a Python proxy
  from vaultak_mcp import VaultakMCPGateway
  gateway = VaultakMCPGateway(api_key="vtk_...", target_url="http://localhost:3000")
  gateway.start(port=3001)
"""

import os
import sys
import json
import time
import hashlib
import logging
import argparse
import threading
from typing import Optional
from datetime import datetime, timezone
from pathlib import Path
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.request import urlopen, Request as URLRequest
from urllib.error import URLError
from urllib.parse import urlparse

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

VERSION    = "0.1.0"
API_BASE   = os.environ.get("VAULTAK_API_URL", "https://vaultak.com")
CONFIG_DIR = Path.home() / ".vaultak"
CONFIG_DIR.mkdir(exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [vaultak-mcp] %(message)s"
)
logger = logging.getLogger("vaultak-mcp")

# ── Risk weights for MCP tool categories ─────────────────────────────────────
TOOL_RISK_WEIGHTS = {
    # File system tools
    "write_file":        0.75,
    "delete_file":       0.85,
    "create_directory":  0.60,
    "move_file":         0.65,
    "read_file":         0.25,
    "list_directory":    0.15,

    # Shell / code execution
    "run_command":       0.90,
    "execute_code":      0.90,
    "bash":              0.90,
    "shell":             0.90,

    # Database tools
    "query_database":    0.35,
    "execute_sql":       0.70,
    "insert_record":     0.65,
    "delete_record":     0.80,
    "update_record":     0.65,

    # Network / web tools
    "fetch_url":         0.45,
    "http_request":      0.50,
    "send_email":        0.70,
    "send_message":      0.65,

    # Browser tools
    "browser_navigate":  0.40,
    "browser_click":     0.45,
    "browser_type":      0.50,
    "screenshot":        0.30,

    # Code / git tools
    "git_commit":        0.60,
    "git_push":          0.75,
    "deploy":            0.90,
    "publish":           0.80,

    # Default for unknown tools
    "_default":          0.50,
}

# ── Sensitive argument patterns ───────────────────────────────────────────────
SENSITIVE_ARG_PATTERNS = [
    "prod", "production", "*.env", ".env", "secret",
    "password", "credential", "token", "key", "private",
    "/etc/", "/root/", "~/.ssh/", ".pem", ".key",
]


def score_tool_call(tool_name: str, arguments: dict) -> float:
    """Compute risk score for an MCP tool call."""
    base = TOOL_RISK_WEIGHTS.get(tool_name.lower(),
                                  TOOL_RISK_WEIGHTS["_default"])

    # Check arguments for sensitive patterns
    arg_str = json.dumps(arguments).lower()
    sensitive_hit = any(p in arg_str for p in SENSITIVE_ARG_PATTERNS)
    if sensitive_hit:
        base = min(1.0, base + 0.2)

    return round(base, 3)


# ── Vaultak API client ────────────────────────────────────────────────────────
class VaultakAPI:
    def __init__(self, api_key: str, agent_id: str):
        self.api_key    = api_key
        self.agent_id   = agent_id
        self.headers    = {
            "x-api-key":    api_key,
            "Content-Type": "application/json",
        }
        self.session_id = hashlib.sha256(
            f"{agent_id}{datetime.now().isoformat()}".encode()
        ).hexdigest()[:16]

    def check(self, tool_name: str, arguments: dict,
              risk_score: float) -> dict:
        if not HAS_REQUESTS:
            return {"decision": "allow"}
        try:
            r = requests.post(
                f"{API_BASE}/api/check",
                headers=self.headers,
                json={
                    "agent_id":    self.agent_id,
                    "action_type": "mcp_tool_call",
                    "resource":    tool_name,
                    "risk_score":  risk_score,
                    "metadata": {
                        "tool":      tool_name,
                        "arguments": {
                            k: "***" if any(
                                p in k.lower()
                                for p in ["key", "secret", "password", "token"]
                            ) else str(v)[:100]
                            for k, v in arguments.items()
                        },
                        "source": "mcp_gateway",
                    },
                },
                timeout=2,
            )
            return r.json() if r.status_code == 200 else {"decision": "allow"}
        except Exception:
            return {"decision": "allow"}

    def log(self, tool_name: str, arguments: dict,
            risk_score: float, decision: str):
        if not HAS_REQUESTS:
            return
        try:
            requests.post(
                f"{API_BASE}/api/actions",
                headers=self.headers,
                json={
                    "agent_id":    self.agent_id,
                    "action_type": "mcp_tool_call",
                    "resource":    tool_name,
                    "risk_score":  risk_score,
                    "decision":    decision,
                    "source":      "mcp_gateway",
                    "session_id":  self.session_id,
                    "timestamp":   datetime.now(timezone.utc).isoformat(),
                },
                timeout=2,
            )
        except Exception:
            pass


# ── MCP Policy Engine ─────────────────────────────────────────────────────────
class MCPPolicy:
    """
    Policy for MCP tool calls.
    Defines which tools are allowed, blocked, or require approval.
    """

    def __init__(self, policy_dict: dict = None):
        p = policy_dict or {}
        self.allowed_tools   = set(p.get("allowed_tools",   []))
        self.blocked_tools   = set(p.get("blocked_tools",   []))
        self.max_risk_score  = p.get("max_risk_score",  0.85)
        self.mode            = p.get("mode", "alert")
        self.blocked_args    = p.get("blocked_arg_patterns", SENSITIVE_ARG_PATTERNS)

    def evaluate(self, tool_name: str, arguments: dict,
                 risk_score: float) -> tuple:
        """Returns (decision, reason)."""

        # Blocked tools take highest priority
        if tool_name.lower() in {t.lower() for t in self.blocked_tools}:
            return "block", f"Tool '{tool_name}' is blocked by policy"

        # Allowlist: if set, only listed tools are permitted
        if self.allowed_tools:
            if tool_name.lower() not in {t.lower() for t in self.allowed_tools}:
                return "block", f"Tool '{tool_name}' is not in the allowed tools list"

        # Check argument patterns
        arg_str = json.dumps(arguments).lower()
        for pattern in self.blocked_args:
            if pattern.lower() in arg_str:
                return "block", f"Arguments contain blocked pattern: {pattern}"

        # Risk ceiling
        if risk_score >= self.max_risk_score:
            return "block", f"Risk score {risk_score:.2f} exceeds limit {self.max_risk_score}"

        return "allow", "Within policy"

    @classmethod
    def from_file(cls, path: str) -> "MCPPolicy":
        with open(path) as f:
            return cls(json.load(f))

    @classmethod
    def from_agent_id(cls, agent_id: str) -> Optional["MCPPolicy"]:
        path = CONFIG_DIR / "policies" / f"{agent_id}_mcp.json"
        if path.exists():
            return cls.from_file(str(path))
        return None

    def save(self, agent_id: str):
        policy_dir = CONFIG_DIR / "policies"
        policy_dir.mkdir(exist_ok=True)
        path = policy_dir / f"{agent_id}_mcp.json"
        path.write_text(json.dumps({
            "allowed_tools":        list(self.allowed_tools),
            "blocked_tools":        list(self.blocked_tools),
            "max_risk_score":       self.max_risk_score,
            "mode":                 self.mode,
            "blocked_arg_patterns": self.blocked_args,
        }, indent=2))
        return path


# ── HTTP Proxy Gateway ────────────────────────────────────────────────────────
class MCPProxyHandler(BaseHTTPRequestHandler):
    """
    HTTP proxy that intercepts MCP JSON-RPC requests,
    applies Vaultak policies, then forwards allowed requests
    to the real MCP server.
    """
    gateway = None  # Set by VaultakMCPGateway

    def log_message(self, format, *args):
        pass  # Suppress default HTTP logging

    def do_POST(self):
        content_length = int(self.headers.get("Content-Length", 0))
        body           = self.rfile.read(content_length)

        try:
            rpc = json.loads(body)
        except json.JSONDecodeError:
            self._forward_raw(body)
            return

        # Only intercept tool calls
        method = rpc.get("method", "")
        if method != "tools/call":
            self._forward_raw(body)
            return

        # Extract tool name and arguments
        params     = rpc.get("params", {})
        tool_name  = params.get("name", "unknown")
        arguments  = params.get("arguments", {})
        request_id = rpc.get("id")

        # Score and evaluate
        risk_score = score_tool_call(tool_name, arguments)
        decision, reason = self.gateway.policy.evaluate(
            tool_name, arguments, risk_score)

        logger.info(f"MCP  {tool_name}  risk:{risk_score:.2f}  {decision.upper()}")

        # Log to Vaultak backend
        threading.Thread(
            target=self.gateway.api.log,
            args=(tool_name, arguments, risk_score, decision),
            daemon=True
        ).start()

        if decision == "block":
            # Return a JSON-RPC error response
            self.gateway.stats["blocked"] += 1
            error_response = json.dumps({
                "jsonrpc": "2.0",
                "id":      request_id,
                "error": {
                    "code":    -32600,
                    "message": f"Blocked by Vaultak: {reason}",
                    "data": {
                        "tool":       tool_name,
                        "risk_score": risk_score,
                        "reason":     reason,
                        "policy":     "vaultak_mcp_gateway",
                    }
                }
            }).encode()

            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", len(error_response))
            self.send_header("X-Vaultak-Decision", "block")
            self.send_header("X-Vaultak-Risk", str(risk_score))
            self.end_headers()
            self.wfile.write(error_response)
            return

        # Allow: forward to real MCP server
        self.gateway.stats["allowed"] += 1
        self._forward_raw(body, extra_headers={
            "X-Vaultak-Decision": "allow",
            "X-Vaultak-Risk":     str(risk_score),
        })

    def do_GET(self):
        self._forward_raw(b"", method="GET")

    def _forward_raw(self, body: bytes, method: str = "POST",
                     extra_headers: dict = None):
        target_url = self.gateway.target_url + self.path
        headers = {
            k: v for k, v in self.headers.items()
            if k.lower() not in ("host", "content-length")
        }
        if extra_headers:
            headers.update(extra_headers)

        if HAS_REQUESTS:
            try:
                resp = requests.request(
                    method=method,
                    url=target_url,
                    headers=headers,
                    data=body,
                    timeout=30,
                    stream=True,
                )
                self.send_response(resp.status_code)
                for k, v in resp.headers.items():
                    if k.lower() not in ("transfer-encoding", "connection"):
                        self.send_header(k, v)
                self.end_headers()
                self.wfile.write(resp.content)
            except Exception as e:
                self._error(502, str(e))
        else:
            self._error(503, "requests library not available")

    def _error(self, code: int, message: str):
        body = json.dumps({"error": message}).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", len(body))
        self.end_headers()
        self.wfile.write(body)


# ── Main Gateway class ────────────────────────────────────────────────────────
class VaultakMCPGateway:
    """
    Vaultak MCP Gateway.
    Starts an HTTP proxy that intercepts MCP tool calls
    and applies Vaultak security policies.

    Usage:
        gateway = VaultakMCPGateway(
            api_key="vtk_...",
            target_url="http://localhost:3000",
            agent_id="my-agent",
            policy=MCPPolicy({
                "blocked_tools": ["delete_file", "run_command"],
                "max_risk_score": 0.7,
            })
        )
        gateway.start(port=3001)
        # Now point your agent at http://localhost:3001 instead of :3000
    """

    def __init__(
        self,
        api_key:    str,
        target_url: str,
        agent_id:   str      = "mcp-agent",
        policy:     MCPPolicy = None,
        verbose:    bool     = False,
    ):
        self.api_key    = api_key
        self.target_url = target_url.rstrip("/")
        self.agent_id   = agent_id
        self.policy     = policy or MCPPolicy.from_agent_id(agent_id) or MCPPolicy()
        self.verbose    = verbose
        self.api        = VaultakAPI(api_key, agent_id)
        self.server     = None
        self.stats      = {"allowed": 0, "blocked": 0, "total": 0}

        # Inject gateway reference into handler class
        MCPProxyHandler.gateway = self

    def start(self, port: int = 3001, block: bool = True):
        self.server = HTTPServer(("0.0.0.0", port), MCPProxyHandler)
        logger.info(f"Vaultak MCP Gateway v{VERSION}")
        logger.info(f"Listening on  http://localhost:{port}")
        logger.info(f"Forwarding to {self.target_url}")
        logger.info(f"Agent ID:     {self.agent_id}")
        logger.info(f"Mode:         {self.policy.mode.upper()}")
        logger.info(f"Dashboard:    app.vaultak.com")

        if block:
            try:
                self.server.serve_forever()
            except KeyboardInterrupt:
                self.stop()
        else:
            t = threading.Thread(
                target=self.server.serve_forever, daemon=True)
            t.start()

    def stop(self):
        if self.server:
            self.server.shutdown()
        logger.info(f"Gateway stopped. "
                    f"Allowed: {self.stats['allowed']}  "
                    f"Blocked: {self.stats['blocked']}")


# ── MCP Scanner ───────────────────────────────────────────────────────────────
class MCPScanner:
    """
    Scans MCP server configurations and tool definitions
    for security vulnerabilities.
    """

    DANGEROUS_CAPABILITIES = [
        "run_command", "execute_code", "bash", "shell",
        "delete_file", "deploy", "git_push", "publish",
        "send_email", "http_request",
    ]

    HIGH_RISK_PATTERNS = [
        r"(?i)subprocess",
        r"(?i)eval\s*\(",
        r"(?i)exec\s*\(",
        r"(?i)os\.system",
        r"(?i)shell\s*=\s*True",
        r"(?i)rm\s+-rf",
        r"(?i)DROP\s+TABLE",
        r"(?i)DELETE\s+FROM",
    ]

    def scan_tool_definition(self, tool: dict) -> dict:
        """Scan a single MCP tool definition for risks."""
        import re
        issues = []
        name   = tool.get("name", "unknown")
        desc   = tool.get("description", "")
        schema = json.dumps(tool.get("inputSchema", {}))

        # Check for dangerous tool names
        if name.lower() in self.DANGEROUS_CAPABILITIES:
            issues.append({
                "severity": "high",
                "issue":    f"Tool '{name}' is a high-risk capability",
                "advice":   "Add explicit policy restrictions for this tool",
            })

        # Check description for risky patterns
        full_text = f"{desc} {schema}".lower()
        for pattern in self.HIGH_RISK_PATTERNS:
            if re.search(pattern, full_text):
                issues.append({
                    "severity": "medium",
                    "issue":    f"Tool definition contains risky pattern: {pattern}",
                    "advice":   "Review tool implementation for security implications",
                })

        # Check for missing input validation
        input_schema = tool.get("inputSchema", {})
        properties   = input_schema.get("properties", {})
        required     = input_schema.get("required", [])

        for prop_name, prop_def in properties.items():
            if "path" in prop_name.lower() and prop_name not in required:
                issues.append({
                    "severity": "low",
                    "issue":    f"Path parameter '{prop_name}' is not required",
                    "advice":   "Consider requiring all path parameters",
                })

        risk_level = "low"
        if any(i["severity"] == "high" for i in issues):
            risk_level = "high"
        elif any(i["severity"] == "medium" for i in issues):
            risk_level = "medium"

        return {
            "tool":       name,
            "risk_level": risk_level,
            "issues":     issues,
            "safe":       len(issues) == 0,
        }

    def scan_server(self, tools: list) -> dict:
        """Scan all tools from an MCP server."""
        results    = [self.scan_tool_definition(t) for t in tools]
        high_risk  = [r for r in results if r["risk_level"] == "high"]
        medium_risk= [r for r in results if r["risk_level"] == "medium"]

        return {
            "total_tools":    len(results),
            "safe_tools":     sum(1 for r in results if r["safe"]),
            "high_risk":      len(high_risk),
            "medium_risk":    len(medium_risk),
            "overall_risk":   "high" if high_risk else "medium" if medium_risk else "low",
            "tools":          results,
            "recommendations": self._generate_recommendations(results),
        }

    def _generate_recommendations(self, results: list) -> list:
        recs = []
        high = [r["tool"] for r in results if r["risk_level"] == "high"]
        if high:
            recs.append({
                "priority": "high",
                "action":   f"Add explicit block policies for: {', '.join(high)}",
                "policy":   {"blocked_tools": high},
            })
        recs.append({
            "priority": "medium",
            "action":   "Set max_risk_score to 0.7 for production deployments",
            "policy":   {"max_risk_score": 0.7},
        })
        return recs


# ── CLI ───────────────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        prog="vaultak-mcp",
        description="Vaultak MCP Gateway: Secure any MCP server",
    )
    parser.add_argument("--version", action="version",
                        version=f"%(prog)s {VERSION}")
    sub = parser.add_subparsers(dest="cmd", required=True)

    # start
    p_start = sub.add_parser("start",
                              help="Start the MCP gateway proxy")
    p_start.add_argument("--api-key",   required=True,
                         help="Your Vaultak API key")
    p_start.add_argument("--target",    required=True,
                         help="MCP server URL to proxy")
    p_start.add_argument("--port",      type=int, default=3001,
                         help="Port to listen on (default: 3001)")
    p_start.add_argument("--name",      default="mcp-agent",
                         help="Agent ID for dashboard")
    p_start.add_argument("--mode",
                         choices=["alert", "block"],
                         default="block",
                         help="Response mode (default: block)")
    p_start.add_argument("--block",     nargs="*",
                         help="Tool names to block")
    p_start.add_argument("--allow",     nargs="*",
                         help="Allowed tools only (allowlist)")
    p_start.add_argument("--max-risk",  type=float, default=0.85,
                         help="Max risk score before blocking")
    p_start.add_argument("--verbose",   action="store_true")

    # scan
    p_scan = sub.add_parser("scan",
                             help="Scan an MCP server config for vulnerabilities")
    p_scan.add_argument("file", help="Path to MCP tools JSON file")

    args = parser.parse_args()

    if args.cmd == "start":
        policy = MCPPolicy({
            "blocked_tools":  args.block or [],
            "allowed_tools":  args.allow or [],
            "max_risk_score": args.max_risk,
            "mode":           args.mode,
        })
        gateway = VaultakMCPGateway(
            api_key    = args.api_key,
            target_url = args.target,
            agent_id   = args.name,
            policy     = policy,
            verbose    = args.verbose,
        )
        gateway.start(port=args.port)

    elif args.cmd == "scan":
        with open(args.file) as f:
            data = json.load(f)
        tools   = data if isinstance(data, list) else data.get("tools", [])
        scanner = MCPScanner()
        result  = scanner.scan_server(tools)
        print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
