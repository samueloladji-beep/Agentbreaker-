"""
Vaultak MCP Server for Claude
Exposes Vaultak dashboard capabilities as Claude-callable tools.
This is an optional integration — Vaultak works fully without it.

Tools exposed:
  - get_agents        — list all monitored agents and their status
  - get_alerts        — get active security alerts
  - get_risk_summary  — get risk distribution and stats
  - acknowledge_alert — acknowledge an alert by ID
  - pause_agent       — pause an agent by ID
  - resume_agent      — resume a paused agent
"""

import os
import json
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.request import urlopen, Request as URLRequest

API_BASE = os.environ.get("VAULTAK_API_URL", "https://vaultak.com")

TOOLS = [
    {
        "name": "get_agents",
        "description": "List all AI agents monitored by Vaultak, including their status, risk score, and action counts.",
        "input_schema": {
            "type": "object",
            "properties": {
                "api_key": {"type": "string", "description": "Your Vaultak API key (starts with vtk_)"}
            },
            "required": ["api_key"]
        }
    },
    {
        "name": "get_alerts",
        "description": "Get active security alerts from Vaultak. Returns unacknowledged alerts with severity and agent info.",
        "input_schema": {
            "type": "object",
            "properties": {
                "api_key": {"type": "string", "description": "Your Vaultak API key (starts with vtk_)"}
            },
            "required": ["api_key"]
        }
    },
    {
        "name": "get_risk_summary",
        "description": "Get a summary of risk distribution and key security metrics from your Vaultak dashboard.",
        "input_schema": {
            "type": "object",
            "properties": {
                "api_key": {"type": "string", "description": "Your Vaultak API key (starts with vtk_)"}
            },
            "required": ["api_key"]
        }
    },
    {
        "name": "acknowledge_alert",
        "description": "Acknowledge a specific security alert in Vaultak by its ID.",
        "input_schema": {
            "type": "object",
            "properties": {
                "api_key": {"type": "string", "description": "Your Vaultak API key (starts with vtk_)"},
                "alert_id": {"type": "string", "description": "The ID of the alert to acknowledge"}
            },
            "required": ["api_key", "alert_id"]
        }
    },
    {
        "name": "pause_agent",
        "description": "Pause an AI agent in Vaultak to stop it from executing further actions.",
        "input_schema": {
            "type": "object",
            "properties": {
                "api_key": {"type": "string", "description": "Your Vaultak API key (starts with vtk_)"},
                "agent_id": {"type": "string", "description": "The ID of the agent to pause"}
            },
            "required": ["api_key", "agent_id"]
        }
    },
    {
        "name": "resume_agent",
        "description": "Resume a paused AI agent in Vaultak.",
        "input_schema": {
            "type": "object",
            "properties": {
                "api_key": {"type": "string", "description": "Your Vaultak API key (starts with vtk_)"},
                "agent_id": {"type": "string", "description": "The ID of the agent to resume"}
            },
            "required": ["api_key", "agent_id"]
        }
    },
]


def call_vaultak(endpoint, api_key, method="GET", body=None):
    url = f"{API_BASE}{endpoint}"
    headers = {"x-api-key": api_key, "Content-Type": "application/json"}
    data = json.dumps(body).encode() if body else None
    req = URLRequest(url, data=data, headers=headers, method=method)
    try:
        with urlopen(req, timeout=10) as resp:
            return json.loads(resp.read().decode())
    except Exception as e:
        return {"error": str(e)}


def handle_tool(name, inputs):
    api_key = inputs.get("api_key", "")
    if not api_key.startswith("vtk_"):
        return {"error": "Invalid API key. Must start with vtk_"}

    if name == "get_agents":
        data = call_vaultak("/api/agents", api_key)
        if isinstance(data, list):
            return {
                "agents": [
                    {
                        "id": a.get("agent_id"),
                        "name": a.get("name"),
                        "status": "paused" if a.get("paused") else "active",
                        "avg_risk_score": round(a.get("avg_risk_score", 0), 2),
                        "last_seen": a.get("last_seen")
                    }
                    for a in data
                ],
                "total": len(data)
            }
        return data

    elif name == "get_alerts":
        data = call_vaultak("/api/alerts", api_key)
        if isinstance(data, list):
            active = [a for a in data if not a.get("acknowledged")]
            return {
                "alerts": [
                    {
                        "id": a.get("id"),
                        "message": a.get("message"),
                        "severity": a.get("level"),
                        "agent_id": a.get("agent_id"),
                        "created_at": a.get("created_at")
                    }
                    for a in active
                ],
                "total": len(active)
            }
        return data

    elif name == "get_risk_summary":
        return call_vaultak("/api/stats", api_key)

    elif name == "acknowledge_alert":
        alert_id = inputs.get("alert_id")
        if not alert_id:
            return {"error": "alert_id is required"}
        return call_vaultak(f"/api/alerts/{alert_id}/acknowledge", api_key, method="PATCH")

    elif name == "pause_agent":
        agent_id = inputs.get("agent_id")
        if not agent_id:
            return {"error": "agent_id is required"}
        return call_vaultak(f"/api/agents/{agent_id}", api_key, method="PATCH", body={"paused": True})

    elif name == "resume_agent":
        agent_id = inputs.get("agent_id")
        if not agent_id:
            return {"error": "agent_id is required"}
        return call_vaultak(f"/api/agents/{agent_id}", api_key, method="PATCH", body={"paused": False})

    return {"error": f"Unknown tool: {name}"}


class MCPHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        pass

    def do_GET(self):
        if self.path == "/" or self.path == "/tools":
            self._json({"name": "vaultak", "version": "1.0.0",
                        "description": "Runtime security for AI agents", "tools": TOOLS})
        elif self.path == "/health":
            self._json({"status": "ok"})
        else:
            self._json({"error": "Not found"}, 404)

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = json.loads(self.rfile.read(length)) if length else {}

        if self.path == "/call":
            name = body.get("name")
            inputs = body.get("inputs", body.get("input", {}))
            if not name:
                self._json({"error": "name is required"}, 400)
                return
            self._json({"result": handle_tool(name, inputs)})

        elif self.path == "/mcp":
            method = body.get("method")
            params = body.get("params", {})
            req_id = body.get("id")
            if method == "tools/list":
                self._jsonrpc(req_id, {"tools": TOOLS})
            elif method == "tools/call":
                name = params.get("name")
                inputs = params.get("arguments", {})
                result = handle_tool(name, inputs)
                self._jsonrpc(req_id, {"content": [{"type": "text", "text": json.dumps(result, indent=2)}]})
            else:
                self._jsonrpc(req_id, None, {"code": -32601, "message": f"Method not found: {method}"})
        else:
            self._json({"error": "Not found"}, 404)

    def _json(self, data, status=200):
        body = json.dumps(data).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Content-Length", len(body))
        self.end_headers()
        self.wfile.write(body)

    def _jsonrpc(self, req_id, result=None, error=None):
        resp = {"jsonrpc": "2.0", "id": req_id}
        if error:
            resp["error"] = error
        else:
            resp["result"] = result
        self._json(resp)

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()


if __name__ == "__main__":
    port = int(os.environ.get("MCP_PORT", 3001))
    print(f"Vaultak MCP Server running on port {port}")
    print(f"Tools: {[t['name'] for t in TOOLS]}")
    HTTPServer(("0.0.0.0", port), MCPHandler).serve_forever()
