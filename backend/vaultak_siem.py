"""
Vaultak SIEM Integration Module
Pushes every Vaultak event to your SIEM in real time.

Supported integrations:
  - Splunk (HTTP Event Collector)
  - Datadog (Logs API)
  - Microsoft Sentinel (Azure Monitor / Log Analytics)
  - Elastic / ELK Stack (Elasticsearch API)
  - Generic webhook (any SIEM or custom endpoint)
  - Slack (alert notifications)
  - PagerDuty (incident creation)

Usage:
  # Configure via environment variables
  export VAULTAK_SIEM_TYPE=splunk
  export VAULTAK_SIEM_URL=https://splunk.company.com:8088
  export VAULTAK_SIEM_TOKEN=your-hec-token

  # Or configure via the dashboard at app.vaultak.com

  # Or use directly in Python
  from vaultak_siem import SIEMRouter
  router = SIEMRouter()
  router.add(SplunkConnector(url="...", token="..."))
  router.send(event)
"""

import os
import json
import time
import hmac
import hashlib
import logging
import threading
import queue
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from typing import Optional

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

logger = logging.getLogger("vaultak-siem")

# ── Event schema ──────────────────────────────────────────────────────────────

def normalize_event(event: dict) -> dict:
    """
    Normalize a Vaultak event into a standard SIEM-compatible format.
    Maps Vaultak fields to common SIEM field names.
    """
    now = datetime.now(timezone.utc).isoformat()
    return {
        # Standard fields
        "timestamp":        event.get("timestamp", now),
        "source":           "vaultak",
        "source_version":   event.get("version", "0.5.1"),
        "event_type":       event.get("action_type", "unknown"),
        "severity":         _map_severity(event.get("risk_score", 0)),

        # Agent context
        "agent_id":         event.get("agent_id", ""),
        "organization_id":  event.get("org_id", ""),
        "session_id":       event.get("session_id", ""),

        # Action details
        "action_type":      event.get("action_type", ""),
        "resource":         event.get("resource", ""),
        "risk_score":       event.get("risk_score", 0),
        "decision":         event.get("decision", "allow"),
        "reason":           event.get("reason", ""),

        # Response
        "mode":             event.get("mode", "alert"),
        "rolled_back":      event.get("rolled_back", False),

        # Compliance tags
        "compliance_tags":  _get_compliance_tags(event),

        # Raw event for full fidelity
        "raw":              event,
    }


def _map_severity(risk_score: float) -> str:
    if risk_score >= 0.85: return "critical"
    if risk_score >= 0.70: return "high"
    if risk_score >= 0.50: return "medium"
    if risk_score >= 0.30: return "low"
    return "info"


def _get_compliance_tags(event: dict) -> list:
    tags      = ["vaultak", "ai-agent-security"]
    resource  = str(event.get("resource", "")).lower()
    action    = str(event.get("action_type", "")).lower()

    if any(p in resource for p in ["patient", "phi", "health", "medical"]):
        tags.append("hipaa")
    if any(p in resource for p in ["card", "payment", "pci"]):
        tags.append("pci-dss")
    if action in ["pii_detected", "data_masking"]:
        tags.append("gdpr")
    if event.get("decision") == "block":
        tags.append("security-violation")
    if event.get("rolled_back"):
        tags.append("incident-response")

    return tags


# ── Base connector ────────────────────────────────────────────────────────────

class SIEMConnector(ABC):
    """Base class for all SIEM connectors."""

    def __init__(self, name: str, enabled: bool = True):
        self.name    = name
        self.enabled = enabled
        self._sent   = 0
        self._errors = 0

    @abstractmethod
    def send(self, event: dict) -> bool:
        """Send a normalized event. Returns True on success."""
        pass

    def stats(self) -> dict:
        return {
            "connector": self.name,
            "sent":      self._sent,
            "errors":    self._errors,
        }


# ── Splunk HEC connector ──────────────────────────────────────────────────────

class SplunkConnector(SIEMConnector):
    """
    Sends events to Splunk via HTTP Event Collector (HEC).

    Setup in Splunk:
    1. Settings > Data Inputs > HTTP Event Collector > New Token
    2. Set source type to _json
    3. Copy the token here
    """

    def __init__(self, url: str, token: str,
                 index: str = "vaultak",
                 source_type: str = "vaultak:agent:security",
                 verify_ssl: bool = True):
        super().__init__("splunk")
        self.url         = url.rstrip("/") + "/services/collector/event"
        self.token       = token
        self.index       = index
        self.source_type = source_type
        self.verify_ssl  = verify_ssl

    def send(self, event: dict) -> bool:
        if not HAS_REQUESTS or not self.enabled:
            return False
        try:
            payload = {
                "time":       time.time(),
                "host":       "vaultak",
                "source":     "vaultak-agent-security",
                "sourcetype": self.source_type,
                "index":      self.index,
                "event":      event,
            }
            r = requests.post(
                self.url,
                headers={
                    "Authorization": f"Splunk {self.token}",
                    "Content-Type":  "application/json",
                },
                json=payload,
                verify=self.verify_ssl,
                timeout=5,
            )
            success = r.status_code in (200, 201)
            if success:
                self._sent += 1
            else:
                self._errors += 1
                logger.warning(f"Splunk error {r.status_code}: {r.text[:100]}")
            return success
        except Exception as e:
            self._errors += 1
            logger.error(f"Splunk send error: {e}")
            return False

    @classmethod
    def from_env(cls) -> Optional["SplunkConnector"]:
        url   = os.environ.get("VAULTAK_SPLUNK_URL")
        token = os.environ.get("VAULTAK_SPLUNK_TOKEN")
        if url and token:
            return cls(url=url, token=token,
                       index=os.environ.get("VAULTAK_SPLUNK_INDEX", "vaultak"))
        return None


# ── Datadog connector ─────────────────────────────────────────────────────────

class DatadogConnector(SIEMConnector):
    """
    Sends events to Datadog Logs API.
    Requires a Datadog API key with logs:write permission.
    """

    ENDPOINTS = {
        "us": "https://http-intake.logs.datadoghq.com/api/v2/logs",
        "eu": "https://http-intake.logs.datadoghq.eu/api/v2/logs",
    }

    def __init__(self, api_key: str, site: str = "us",
                 service: str = "vaultak",
                 tags: list = None):
        super().__init__("datadog")
        self.api_key  = api_key
        self.endpoint = self.ENDPOINTS.get(site, self.ENDPOINTS["us"])
        self.service  = service
        self.tags     = tags or ["source:vaultak", "env:production"]

    def send(self, event: dict) -> bool:
        if not HAS_REQUESTS or not self.enabled:
            return False
        try:
            payload = [{
                "ddsource":  "vaultak",
                "ddtags":    ",".join(self.tags),
                "hostname":  "vaultak-backend",
                "message":   json.dumps(event),
                "service":   self.service,
                "status":    event.get("severity", "info"),
                **event,
            }]
            r = requests.post(
                self.endpoint,
                headers={
                    "DD-API-KEY":   self.api_key,
                    "Content-Type": "application/json",
                },
                json=payload,
                timeout=5,
            )
            success = r.status_code in (200, 202)
            if success:
                self._sent += 1
            else:
                self._errors += 1
            return success
        except Exception as e:
            self._errors += 1
            logger.error(f"Datadog send error: {e}")
            return False

    @classmethod
    def from_env(cls) -> Optional["DatadogConnector"]:
        key = os.environ.get("VAULTAK_DATADOG_API_KEY")
        if key:
            return cls(api_key=key,
                       site=os.environ.get("VAULTAK_DATADOG_SITE", "us"))
        return None


# ── Microsoft Sentinel connector ──────────────────────────────────────────────

class SentinelConnector(SIEMConnector):
    """
    Sends events to Microsoft Sentinel via the Log Analytics Data Collector API.
    """

    def __init__(self, workspace_id: str, shared_key: str,
                 log_type: str = "VaultakAgentSecurity"):
        super().__init__("sentinel")
        self.workspace_id = workspace_id
        self.shared_key   = shared_key
        self.log_type     = log_type
        self.endpoint     = (
            f"https://{workspace_id}.ods.opinsights.azure.com"
            f"/api/logs?api-version=2016-04-01"
        )

    def _build_signature(self, date: str, content_length: int) -> str:
        string_to_hash = (
            f"POST\n{content_length}\napplication/json\n"
            f"x-ms-date:{date}\n/api/logs"
        )
        encoded = base64_hmac(self.shared_key, string_to_hash)
        return f"SharedKey {self.workspace_id}:{encoded}"

    def send(self, event: dict) -> bool:
        if not HAS_REQUESTS or not self.enabled:
            return False
        try:
            import base64
            body      = json.dumps([event]).encode()
            rfc1123   = datetime.utcnow().strftime(
                "%a, %d %b %Y %H:%M:%S GMT")
            sig_str   = (
                f"POST\n{len(body)}\napplication/json\n"
                f"x-ms-date:{rfc1123}\n/api/logs"
            )
            key_bytes = base64.b64decode(self.shared_key)
            sig_bytes = hmac.new(
                key_bytes, sig_str.encode("utf-8"), hashlib.sha256).digest()
            signature = base64.b64encode(sig_bytes).decode()
            auth      = f"SharedKey {self.workspace_id}:{signature}"

            r = requests.post(
                self.endpoint,
                headers={
                    "Content-Type":  "application/json",
                    "Log-Type":      self.log_type,
                    "x-ms-date":     rfc1123,
                    "Authorization": auth,
                },
                data=body,
                timeout=5,
            )
            success = r.status_code == 200
            if success:
                self._sent += 1
            else:
                self._errors += 1
            return success
        except Exception as e:
            self._errors += 1
            logger.error(f"Sentinel send error: {e}")
            return False

    @classmethod
    def from_env(cls) -> Optional["SentinelConnector"]:
        wid = os.environ.get("VAULTAK_SENTINEL_WORKSPACE_ID")
        key = os.environ.get("VAULTAK_SENTINEL_SHARED_KEY")
        if wid and key:
            return cls(workspace_id=wid, shared_key=key)
        return None


# ── Elastic connector ─────────────────────────────────────────────────────────

class ElasticConnector(SIEMConnector):
    """Sends events to Elasticsearch."""

    def __init__(self, url: str, index: str = "vaultak-events",
                 api_key: str = None, username: str = None,
                 password: str = None):
        super().__init__("elastic")
        self.url      = url.rstrip("/")
        self.index    = index
        self.api_key  = api_key
        self.username = username
        self.password = password

    def send(self, event: dict) -> bool:
        if not HAS_REQUESTS or not self.enabled:
            return False
        try:
            headers = {"Content-Type": "application/json"}
            if self.api_key:
                headers["Authorization"] = f"ApiKey {self.api_key}"

            auth = None
            if self.username and self.password:
                auth = (self.username, self.password)

            r = requests.post(
                f"{self.url}/{self.index}/_doc",
                headers=headers,
                json=event,
                auth=auth,
                timeout=5,
            )
            success = r.status_code in (200, 201)
            if success:
                self._sent += 1
            else:
                self._errors += 1
            return success
        except Exception as e:
            self._errors += 1
            logger.error(f"Elastic send error: {e}")
            return False

    @classmethod
    def from_env(cls) -> Optional["ElasticConnector"]:
        url = os.environ.get("VAULTAK_ELASTIC_URL")
        if url:
            return cls(url=url,
                       api_key=os.environ.get("VAULTAK_ELASTIC_API_KEY"))
        return None


# ── Generic webhook connector ─────────────────────────────────────────────────

class WebhookConnector(SIEMConnector):
    """
    Generic webhook connector for any SIEM or custom endpoint.
    Supports HMAC signature for verification.
    """

    def __init__(self, url: str, secret: str = None,
                 headers: dict = None, method: str = "POST"):
        super().__init__("webhook")
        self.url     = url
        self.secret  = secret
        self.headers = headers or {"Content-Type": "application/json"}
        self.method  = method

    def send(self, event: dict) -> bool:
        if not HAS_REQUESTS or not self.enabled:
            return False
        try:
            body = json.dumps(event).encode()
            hdrs = dict(self.headers)

            if self.secret:
                sig = hmac.new(
                    self.secret.encode(),
                    body,
                    hashlib.sha256
                ).hexdigest()
                hdrs["X-Vaultak-Signature"] = f"sha256={sig}"

            r = requests.request(
                method=self.method,
                url=self.url,
                headers=hdrs,
                data=body,
                timeout=5,
            )
            success = 200 <= r.status_code < 300
            if success:
                self._sent += 1
            else:
                self._errors += 1
            return success
        except Exception as e:
            self._errors += 1
            logger.error(f"Webhook send error: {e}")
            return False

    @classmethod
    def from_env(cls) -> Optional["WebhookConnector"]:
        url = os.environ.get("VAULTAK_WEBHOOK_URL")
        if url:
            return cls(url=url,
                       secret=os.environ.get("VAULTAK_WEBHOOK_SECRET"))
        return None


# ── Slack connector ───────────────────────────────────────────────────────────

class SlackConnector(SIEMConnector):
    """Sends high-severity alerts to Slack."""

    def __init__(self, webhook_url: str,
                 min_severity: str = "high",
                 channel: str = None):
        super().__init__("slack")
        self.webhook_url  = webhook_url
        self.min_severity = min_severity
        self.channel      = channel
        self._severities  = ["info", "low", "medium", "high", "critical"]

    def send(self, event: dict) -> bool:
        if not HAS_REQUESTS or not self.enabled:
            return False

        severity = event.get("severity", "info")
        min_idx  = self._severities.index(self.min_severity)
        evt_idx  = self._severities.index(severity) if severity in self._severities else 0

        if evt_idx < min_idx:
            return True  # Skip below threshold

        try:
            color = {
                "critical": "#f87171",
                "high":     "#fb923c",
                "medium":   "#fbbf24",
                "low":      "#a3e635",
                "info":     "#94a3b8",
            }.get(severity, "#94a3b8")

            blocks = [
                {
                    "type": "header",
                    "text": {
                        "type":  "plain_text",
                        "text":  f"Vaultak Alert: {severity.upper()}",
                    }
                },
                {
                    "type": "section",
                    "fields": [
                        {"type": "mrkdwn", "text": f"*Agent:*\n{event.get('agent_id', 'unknown')}"},
                        {"type": "mrkdwn", "text": f"*Action:*\n{event.get('action_type', 'unknown')}"},
                        {"type": "mrkdwn", "text": f"*Resource:*\n{event.get('resource', 'unknown')}"},
                        {"type": "mrkdwn", "text": f"*Risk Score:*\n{event.get('risk_score', 0):.2f}"},
                        {"type": "mrkdwn", "text": f"*Decision:*\n{event.get('decision', 'unknown').upper()}"},
                        {"type": "mrkdwn", "text": f"*Reason:*\n{event.get('reason', 'N/A')}"},
                    ]
                },
                {
                    "type": "actions",
                    "elements": [
                        {
                            "type":  "button",
                            "text":  {"type": "plain_text", "text": "View in Dashboard"},
                            "url":   "https://app.vaultak.com",
                            "style": "primary",
                        }
                    ]
                }
            ]

            payload = {"attachments": [{"color": color, "blocks": blocks}]}
            if self.channel:
                payload["channel"] = self.channel

            r = requests.post(
                self.webhook_url, json=payload, timeout=5)
            success = r.status_code == 200
            if success:
                self._sent += 1
            else:
                self._errors += 1
            return success
        except Exception as e:
            self._errors += 1
            logger.error(f"Slack send error: {e}")
            return False

    @classmethod
    def from_env(cls) -> Optional["SlackConnector"]:
        url = os.environ.get("VAULTAK_SLACK_WEBHOOK")
        if url:
            return cls(webhook_url=url)
        return None


# ── PagerDuty connector ───────────────────────────────────────────────────────

class PagerDutyConnector(SIEMConnector):
    """Creates PagerDuty incidents for critical violations."""

    def __init__(self, integration_key: str,
                 min_severity: str = "critical"):
        super().__init__("pagerduty")
        self.integration_key = integration_key
        self.min_severity    = min_severity
        self._severities     = ["info", "low", "medium", "high", "critical"]

    def send(self, event: dict) -> bool:
        if not HAS_REQUESTS or not self.enabled:
            return False

        severity = event.get("severity", "info")
        min_idx  = self._severities.index(self.min_severity)
        evt_idx  = self._severities.index(severity) if severity in self._severities else 0

        if evt_idx < min_idx:
            return True

        try:
            pd_severity = {
                "critical": "critical",
                "high":     "error",
                "medium":   "warning",
                "low":      "info",
                "info":     "info",
            }.get(severity, "warning")

            payload = {
                "routing_key":  self.integration_key,
                "event_action": "trigger",
                "dedup_key":    hashlib.sha256(
                    f"{event.get('agent_id')}{event.get('resource')}{event.get('timestamp')}".encode()
                ).hexdigest()[:32],
                "payload": {
                    "summary":   (
                        f"Vaultak: {event.get('action_type', 'violation')} "
                        f"on {event.get('resource', 'unknown')} "
                        f"(risk: {event.get('risk_score', 0):.2f})"
                    ),
                    "severity":  pd_severity,
                    "source":    "vaultak",
                    "timestamp": event.get("timestamp"),
                    "custom_details": event,
                },
                "links": [
                    {"href": "https://app.vaultak.com",
                     "text": "View in Vaultak Dashboard"}
                ],
            }

            r = requests.post(
                "https://events.pagerduty.com/v2/enqueue",
                json=payload,
                timeout=5,
            )
            success = r.status_code in (200, 202)
            if success:
                self._sent += 1
            else:
                self._errors += 1
            return success
        except Exception as e:
            self._errors += 1
            logger.error(f"PagerDuty send error: {e}")
            return False

    @classmethod
    def from_env(cls) -> Optional["PagerDutyConnector"]:
        key = os.environ.get("VAULTAK_PAGERDUTY_KEY")
        if key:
            return cls(integration_key=key)
        return None


# ── SIEM Router ───────────────────────────────────────────────────────────────

class SIEMRouter:
    """
    Routes Vaultak events to one or more SIEM connectors.
    Automatically builds from environment variables.
    Sends asynchronously to avoid blocking agent execution.

    Usage:
        router = SIEMRouter.from_env()
        router.route(event)

    Or add connectors manually:
        router = SIEMRouter()
        router.add(SplunkConnector(url="...", token="..."))
        router.add(SlackConnector(webhook_url="..."))
        router.route(event)
    """

    def __init__(self, async_send: bool = True):
        self.connectors  = []
        self.async_send  = async_send
        self._queue      = queue.Queue(maxsize=1000)
        self._worker     = None

        if async_send:
            self._start_worker()

    def add(self, connector: SIEMConnector):
        self.connectors.append(connector)
        logger.info(f"SIEM connector added: {connector.name}")

    def route(self, raw_event: dict):
        """Normalize and route an event to all connectors."""
        if not self.connectors:
            return

        event = normalize_event(raw_event)

        if self.async_send:
            try:
                self._queue.put_nowait(event)
            except queue.Full:
                logger.warning("SIEM queue full, dropping event")
        else:
            self._send_to_all(event)

    def _send_to_all(self, event: dict):
        for connector in self.connectors:
            if connector.enabled:
                try:
                    connector.send(event)
                except Exception as e:
                    logger.error(f"Error sending to {connector.name}: {e}")

    def _start_worker(self):
        self._worker = threading.Thread(
            target=self._worker_loop, daemon=True)
        self._worker.start()

    def _worker_loop(self):
        while True:
            try:
                event = self._queue.get(timeout=1)
                self._send_to_all(event)
                self._queue.task_done()
            except queue.Empty:
                continue
            except Exception as e:
                logger.error(f"SIEM worker error: {e}")

    def stats(self) -> dict:
        return {
            "connectors":  [c.stats() for c in self.connectors],
            "queue_size":  self._queue.qsize(),
        }

    @classmethod
    def from_env(cls) -> "SIEMRouter":
        """Auto-configure from environment variables."""
        router = cls()

        for connector_cls in [
            SplunkConnector,
            DatadogConnector,
            SentinelConnector,
            ElasticConnector,
            WebhookConnector,
            SlackConnector,
            PagerDutyConnector,
        ]:
            connector = connector_cls.from_env()
            if connector:
                router.add(connector)

        if router.connectors:
            logger.info(f"SIEM router initialized with "
                        f"{len(router.connectors)} connector(s)")
        return router


# ── Backend integration helper ────────────────────────────────────────────────

# Global router instance for use in main.py
_router: Optional[SIEMRouter] = None

def get_router() -> SIEMRouter:
    global _router
    if _router is None:
        _router = SIEMRouter.from_env()
    return _router

def emit(event: dict):
    """Emit a Vaultak event to all configured SIEM connectors."""
    get_router().route(event)


if __name__ == "__main__":
    # Quick test with a mock event
    import sys
    event = {
        "agent_id":    "test-agent",
        "action_type": "file_delete",
        "resource":    "prod.env",
        "risk_score":  0.91,
        "decision":    "block",
        "reason":      "Matches blocked pattern: *.env",
        "mode":        "rollback",
        "rolled_back": True,
        "timestamp":   datetime.now(timezone.utc).isoformat(),
    }
    normalized = normalize_event(event)
    print(json.dumps(normalized, indent=2))
