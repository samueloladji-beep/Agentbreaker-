# Vaultak Sentry

**Zero-code runtime security for AI agents.**

Vaultak Sentry monitors any AI agent at the OS level without requiring code changes. Install once, run any agent through Sentry, and get full behavioral monitoring, policy enforcement, and automatic violation response visible in your Vaultak dashboard.

Part of the Vaultak platform:
- **Vaultak Core** (`pip install vaultak`): SDK for developers who want deep code-level integration
- **Vaultak Sentry** (`pip install vaultak-sentry`): Daemon for teams governing existing agents without code changes

## Installation

```bash
pip install vaultak-sentry
```

## Quick Start

```bash
# Authenticate
vaultak-sentry auth --api-key vtk_your_key_here

# List available policy templates
vaultak-sentry policy list

# Create a policy for your agent
vaultak-sentry policy create --agent-id my-agent --template data-pipeline

# Run any agent with zero code changes
vaultak-sentry run --name my-agent python my_langchain_agent.py
vaultak-sentry run --name my-agent node my_agent.js

# Attach to an already running process
vaultak-sentry attach 12345 --name my-agent

# Check status
vaultak-sentry status
```

## Policy Templates

| Template | Description |
|---|---|
| data-pipeline | Read-only data processing agent |
| coding-agent | Software engineering agent with code execution |
| customer-support | Customer support agent with CRM access |
| research-agent | Web research agent with broad read access |
| hipaa-agent | HIPAA-compliant healthcare agent |
| strict | Maximum restriction policy |

## Response Modes

| Mode | Behavior |
|---|---|
| alert | Log violations and notify dashboard. Agent keeps running. |
| pause | Stop the agent immediately on violation. |
| rollback | Attempt to reverse recent actions then stop the agent. |

## What Sentry Monitors

- File system access (reads, writes, deletes)
- Network connections (outbound and inbound)
- Child process spawning
- CPU and memory spikes
- Database connections via port detection

## Advanced Usage

```bash
# Strict mode with custom blocked resources
vaultak-sentry run \
  --mode rollback \
  --block "prod.*" "*.env" "*.key" \
  --max-risk 0.7 \
  --name my-production-agent \
  python agent.py

# Disable specific monitors
vaultak-sentry run --no-net --no-proc python agent.py

# Custom policy inline
vaultak-sentry run \
  --allow "/data/readonly/**" "/tmp/**" \
  --block "*.env" "prod.*" \
  --allow-hosts "api.openai.com" \
  python agent.py
```

## Links

- Website: https://vaultak.com
- Dashboard: https://app.vaultak.com
- Docs: https://docs.vaultak.com
