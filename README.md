# Vaultak

**Runtime security and behavioral monitoring for AI agents.**

Vaultak is the control layer for AI agents in production. Monitor every action, enforce permission boundaries, and automatically pause or roll back agents before damage is done.

## Install

```bash
pip install vaultak
```

## Quick Start

```python
from vaultak import Vaultak

vt = Vaultak(api_key="vtk_...")

with vt.monitor("my-agent"):
    # your agent code here
    pass
```

## Products

- **Vaultak Core** — SDK, 5 lines of code, deep integration
- **Vaultak Sentry** — Desktop app, zero code changes, any language

## Links

- Website: https://vaultak.com
- Dashboard: https://app.vaultak.com
- Docs: https://docs.vaultak.com
- PyPI: https://pypi.org/project/vaultak

## License

MIT
