# Vaultak Go SDK

Runtime security for autonomous AI agents.

## Install

```bash
go get github.com/samueloladji-beep/vaultak-go
```

## Usage

```go
import vaultak "github.com/samueloladji-beep/vaultak-go"

vt := vaultak.New("vtk_your_key",
    vaultak.WithAgentID("my-agent"),
    vaultak.WithBlockedResources([]string{"*.env", "prod.*"}),
)

// Monitored file write with automatic rollback
err := vt.WriteFile("/tmp/output.txt", data, 0644)

// Manual interception
decision, err := vt.Intercept("api_call", "https://api.example.com", nil)
if err != nil {
    // blocked or paused
}
```

## Thresholds

```go
vt := vaultak.New("vtk_your_key",
    vaultak.WithAlertThreshold(30),
    vaultak.WithPauseThreshold(60),
    vaultak.WithRollbackThreshold(85),
)
```
