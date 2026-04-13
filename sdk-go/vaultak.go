package vaultak

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
)

const (
	DefaultAlertThreshold    = 30
	DefaultPauseThreshold    = 60
	DefaultRollbackThreshold = 85
	DefaultAPIEndpoint       = "https://vaultak.com"
)

// Client is the Vaultak SDK client for Go agents.
type Client struct {
	APIKey             string
	AgentID            string
	AlertThreshold     int
	PauseThreshold     int
	RollbackThreshold  int
	BlockedResources   []string
	AllowedResources   []string
	MaxActionsPerMin   int
	APIEndpoint        string

	sessionID     string
	actionTimes   []time.Time
	fileSnapshots map[string][]byte
	paused        bool
	mu            sync.Mutex
}

// ActionEvent represents a logged agent action.
type ActionEvent struct {
	AgentID    string                 `json:"agent_id"`
	SessionID  string                 `json:"session_id"`
	ActionType string                 `json:"action_type"`
	Resource   string                 `json:"resource"`
	Payload    map[string]interface{} `json:"payload"`
	RiskScore  float64                `json:"risk_score"`
	Decision   string                 `json:"decision"`
	Timestamp  string                 `json:"timestamp"`
	Source     string                 `json:"source"`
}

// New creates a new Vaultak client.
func New(apiKey string, opts ...Option) *Client {
	c := &Client{
		APIKey:            apiKey,
		AgentID:           getEnv("VAULTAK_AGENT_ID", "default"),
		AlertThreshold:    DefaultAlertThreshold,
		PauseThreshold:    DefaultPauseThreshold,
		RollbackThreshold: DefaultRollbackThreshold,
		MaxActionsPerMin:  60,
		APIEndpoint:       getEnv("VAULTAK_API_ENDPOINT", DefaultAPIEndpoint),
		sessionID:         uuid.New().String(),
		fileSnapshots:     make(map[string][]byte),
	}
	if apiKey == "" {
		c.APIKey = getEnv("VAULTAK_API_KEY", "")
	}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

// Option is a functional option for configuring the client.
type Option func(*Client)

func WithAgentID(id string) Option        { return func(c *Client) { c.AgentID = id } }
func WithAlertThreshold(t int) Option     { return func(c *Client) { c.AlertThreshold = t } }
func WithPauseThreshold(t int) Option     { return func(c *Client) { c.PauseThreshold = t } }
func WithRollbackThreshold(t int) Option  { return func(c *Client) { c.RollbackThreshold = t } }
func WithBlockedResources(r []string) Option { return func(c *Client) { c.BlockedResources = r } }
func WithAllowedResources(r []string) Option { return func(c *Client) { c.AllowedResources = r } }

// Intercept evaluates an action and returns the decision.
// Call this before performing any significant agent action.
func (c *Client) Intercept(actionType, resource string, payload map[string]interface{}) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.paused {
		return "BLOCK", fmt.Errorf("agent is paused awaiting review")
	}

	// Rate limiting
	now := time.Now()
	var recent []time.Time
	for _, t := range c.actionTimes {
		if now.Sub(t) < time.Minute {
			recent = append(recent, t)
		}
	}
	c.actionTimes = recent
	if len(recent) >= c.MaxActionsPerMin {
		c.sendAction(actionType, resource, payload, 90, "BLOCK")
		return "BLOCK", fmt.Errorf("rate limit exceeded")
	}

	// Policy checks
	for _, pattern := range c.BlockedResources {
		if matchPattern(resource, pattern) {
			c.sendAction(actionType, resource, payload, 95, "BLOCK")
			return "BLOCK", fmt.Errorf("resource blocked by policy: %s", resource)
		}
	}

	if len(c.AllowedResources) > 0 {
		allowed := false
		for _, pattern := range c.AllowedResources {
			if matchPattern(resource, pattern) {
				allowed = true
				break
			}
		}
		if !allowed {
			c.sendAction(actionType, resource, payload, 80, "BLOCK")
			return "BLOCK", fmt.Errorf("resource not in allowlist: %s", resource)
		}
	}

	score := c.computeScore(actionType, resource)

	if score >= c.RollbackThreshold {
		c.sendAction(actionType, resource, payload, score, "ROLLBACK")
		c.executeRollback()
		c.paused = true
		return "ROLLBACK", fmt.Errorf("risk score %d exceeded rollback threshold — state restored", score)
	} else if score >= c.PauseThreshold {
		c.sendAction(actionType, resource, payload, score, "PAUSE")
		c.paused = true
		return "PAUSE", fmt.Errorf("risk score %d exceeded pause threshold — awaiting review", score)
	} else if score >= c.AlertThreshold {
		c.sendAction(actionType, resource, payload, score, "ALERT")
	} else {
		c.sendAction(actionType, resource, payload, score, "ALLOW")
	}

	c.actionTimes = append(c.actionTimes, now)
	return "ALLOW", nil
}

// SnapshotFile saves the current state of a file for potential rollback.
func (c *Client) SnapshotFile(path string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	data, err := os.ReadFile(path)
	if err != nil {
		c.fileSnapshots[path] = nil // file did not exist
		return
	}
	c.fileSnapshots[path] = data
}

// WriteFile is a monitored replacement for os.WriteFile.
func (c *Client) WriteFile(path string, data []byte, perm os.FileMode) error {
	c.SnapshotFile(path)
	decision, err := c.Intercept("file_write", path, map[string]interface{}{"size": len(data)})
	if decision == "BLOCK" || decision == "ROLLBACK" || decision == "PAUSE" {
		return err
	}
	return os.WriteFile(path, data, perm)
}

// RemoveFile is a monitored replacement for os.Remove.
func (c *Client) RemoveFile(path string) error {
	decision, err := c.Intercept("delete", path, nil)
	if decision == "BLOCK" || decision == "ROLLBACK" || decision == "PAUSE" {
		return err
	}
	return os.Remove(path)
}

// LogAction manually logs an action to the dashboard.
func (c *Client) LogAction(actionType, resource string, payload map[string]interface{}) {
	c.sendAction(actionType, resource, payload, 0, "ALLOW")
}

// Approve resumes a paused agent.
func (c *Client) Approve() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.paused = false
}

func (c *Client) computeScore(actionType, resource string) int {
	scores := map[string]int{
		"file_write": 40, "file_read": 10, "delete": 75,
		"api_call": 35, "execute": 60, "database_write": 50,
		"database_read": 15,
	}
	score := 30
	if s, ok := scores[actionType]; ok {
		score = s
	}
	sensitive := []string{"prod", "production", "secret", ".env", "password", "key", "token", "credential"}
	for _, p := range sensitive {
		if strings.Contains(strings.ToLower(resource), p) {
			score += 30
			break
		}
	}
	if score > 100 {
		return 100
	}
	return score
}

func (c *Client) executeRollback() {
	for path, data := range c.fileSnapshots {
		if data == nil {
			os.Remove(path)
		} else {
			os.WriteFile(path, data, 0644)
		}
		fmt.Fprintf(os.Stderr, "[Vaultak] Rolled back: %s\n", path)
	}
	c.fileSnapshots = make(map[string][]byte)
}

func (c *Client) sendAction(actionType, resource string, payload map[string]interface{}, score int, decision string) {
	event := ActionEvent{
		AgentID:    c.AgentID,
		SessionID:  c.sessionID,
		ActionType: actionType,
		Resource:   resource,
		Payload:    payload,
		RiskScore:  float64(score) / 100.0,
		Decision:   decision,
		Timestamp:  time.Now().UTC().Format(time.RFC3339),
		Source:     "go-sdk",
	}
	go func() {
		data, err := json.Marshal(event)
		if err != nil {
			return
		}
		req, err := http.NewRequest("POST", c.APIEndpoint+"/api/actions", bytes.NewReader(data))
		if err != nil {
			return
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("x-api-key", c.APIKey)
		client := &http.Client{Timeout: 3 * time.Second}
		resp, err := client.Do(req)
		if err != nil {
			return
		}
		defer resp.Body.Close()
	}()
}

func matchPattern(resource, pattern string) bool {
	if strings.Contains(pattern, "*") {
		matched, _ := filepath.Match(pattern, resource)
		if matched {
			return true
		}
		base := strings.ReplaceAll(pattern, "*", "")
		return strings.Contains(resource, base)
	}
	return strings.Contains(resource, pattern)
}

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
