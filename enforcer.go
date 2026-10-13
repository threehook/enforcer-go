// Package enforcer lets an application ask an Attesta sidecar for an authorization and read the decision.
package enforcer

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// ErrUnknownRequest means the sidecar no longer knows the request: it expired, or the sidecar restarted.
var ErrUnknownRequest = errors.New("unknown or expired request")

// Request is an authorization the sidecar has started.
type Request struct {
	RequestID string `json:"requestId"`
	// Link is the openid4vp:// link the employee opens in their wallet.
	Link string `json:"authorizationRequest"`
	// TraceID is the trace the client started for the request; Attesta's decision log carries it.
	TraceID string `json:"-"`
}

// Subject identifies the person a decision is about: issuer DID and email.
type Subject struct {
	Issuer string `json:"issuer"`
	Email  string `json:"email"`
}

// Outcome is the sidecar's answer to a request: pending until the wallet has answered, then done with the decision.
type Outcome struct {
	Status  string   `json:"status"`
	Allow   bool     `json:"allow"`
	Reason  string   `json:"reason"`
	Subject *Subject `json:"subject"`
}

// Client talks to the sidecar next to the application.
type Client struct {
	base string
	http *http.Client
}

func New(base string) *Client {
	return &Client{base: base, http: &http.Client{Timeout: 10 * time.Second}}
}

// Start asks the sidecar to start an authorization. userRoles are sent along as the caller's claim about the person.
func (c *Client) Start(ctx context.Context, resource, policyID, credentialType string, claims, userRoles []string) (Request, error) {
	body, err := json.Marshal(map[string]any{"resource": resource, "policyId": policyID, "credentialType": credentialType, "claims": claims})
	if err != nil {
		return Request{}, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.base+"/v1/authorize/requests", bytes.NewReader(body))
	if err != nil {
		return Request{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	traceID, spanID := randomHex(16), randomHex(8)
	req.Header.Set("traceparent", "00-"+traceID+"-"+spanID+"-01")
	if len(userRoles) > 0 {
		req.Header.Set("Att-User-Roles", strings.Join(userRoles, ","))
	}
	raw, status, err := c.do(req)
	if err != nil {
		return Request{}, err
	}
	if status != http.StatusOK {
		return Request{}, fmt.Errorf("Attesta answered %d: %s", status, bytes.TrimSpace(raw))
	}
	var out Request
	if err := json.Unmarshal(raw, &out); err != nil || out.RequestID == "" || out.Link == "" {
		return Request{}, fmt.Errorf("Attesta sent an unusable answer: %s", raw)
	}
	out.TraceID = traceID
	return out, nil
}

// randomHex returns n random bytes as lowercase hex.
func randomHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// Outcome reads the decision, and the sidecar's answer as it came. ErrUnknownRequest means the sidecar no longer knows the request.
func (c *Client) Outcome(ctx context.Context, id string) (Outcome, json.RawMessage, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.base+"/v1/authorize/requests/"+id, nil)
	if err != nil {
		return Outcome{}, nil, err
	}
	raw, status, err := c.do(req)
	if err != nil {
		return Outcome{}, nil, err
	}
	switch status {
	case http.StatusOK:
	case http.StatusNotFound:
		return Outcome{}, nil, ErrUnknownRequest
	default:
		return Outcome{}, nil, fmt.Errorf("Attesta answered %d: %s", status, bytes.TrimSpace(raw))
	}
	var out Outcome
	if err := json.Unmarshal(raw, &out); err != nil {
		return Outcome{}, nil, fmt.Errorf("Attesta sent an unusable answer: %s", raw)
	}
	return out, raw, nil
}

func (c *Client) do(req *http.Request) ([]byte, int, error) {
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return raw, resp.StatusCode, err
}
