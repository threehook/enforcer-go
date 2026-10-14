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

// ErrUnknownRequest means the request expired or Attesta restarted.
var ErrUnknownRequest = errors.New("unknown or expired request")

type Request struct {
	RequestID string `json:"requestId"`
	Link      string `json:"authorizationRequest"`
	// TraceID is also in Attesta's decision log.
	TraceID string `json:"-"`
}

type Subject struct {
	Issuer string `json:"issuer"`
	Email  string `json:"email"`
}

type Decision string

const (
	DecisionPermit Decision = "Permit"

	DecisionDeny Decision = "Deny"

	// DecisionNotApplicable means no policy matches the resource, action or subject.
	DecisionNotApplicable Decision = "NotApplicable"

	// DecisionIndeterminate means evaluation failed or attributes were missing.
	DecisionIndeterminate Decision = "Indeterminate"
)

type Outcome struct {
	Status   string   `json:"status"`
	Decision Decision `json:"decision"`
	Reason   string   `json:"reason"`
	Subject  *Subject `json:"subject"`
	// Obligations must be carried out together with the decision; if one cannot be, the application must not grant access.
	Obligations []Obligation `json:"obligations"`
	// Advice may be ignored without changing the decision.
	Advice []Advice `json:"advice"`
}

// AttributeAssignment is a named value that an Obligation or Advice hands to the application.
type AttributeAssignment struct {
	AttributeID string `json:"attributeId"`
	Category    string `json:"category,omitempty"`
	// DataType is an XACML data type URI; empty means string.
	DataType string `json:"dataType,omitempty"`
	Issuer   string `json:"issuer,omitempty"`
	Value    any    `json:"value"`
}

type Obligation struct {
	ID                   string                `json:"id"`
	AttributeAssignments []AttributeAssignment `json:"attributeAssignments"`
}

type Advice struct {
	ID                   string                `json:"id"`
	AttributeAssignments []AttributeAssignment `json:"attributeAssignments"`
}

type Client struct {
	base string
	http *http.Client
}

func New(base string) *Client {
	return &Client{base: base, http: &http.Client{Timeout: 10 * time.Second}}
}

// Credential is a credential the person is asked to present.
type Credential struct {
	Type   string   `json:"credentialType"`
	Claims []string `json:"claims"`
}

// Authorization is what an application asks Attesta to decide.
type Authorization struct {
	Resource string
	PolicyID string
	// Credentials are what the person must present, each of a type of its own. The first identifies the person and the others must be of the same person.
	Credentials []Credential
	// UserRoles are the application's own claim about the person.
	UserRoles []string
}

// Start asks Attesta to decide on the authorization. The policy has to be one that accepts as many credentials as are asked for.
func (c *Client) Start(ctx context.Context, a Authorization) (Request, error) {
	body, err := json.Marshal(map[string]any{"resource": a.Resource, "policyId": a.PolicyID, "credentials": a.Credentials})
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
	if len(a.UserRoles) > 0 {
		req.Header.Set("Att-User-Roles", strings.Join(a.UserRoles, ","))
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

func randomHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// Outcome also returns Attesta's answer unparsed.
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
