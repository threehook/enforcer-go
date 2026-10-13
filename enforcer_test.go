package enforcer

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestClientStartsARequest(t *testing.T) {
	var gotBody map[string]any
	var gotRoles, gotTraceparent string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotRoles = r.Header.Get("Att-User-Roles")
		gotTraceparent = r.Header.Get("traceparent")
		if r.Method != "POST" || r.URL.Path != "/v1/authorize/requests" {
			t.Errorf("server got %s %s", r.Method, r.URL.Path)
		}
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		_, _ = w.Write([]byte(`{"requestId":"abc","authorizationRequest":"openid4vp://?y=2"}`))
	}))
	defer server.Close()

	got, err := New(server.URL).Start(context.Background(), "res", "pol", "Type", []string{"department", "diploma"}, []string{"a", "b"})
	if err != nil || got.RequestID != "abc" || got.Link != "openid4vp://?y=2" {
		t.Fatalf("start = %+v, %v", got, err)
	}
	if gotBody["resource"] != "res" || gotBody["policyId"] != "pol" || gotBody["credentialType"] != "Type" ||
		strings.Join(toStrings(gotBody["claims"]), ",") != "department,diploma" {
		t.Errorf("server got body %v", gotBody)
	}
	if want := "00-" + got.TraceID + "-"; !strings.HasPrefix(gotTraceparent, want) || len(gotTraceparent) != len(want)+16+3 || len(got.TraceID) != 32 {
		t.Errorf("server got traceparent %q for trace %q, want a fresh W3C trace context", gotTraceparent, got.TraceID)
	}
	if gotRoles != "a,b" {
		t.Errorf("server got Att-User-Roles %q, want a,b", gotRoles)
	}
}

func TestClientStartFailures(t *testing.T) {
	for name, handler := range map[string]http.HandlerFunc{
		"server error": func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, `{"error":"unknown policy"}`, http.StatusNotFound)
		},
		"empty answer": func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(`{}`)) },
		"not json":     func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(`oops`)) },
	} {
		t.Run(name, func(t *testing.T) {
			server := httptest.NewServer(handler)
			defer server.Close()
			if _, err := New(server.URL).Start(context.Background(), "r", "p", "t", nil, nil); err == nil {
				t.Error("want an error")
			}
		})
	}

	if _, err := New("http://127.0.0.1:1").Start(context.Background(), "r", "p", "t", nil, nil); err == nil {
		t.Error("server not running: want an error")
	}
}

func TestClientReadsTheOutcome(t *testing.T) {
	const answer = `{"status":"done","decision":"Permit","reason":"Geautoriseerd","subject":{"issuer":"did:key:g","email":"jerry@example.com"}}`
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/authorize/requests/abc":
			_, _ = w.Write([]byte(answer))
		case "/v1/authorize/requests/gone":
			http.Error(w, "unknown or expired request", http.StatusNotFound)
		default:
			http.Error(w, "boom", http.StatusInternalServerError)
		}
	}))
	defer server.Close()
	c := New(server.URL)

	got, raw, err := c.Outcome(context.Background(), "abc")
	if err != nil || got.Status != "done" || got.Decision != DecisionPermit || got.Subject == nil || got.Subject.Email != "jerry@example.com" || string(raw) != answer {
		t.Errorf("outcome = %+v, %s, %v", got, raw, err)
	}
	if _, _, err := c.Outcome(context.Background(), "gone"); !errors.Is(err, ErrUnknownRequest) {
		t.Errorf("unknown request: error = %v, want ErrUnknownRequest", err)
	}
	if _, _, err := c.Outcome(context.Background(), "other"); err == nil || errors.Is(err, ErrUnknownRequest) {
		t.Errorf("server error: error = %v, want a plain error", err)
	}
}

func toStrings(v any) []string {
	var out []string
	for _, e := range v.([]any) {
		out = append(out, e.(string))
	}
	return out
}
