package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"time"

	"github.com/threehook/enforcer-go"
)

func main() {
	base := flag.String("attesta", "http://127.0.0.1:8080", "base URL of Attesta")
	resource := flag.String("resource", "resource", "resource to authorize")
	policy := flag.String("policy", "policy-id", "policy ID")
	credType := flag.String("type", "CredentialType", "credential type to ask for")
	claims := flag.String("claims", "department", "comma-separated claims to ask for")
	roles := flag.String("roles", "", "comma-separated roles of the caller")
	flag.Parse()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	c := enforcer.New(*base)
	req, err := c.Start(ctx, enforcer.Authorization{
		Resource:    *resource,
		PolicyID:    *policy,
		Credentials: []enforcer.Credential{{Type: *credType, Claims: split(*claims)}},
		UserRoles:   split(*roles),
	})
	if err != nil {
		log.Fatalf("start: %v", err)
	}
	fmt.Printf("Open this link in your wallet:\n%s\n(request %s, trace %s)\n", req.Link, req.RequestID, req.TraceID)

	for {
		out, _, err := c.Outcome(ctx, req.RequestID)
		switch {
		case errors.Is(err, enforcer.ErrUnknownRequest):
			log.Fatal("request expired or unknown to Attesta")
		case err != nil:
			log.Fatalf("outcome: %v", err)
		case out.Status == "done":
			if out.Decision != enforcer.DecisionPermit {
				fmt.Printf("%s: %s\n", out.Decision, out.Reason)
				os.Exit(1)
			}
			if out.Subject != nil {
				fmt.Printf("allowed for %s (issuer %s)\n", out.Subject.Email, out.Subject.Issuer)
			} else {
				fmt.Println("allowed")
			}
			return
		}
		select {
		case <-ctx.Done():
			log.Fatal("interrupted")
		case <-time.After(2 * time.Second):
		}
	}
}

func split(s string) []string {
	if s == "" {
		return nil
	}
	return strings.Split(s, ",")
}
