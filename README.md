# enforcer-go

Go library for applications that use [Attesta](https://github.com/threehook/attesta) for authorization. It talks to Attesta on behalf of the
application: start an authorization, hand the wallet link to the user, read the decision.

```go
c := enforcer.New("http://127.0.0.1:8080")
req, err := c.Start(ctx, enforcer.Authorization{
	Resource: "resource",
	PolicyID: "policy-id",
	Credentials: []enforcer.Credential{
		{Type: "Employee", Claims: []string{"department", "roles"}},
		{Type: "Certificate", Claims: []string{"course"}}, // optional: more credentials of the same person
	},
})
// show req.Link to the user, then poll:
out, _, err := c.Outcome(ctx, req.RequestID)
if err == nil && out.Decision == enforcer.DecisionPermit {
	// carry out the action for out.Subject
}
```

`Outcome` returns `ErrUnknownRequest` when Attesta no longer knows the request (expired, or Attesta restarted).

MIT license.
