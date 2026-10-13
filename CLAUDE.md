# enforcer-go

Go client library for applications that use [Attesta](https://github.com/threehook/attesta) for authorization. Module: `github.com/threehook/enforcer-go`.

## Conventions

- **This is a library, not a program.** The root package is `package enforcer`. Do not add a `main.go` or `package main` to the root: it would make the module unimportable. Runnable demos go under `examples/<name>/main.go`, and any CLI under `cmd/<name>/`.
- **Never use the word "sidecar"** in code, comments, tests, docs or release notes. The deployment architecture may change. Refer to "Attesta" (or "the server" in tests).
- **Comments: only when a functional explanation is needed.** No comments that restate the name or the code, no doc comments for the sake of it, no narration. A comment must say something the code cannot: a non-obvious behavior, constraint or reason.
- Wire format is lowerCamel JSON (`attributeId`, `attributeAssignments`), not the XACML JSON profile casing. Attesta is the only PDP this client talks to.
- Keep the public API small. The library is 0.x, so the API may still change before 1.0.
- Standard library only, unless there is a strong reason otherwise.

## Checks

Run before committing: `gofmt -l .`, `go vet ./...`, `go test ./...`.

## Git

- Do not commit `.idea/` (GoLand); it is in `.gitignore`.
- Do not push, tag or release without being asked.
