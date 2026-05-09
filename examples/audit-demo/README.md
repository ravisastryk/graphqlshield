# audit-demo

Demonstrates **Layer 3** of GraphQLShield: static resolver code auditing.

`resolvers/insecure.go` is intentionally vulnerable. Run the auditor and watch it find every issue.

## Run

```bash
go mod tidy && go run main.go
```

### Expected output

```
── Built-in scanner ────────────────────────────────
⚠   graphqlshield audit: 4 issue(s)

1. [CWE-798] CRITICAL — Hardcoded password literal detected
   resolvers/insecure.go:14

2. [CWE-798] CRITICAL — Hardcoded secret literal detected
   resolvers/insecure.go:15

3. [CWE-327] HIGH — MD5 is cryptographically broken — use SHA-256 or bcrypt/argon2
   resolvers/insecure.go:20

4. [CWE-327] HIGH — SHA-1 is deprecated for security use — use SHA-256
   resolvers/insecure.go:27
```

## Deeper analysis with cryptoguard-go

```bash
go install github.com/ravisastryk/cryptoguard-go/cmd/cryptoguard@latest
go run main.go
```

cryptoguard-go adds AST taint tracking, cross-function IV reuse detection, and post-quantum readiness scanning on top of the built-in rules.

## Use as a CI gate

```bash
# exits 2 on CRITICAL findings → fails the pipeline
go run main.go
```
