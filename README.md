# GraphQLShield

> **CWE-aware defence-in-depth middleware for Go GraphQL APIs.**  
> Wraps any [`gqlgen`](https://github.com/99designs/gqlgen) handler in **one line**.

[![Go Reference](https://pkg.go.dev/badge/github.com/ravisastryk/graphqlshield.svg)](https://pkg.go.dev/github.com/ravisastryk/graphqlshield)
[![Go 1.26](https://img.shields.io/badge/go-1.26.2-00acd7.svg?style=flat-square)](https://go.dev/doc/go1.26)
[![Go Report Card](https://goreportcard.com/badge/github.com/ravisastryk/graphqlshield?style=flat-square)](https://goreportcard.com/report/github.com/ravisastryk/graphqlshield)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg?style=flat-square)](LICENSE)
[![CI](https://github.com/ravisastryk/graphqlshield/actions/workflows/ci.yml/badge.svg)](https://github.com/ravisastryk/graphqlshield/actions/workflows/ci.yml)

---

## The problem

GraphQL APIs face a unique threat landscape that WAFs and generic security tools miss entirely:

| Threat | Why WAFs miss it |
|---|---|
| Deeply nested queries → CPU/memory exhaustion | Every request is `POST /graphql` — depth is invisible to HTTP-layer tools |
| `__schema` introspection → full API exposure | Looks like any other query |
| Mutation variables carrying SQL/XSS/command injection | Variables are JSON — WAFs see opaque byte strings |
| Hardcoded secrets, weak crypto in resolvers | Runtime tools can't inspect source code |

Most Go GraphQL servers ship with **zero security middleware** between HTTP and resolver execution.

---

## The solution — one line

```go
// Your existing gqlgen setup — UNCHANGED
gqlHandler := handler.NewDefaultServer(graph.NewExecutableSchema(cfg))

// GraphQLShield — add exactly this
s := graphqlshield.New(
    graphqlshield.WithMaxDepth(5),
    graphqlshield.WithBlockIntrospection(),
    graphqlshield.WithBlockSensitiveFields("password", "ssn"),
)
http.Handle("/graphql", s.Wrap(gqlHandler))  // ← the ONE line
```

---

## Install

```bash
go get github.com/ravisastryk/graphqlshield@latest
```

Requires **Go 1.26+**.

---

## Three layers of defence

```
HTTP request
    │
    ▼
┌─────────────────────────────────────────────────┐
│  Layer 1 — Static controls                      │
│  ✓ MaxDepth(n)             CWE-400              │
│  ✓ BlockIntrospection()    CWE-200              │
│  ✓ BlockSensitiveFields()  CWE-200              │
└──────────────────────────┬──────────────────────┘
                           │ pass
                           ▼
┌─────────────────────────────────────────────────┐
│  Layer 2 — Runtime variable sanitization        │
│  powered by go-safeinput                        │
│  ✓ SQL Injection     CWE-89                     │
│  ✓ XSS               CWE-79                     │
│  ✓ Command Injection  CWE-78                    │
│  ✓ Path Traversal    CWE-22                     │
│  ✓ NoSQL Injection   CWE-943                    │
└──────────────────────────┬──────────────────────┘
                           │ pass
                           ▼
                    gqlgen resolver
```

**Layer 3 — Resolver auditing** (offline, CI step):

```bash
# Scans resolver source for weak crypto, hardcoded secrets, missing auth
go run examples/audit-demo/main.go
```

---

## Quick demo

```bash
# Clone
git clone https://github.com/ravisastryk/graphqlshield
cd graphqlshield

# Run unit tests
make test

# Start the live gqlgen demo server
cd examples/gqlgen-demo && go mod tidy && go run server.go

# Fire 8 attack vectors (new terminal)
bash examples/gqlgen-demo/attacks.sh
```

### Attack demo output

```
╔══════════════════════════════════════════════════════════════╗
║       GraphQLShield ✕ gqlgen — Attack Demo                  ║
╚══════════════════════════════════════════════════════════════╝

  1/8  SQL Injection          (CWE-89  → 400)  ✅  HTTP 400
  2/8  Cross-Site Scripting   (CWE-79  → 400)  ✅  HTTP 400
  3/8  Command Injection      (CWE-78  → 400)  ✅  HTTP 400
  4/8  Path Traversal         (CWE-22  → 400)  ✅  HTTP 400
  5/8  NoSQL Injection        (CWE-943 → 400)  ✅  HTTP 400
  6/8  Depth-based DoS        (CWE-400 → 400)  ✅  HTTP 400
  7/8  Introspection leak     (CWE-200 → 403)  ✅  HTTP 403
  8/8  Legitimate register    (clean   → 200)  ✅  HTTP 200

  Result: 8/8 tests passed
  ✅  GraphQLShield is working correctly!
```

---

## Configuration reference

```go
graphqlshield.New(
    // Layer 1 — static controls
    graphqlshield.WithMaxDepth(5),                          // reject depth > 5 (CWE-400)
    graphqlshield.WithBlockIntrospection(),                 // block __schema/__type (CWE-200)
    graphqlshield.WithBlockSensitiveFields(                 // block named fields (CWE-200)
        "password", "ssn", "creditCard", "token",
    ),

    // Observability
    graphqlshield.WithLogger(slog.Default()),               // structured logging
)
```

All Layer 2 CWE checks (89 · 79 · 78 · 22 · 943) are **always on** — no configuration needed.

---

## Error responses

Every blocked request returns a standard GraphQL error with a CWE code:

```json
{
  "errors": [{
    "message": "[CWE-89] SQL Injection in variable \"name\": SQL injection pattern detected",
    "extensions": { "code": "CWE-89" }
  }]
}
```

---

## CWE coverage

| CWE | Vulnerability | Layer | Powered by |
|---|---|---|---|
| CWE-400 | Resource Exhaustion (depth DoS) | Static | stdlib |
| CWE-200 | Sensitive Data Exposure (introspection) | Static | stdlib |
| CWE-89 | SQL Injection | Runtime | go-safeinput |
| CWE-79 | Cross-Site Scripting | Runtime | go-safeinput |
| CWE-78 | OS Command Injection | Runtime | go-safeinput |
| CWE-22 | Path Traversal | Runtime | go-safeinput |
| CWE-943 | NoSQL Injection | Runtime | built-in regexp |
| CWE-327 | Weak Cryptographic Algorithm | Audit | cryptoguard-go |
| CWE-328 | Use of Weak Hash | Audit | cryptoguard-go |
| CWE-798 | Use of Hard-coded Credentials | Audit | cryptoguard-go + built-in |
| CWE-338 | Insecure Randomness | Audit | cryptoguard-go |
| CWE-321 | Hardcoded Cryptographic Key | Audit | cryptoguard-go |
| CWE-862 | Missing Authorization | Audit | cryptoguard-go |
| CWE-601 | Open Redirect | Runtime | built-in |

---

## Layer 3: resolver auditing

```bash
# Built-in scanner — works without any extra tools
cd examples/audit-demo && go run main.go

# Deeper analysis with cryptoguard-go (AST + taint tracking)
go install github.com/ravisastryk/cryptoguard-go/cmd/cryptoguard@latest
go run main.go
```

Sample output against the intentionally insecure demo resolvers:

```
⚠   graphqlshield audit: 4 issue(s)

1. [CWE-798] CRITICAL — Hardcoded password literal detected
   resolvers/insecure.go:14

2. [CWE-798] CRITICAL — Hardcoded secret literal detected
   resolvers/insecure.go:15

3. [CWE-327] HIGH — MD5 is cryptographically broken — use SHA-256 or bcrypt/argon2
   resolvers/insecure.go:20

4. [CWE-327] HIGH — SHA-1 is deprecated for security use — use SHA-256
   resolvers/insecure.go:27

❌  CRITICAL findings — failing CI
```

---

## Examples

| Example | What it shows |
|---|---|
| [`examples/gqlgen-demo`](examples/gqlgen-demo/) | Real gqlgen server + `s.Wrap()` + live attack demo |
| [`examples/audit-demo`](examples/audit-demo/) | Layer 3 resolver auditing against insecure code |

---

## Running tests

```bash
# All unit tests (race detector on)
make test

# With coverage report
make cover

# Start demo + fire attacks end-to-end
make demo

# Run resolver audit
make audit
```

---

## Standing on the shoulders of giants

GraphQLShield is glue — it brings GraphQL context to excellent existing tools:

| Project | Role |
|---|---|
| [GraphQL](https://graphql.org) | The protocol |
| [gqlgen](https://github.com/99designs/gqlgen) | Type-safe Go GraphQL server (shield wraps its handler) |
| [go-safeinput](https://github.com/ravisastryk/go-safeinput) | MITRE CWE Top 25 input sanitization — powers Layer 2 |
| [cryptoguard-go](https://github.com/ravisastryk/cryptoguard-go) | Crypto misuse detection — powers Layer 3 |
| [gosec](https://github.com/securego/gosec) | Go security checker (audit inspiration) |
| Go community ♥ | Everything else |

---

## License

MIT — see [LICENSE](LICENSE).

---

*Presented at [GraphQLConf 2026](https://graphql.org/conf/2026/) — "GraphQLShield: CWE-Aware Defense in Depth for GraphQL APIs in Go"*  
*Ravi Sastry Kadali*
