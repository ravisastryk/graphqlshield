// gqlgen-demo shows how to add GraphQLShield to an existing gqlgen server.
//
// The entire integration is ONE extra line:
//
//	http.Handle("/graphql", s.Wrap(gqlHandler))
//
// Everything else is your existing gqlgen code, unchanged.
//
// Run:
//
//	go mod tidy && go run server.go
//
// Then open http://localhost:8080/playground  or run:  bash attacks.sh
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"

	// ── gqlgen — already present in every gqlgen project ─────────────────────
	"github.com/99designs/gqlgen/graphql"
	"github.com/99designs/gqlgen/graphql/handler"
	"github.com/vektah/gqlparser/v2"
	"github.com/vektah/gqlparser/v2/ast"
	"github.com/vektah/gqlparser/v2/gqlerror"

	// ── GraphQLShield — the only new import ──────────────────────────────────
	shield "github.com/ravisastryk/graphqlshield"
)

// ─── main ─────────────────────────────────────────────────────────────────────

func main() {
	port := "8080"
	if p := os.Getenv("PORT"); p != "" {
		port = p
	}

	// BEFORE GraphQLShield (standard gqlgen setup):
	//   gqlHandler := handler.NewDefaultServer(newSchema())
	//   http.Handle("/graphql", gqlHandler)
	//
	// AFTER GraphQLShield -- add exactly these lines:

	gqlHandler := handler.NewDefaultServer(newSchema()) // ← unchanged gqlgen line

	s := shield.New(                                    // ← new: configure shield
		shield.WithMaxDepth(5),
		shield.WithBlockIntrospection(),
		shield.WithBlockSensitiveFields("token", "password", "ssn"),
		shield.WithLogger(slog.New(slog.NewTextHandler(
			os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug},
		))),
	)

	mux := http.NewServeMux()
	mux.Handle("/graphql", s.Wrap(gqlHandler))          // ← new: the ONE line wrap
	mux.HandleFunc("/playground", playgroundHandler)    // ← named-example tabs
	mux.HandleFunc("/health", healthHandler)

	printBanner(port)
	log.Fatal(http.ListenAndServe(":"+port, mux))
}

func healthHandler(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprint(w, `{"status":"ok","graphqlshield":"active","maxDepth":5}`)
}

// ─── Playground with named example tabs ──────────────────────────────────────
//
// Custom HTML that boots graphql-playground with one tab per attack scenario,
// so reviewers can click a named tab and hit "Play" to demonstrate each
// GraphQLShield protection live in the browser.

func playgroundHandler(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprint(w, playgroundHTML)
}

const playgroundHTML = `<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8" />
  <title>GraphQLShield x gqlgen — Playground</title>
  <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/graphql-playground-react/build/static/css/index.css" />
  <link rel="shortcut icon" href="https://cdn.jsdelivr.net/npm/graphql-playground-react/build/favicon.png" />
  <script src="https://cdn.jsdelivr.net/npm/graphql-playground-react/build/static/js/middleware.js"></script>
</head>
<body>
  <div id="root">
    <style>
      body { background: #172a3a; font-family: Open Sans, sans-serif; height: 90vh; }
      .loading { font-size: 32px; font-weight: 200; color: rgba(255,255,255,.6); margin-left: 20px; }
      img { width: 78px; height: 78px; }
      .title { font-weight: 400; }
    </style>
    <div class="loading">Loading <span class="title">GraphQLShield Playground</span></div>
  </div>
  <script>
    window.addEventListener('load', function () {
      GraphQLPlayground.init(document.getElementById('root'), {
        endpoint: '/graphql',
        settings: { 'request.credentials': 'same-origin', 'editor.theme': 'dark' },
        tabs: [
          {
            name: '0. Legitimate (clean → 200)',
            endpoint: '/graphql',
            query: 'mutation Register($name: String!, $email: String!) {\n  register(name: $name, email: $email) {\n    id\n    name\n    email\n  }\n}\n',
            variables: '{\n  "name": "John Smith",\n  "email": "john@example.com"\n}'
          },
          {
            name: '1. SQL Injection (CWE-89 → 400)',
            endpoint: '/graphql',
            query: 'mutation CreateUser($name: String!, $email: String!) {\n  createUser(name: $name, email: $email) {\n    id\n  }\n}\n',
            variables: '{\n  "name": "\'; DROP TABLE users;--",\n  "email": "x@x.com"\n}'
          },
          {
            name: '2. XSS (CWE-79 → 400)',
            endpoint: '/graphql',
            query: 'mutation PostComment($body: String!) {\n  addComment(body: $body) {\n    id\n  }\n}\n',
            variables: '{\n  "body": "<script>document.cookie<\/script>"\n}'
          },
          {
            name: '3. Command Injection (CWE-78 → 400)',
            endpoint: '/graphql',
            query: 'mutation RunDiagnostic($cmd: String!) {\n  diagnostic(cmd: $cmd) {\n    result\n  }\n}\n',
            variables: '{\n  "cmd": "$(cat /etc/passwd)"\n}'
          },
          {
            name: '4. Path Traversal (CWE-22 → 400)',
            endpoint: '/graphql',
            query: 'query ReadFile($path: String!) {\n  file(path: $path) {\n    content\n  }\n}\n',
            variables: '{\n  "path": "../../etc/shadow"\n}'
          },
          {
            name: '5. NoSQL Injection (CWE-943 → 400)',
            endpoint: '/graphql',
            query: 'query FindUser($filter: String!) {\n  findUser(filter: $filter) {\n    id\n  }\n}\n',
            variables: '{\n  "filter": "{\\"$ne\\": null}"\n}'
          },
          {
            name: '6. Depth-based DoS (CWE-400 → 400)',
            endpoint: '/graphql',
            query: '{\n  a {\n    b {\n      c {\n        d {\n          e {\n            f {\n              secret\n            }\n          }\n        }\n      }\n    }\n  }\n}\n',
            variables: '{}'
          },
          {
            name: '7. Introspection Leak (CWE-200 → 403)',
            endpoint: '/graphql',
            query: '{\n  __schema {\n    types {\n      name\n    }\n  }\n}\n',
            variables: '{}'
          }
        ]
      })
    })
  </script>
</body>
</html>`

// ═══════════════════════════════════════════════════════════════════════════════
// Everything below is standard gqlgen code — GraphQLShield never touches it.
// In a real project, `go generate` produces graph/generated.go automatically.
// Here it is written by hand so the demo runs with zero build steps.
// ═══════════════════════════════════════════════════════════════════════════════

// ─── GraphQL schema ───────────────────────────────────────────────────────────

const schemaDoc = `
type Query {
  users:            [User!]!
  user(id: ID!):    User
  findUser(filter: String!): User
  file(path: String!):       FileResult
}
type Mutation {
  createUser(name: String!, email: String!): User!
  addComment(body: String!):                 Comment!
  diagnostic(cmd: String!):                  DiagResult!
  register(name: String!, email: String!):   User!
}
type User      { id: ID!  name: String!  email: String! }
type Comment   { id: ID!  body: String!  author: String! }
type FileResult{ name: String!  content: String! }
type DiagResult{ result: String! }
`

// ─── Models ──────────────────────────────────────────────────────────────────

type User struct {
	ID    string `json:"id"`
	Name  string `json:"name"`
	Email string `json:"email"`
}
type Comment struct {
	ID     string `json:"id"`
	Body   string `json:"body"`
	Author string `json:"author"`
}

// ─── In-memory store ─────────────────────────────────────────────────────────

var (
	mu    sync.RWMutex
	store = []*User{{ID: "1", Name: "Alice", Email: "alice@example.com"}}
	seq   atomic.Int64
)

func nextID() string { return fmt.Sprintf("%d", seq.Add(1)+1) }

// ─── ExecutableSchema — what gqlgen generates; hand-written here for demo ─────

type appSchema struct{ parsed *ast.Schema }

func newSchema() graphql.ExecutableSchema {
	s, gqlErr := gqlparser.LoadSchema(&ast.Source{
		Name:  "schema.graphqls",
		Input: schemaDoc,
	})
	if gqlErr != nil {
		log.Fatalf("schema error: %v", gqlErr)
	}
	return &appSchema{parsed: s}
}

func (a *appSchema) Schema() *ast.Schema { return a.parsed }

func (a *appSchema) Complexity(_, _ string, child int, _ map[string]any) (int, bool) {
	return child + 1, true
}

func (a *appSchema) Exec(ctx context.Context) graphql.ResponseHandler {
	return func(ctx context.Context) *graphql.Response {
		oc := graphql.GetOperationContext(ctx)
		data, errs := resolve(oc.OperationName, oc.RawQuery, oc.Variables)
		if len(errs) > 0 {
			return &graphql.Response{Errors: errs}
		}
		raw, _ := json.Marshal(data)
		return &graphql.Response{Data: json.RawMessage(raw)}
	}
}

// ─── Resolver dispatch ────────────────────────────────────────────────────────

func resolve(op, rawQuery string, vars map[string]any) (any, gqlerror.List) {
	if op == "" {
		op = inferOp(rawQuery)
	}
	mu.Lock()
	defer mu.Unlock()

	switch op {
	case "GetUsers":
		return map[string]any{"users": store}, nil

	case "GetUser":
		id := str(vars, "id")
		for _, u := range store {
			if u.ID == id {
				return map[string]any{"user": u}, nil
			}
		}
		return map[string]any{"user": nil}, nil

	case "FindUser":
		if len(store) > 0 {
			return map[string]any{"user": store[0]}, nil
		}
		return map[string]any{"user": nil}, nil

	case "ReadFile":
		return map[string]any{"file": map[string]any{
			"name": str(vars, "path"), "content": "(protected)",
		}}, nil

	case "CreateUser":
		u := &User{ID: nextID(), Name: str(vars, "name"), Email: str(vars, "email")}
		store = append(store, u)
		return map[string]any{"createUser": u}, nil

	case "Register":
		u := &User{ID: nextID(), Name: str(vars, "name"), Email: str(vars, "email")}
		store = append(store, u)
		return map[string]any{"register": u}, nil

	case "PostComment":
		c := &Comment{ID: nextID(), Body: str(vars, "body"), Author: "demo"}
		return map[string]any{"addComment": c}, nil

	case "RunDiagnostic":
		return map[string]any{"diagnostic": map[string]any{"result": "pong"}}, nil

	default:
		return map[string]any{}, nil
	}
}

func inferOp(q string) string {
	switch {
	case strings.Contains(q, "register"):
		return "Register"
	case strings.Contains(q, "createUser"):
		return "CreateUser"
	case strings.Contains(q, "addComment"):
		return "PostComment"
	case strings.Contains(q, "diagnostic"):
		return "RunDiagnostic"
	case strings.Contains(q, "file("):
		return "ReadFile"
	case strings.Contains(q, "findUser"):
		return "FindUser"
	case strings.Contains(q, "users"):
		return "GetUsers"
	default:
		return ""
	}
}

func str(m map[string]any, k string) string {
	if v, ok := m[k]; ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

// ─── Banner ───────────────────────────────────────────────────────────────────

func printBanner(port string) {
	fmt.Printf(`
GraphQLShield x gqlgen -- Live Demo
------------------------------------------------------------
  Integration:  s.Wrap(gqlHandler)   (one line)

  Playground:   http://localhost:%s/playground
  GraphQL:      http://localhost:%s/graphql
  Health:       http://localhost:%s/health

  MaxDepth=5  Introspection=BLOCKED  CWEs 89,79,78,22,943

  Demo attacks: bash attacks.sh
------------------------------------------------------------
`, port, port, port)
}
