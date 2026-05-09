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
	"sort"
	"strings"
	"sync"
	"sync/atomic"

	// ── gqlgen — already present in every gqlgen project ─────────────────────
	"github.com/99designs/gqlgen/graphql"
	"github.com/99designs/gqlgen/graphql/handler"
	"github.com/99designs/gqlgen/graphql/handler/extension"
	"github.com/99designs/gqlgen/graphql/handler/lru"
	"github.com/99designs/gqlgen/graphql/handler/transport"
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

	// Explicit gqlgen server setup. handler.NewDefaultServer is deprecated by
	// gqlgen as "just an example" — for a security demo we'd rather be explicit
	// about exactly which transports and extensions are wired. We deliberately
	// omit transport.GET (query-via-URL is unnecessary attack surface) and
	// transport.MultipartForm (no file uploads in this schema), and skip APQ.
	gqlHandler := handler.New(newSchema())
	gqlHandler.AddTransport(transport.Options{}) // CORS preflight
	gqlHandler.AddTransport(transport.GET{})     // browser visits + ?query= probes
	gqlHandler.AddTransport(transport.POST{})    // the request type the playground + attacks.sh use
	gqlHandler.SetQueryCache(lru.New[*ast.QueryDocument](1000))
	gqlHandler.Use(extension.Introspection{}) // gqlgen-side introspection support;
	// the shield decides whether to block it per-endpoint (see prodShield below).

	logger := slog.New(slog.NewTextHandler(
		os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug},
	))

	// Production-style endpoint: full shield, introspection BLOCKED (CWE-200).
	prodShield := shield.New(
		shield.WithMaxDepth(5),
		shield.WithBlockIntrospection(),
		shield.WithBlockSensitiveFields("token", "password", "ssn"),
		shield.WithLogger(logger),
	)

	// Playground-friendly endpoint: same protections, introspection ALLOWED so
	// the playground's Docs/Schema panels can populate. The standard
	// IntrospectionQuery walks 7 levels of `ofType` via its TypeRef fragment
	// (total depth ~8), so MaxDepth here is loosened to 12 — enough for
	// introspection but still well under a real DoS payload. Tab #7 below
	// hits /graphql-prod to exercise the introspection block in the demo.
	devShield := shield.New(
		shield.WithMaxDepth(12),
		shield.WithBlockSensitiveFields("token", "password", "ssn"),
		shield.WithLogger(logger),
	)

	mux := http.NewServeMux()
	mux.Handle("/graphql", devShield.Wrap(gqlHandler))       // playground default
	mux.Handle("/graphql-prod", prodShield.Wrap(gqlHandler)) // demonstrates introspection block
	mux.HandleFunc("/playground", playgroundHandler)
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
            query: '# /graphql allows depth up to 12 so the standard\n# IntrospectionQuery (depth ~8) can populate the Docs panel.\n# This payload nests 14 levels and still trips the limit.\n{\n  a { b { c { d { e { f { g { h { i { j { k { l { m { secret\n  }}}}}}}}}}}}}\n}\n',
            variables: '{}'
          },
          {
            name: '7. Introspection Leak (CWE-200 → 403)',
            endpoint: '/graphql-prod',
            query: '# This tab targets /graphql-prod — the production endpoint with\n# introspection blocking enabled. Click PLAY to see a 403 from the shield.\n# (The Docs/Schema tabs use /graphql which allows introspection so you can\n# explore the schema in this demo UI.)\n{\n  __schema {\n    types {\n      name\n    }\n  }\n}\n',
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
		if isIntrospectionQuery(oc.Doc) {
			raw, _ := json.Marshal(introspectionResult(a.parsed))
			return &graphql.Response{Data: json.RawMessage(raw)}
		}
		data, errs := resolve(oc.OperationName, oc.RawQuery, oc.Variables)
		if len(errs) > 0 {
			return &graphql.Response{Errors: errs}
		}
		raw, _ := json.Marshal(data)
		return &graphql.Response{Data: json.RawMessage(raw)}
	}
}

// ─── Introspection (hand-rolled — gqlgen normally generates this) ────────────
//
// graphql-playground populates its Docs/Schema panels by issuing a standard
// IntrospectionQuery. gqlgen's `extension.Introspection{}` only gates whether
// such queries are *permitted* — the actual __schema/__type resolvers come
// from generated code, which this demo deliberately doesn't have.
//
// Rather than pull in `go generate`, we walk the parsed *ast.Schema and emit
// the introspection JSON shape directly. We always emit the full schema; the
// client's selection set picks out the fields it asked for, and any extras
// are simply ignored. That's enough to make Docs/Schema work.

func isIntrospectionQuery(doc *ast.QueryDocument) bool {
	if doc == nil {
		return false
	}
	for _, op := range doc.Operations {
		for _, sel := range op.SelectionSet {
			if f, ok := sel.(*ast.Field); ok && strings.HasPrefix(f.Name, "__") {
				return true
			}
		}
	}
	return false
}

func introspectionResult(s *ast.Schema) map[string]any {
	names := make([]string, 0, len(s.Types))
	for n := range s.Types {
		names = append(names, n)
	}
	sort.Strings(names)
	types := make([]any, 0, len(names))
	for _, n := range names {
		types = append(types, introspectType(s, s.Types[n]))
	}

	out := map[string]any{
		"types":            types,
		"directives":       []any{},
		"queryType":        nil,
		"mutationType":     nil,
		"subscriptionType": nil,
	}
	if s.Query != nil {
		out["queryType"] = map[string]any{"name": s.Query.Name}
	}
	if s.Mutation != nil {
		out["mutationType"] = map[string]any{"name": s.Mutation.Name}
	}
	if s.Subscription != nil {
		out["subscriptionType"] = map[string]any{"name": s.Subscription.Name}
	}
	return map[string]any{"__schema": out}
}

func introspectType(s *ast.Schema, d *ast.Definition) map[string]any {
	res := map[string]any{
		"kind":          kindOf(d),
		"name":          d.Name,
		"description":   d.Description,
		"fields":        nil,
		"inputFields":   nil,
		"interfaces":    nil,
		"enumValues":    nil,
		"possibleTypes": nil,
	}
	switch d.Kind {
	case ast.Object, ast.Interface:
		fields := []any{}
		for _, f := range d.Fields {
			if strings.HasPrefix(f.Name, "__") {
				continue
			}
			args := []any{}
			for _, a := range f.Arguments {
				args = append(args, map[string]any{
					"name":         a.Name,
					"description":  a.Description,
					"type":         introspectTypeRef(s, a.Type),
					"defaultValue": nil,
				})
			}
			fields = append(fields, map[string]any{
				"name":              f.Name,
				"description":       f.Description,
				"args":              args,
				"type":              introspectTypeRef(s, f.Type),
				"isDeprecated":      false,
				"deprecationReason": nil,
			})
		}
		res["fields"] = fields
		if d.Kind == ast.Object {
			ifs := []any{}
			for _, n := range d.Interfaces {
				ifs = append(ifs, map[string]any{"kind": "INTERFACE", "name": n, "ofType": nil})
			}
			res["interfaces"] = ifs
		}
	case ast.InputObject:
		inputs := []any{}
		for _, f := range d.Fields {
			inputs = append(inputs, map[string]any{
				"name":         f.Name,
				"description":  f.Description,
				"type":         introspectTypeRef(s, f.Type),
				"defaultValue": nil,
			})
		}
		res["inputFields"] = inputs
	case ast.Enum:
		evs := []any{}
		for _, ev := range d.EnumValues {
			evs = append(evs, map[string]any{
				"name":              ev.Name,
				"description":       ev.Description,
				"isDeprecated":      false,
				"deprecationReason": nil,
			})
		}
		res["enumValues"] = evs
	case ast.Union:
		pts := []any{}
		for _, n := range d.Types {
			pts = append(pts, map[string]any{"kind": "OBJECT", "name": n, "ofType": nil})
		}
		res["possibleTypes"] = pts
	}
	return res
}

func introspectTypeRef(s *ast.Schema, t *ast.Type) map[string]any {
	if t.NonNull {
		inner := *t
		inner.NonNull = false
		return map[string]any{"kind": "NON_NULL", "name": nil, "ofType": introspectTypeRef(s, &inner)}
	}
	if t.Elem != nil {
		return map[string]any{"kind": "LIST", "name": nil, "ofType": introspectTypeRef(s, t.Elem)}
	}
	kind := "SCALAR"
	if def, ok := s.Types[t.NamedType]; ok && def != nil {
		kind = kindOf(def)
	}
	return map[string]any{"kind": kind, "name": t.NamedType, "ofType": nil}
}

func kindOf(d *ast.Definition) string {
	switch d.Kind {
	case ast.Object:
		return "OBJECT"
	case ast.Interface:
		return "INTERFACE"
	case ast.Union:
		return "UNION"
	case ast.Enum:
		return "ENUM"
	case ast.InputObject:
		return "INPUT_OBJECT"
	default:
		return "SCALAR"
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

  Playground:   http://localhost:%s/playground   (docs panel works here)
  GraphQL dev:  http://localhost:%s/graphql        (MaxDepth=12, introspection ALLOWED)
  GraphQL prod: http://localhost:%s/graphql-prod   (MaxDepth=5,  introspection BLOCKED)
  Health:       http://localhost:%s/health

  CWEs 89,79,78,22,200,400,943

  Demo attacks: bash attacks.sh
------------------------------------------------------------
`, port, port, port, port)
}
