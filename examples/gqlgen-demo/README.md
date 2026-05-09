# gqlgen-demo

Demonstrates how to secure an existing [gqlgen](https://github.com/99designs/gqlgen) server with GraphQLShield in **one line of code**.

## The integration

```go
// Before GraphQLShield (standard gqlgen setup)
gqlHandler := handler.NewDefaultServer(graph.NewExecutableSchema(cfg))
http.Handle("/graphql", gqlHandler)

// After GraphQLShield — add ONE line
s := graphqlshield.New(
    graphqlshield.WithMaxDepth(5),
    graphqlshield.WithBlockIntrospection(),
)
http.Handle("/graphql", s.Wrap(gqlHandler)) // ← the only change
```

## Run

```bash
go mod tidy && go run server.go
```

Open the playground at **http://localhost:8080/playground**.

## Fire all 8 attack vectors

```bash
bash attacks.sh
```

Expected output:

```
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

## Try attacks manually in the playground

```graphql
# ❌ SQL Injection — blocked CWE-89
mutation {
  createUser(name: "'; DROP TABLE users;--", email: "x") { id }
}

# ❌ Depth DoS — blocked CWE-400 (depth 6 > max 5)
{ a { b { c { d { e { f { secret } } } } } } }

# ❌ Introspection — blocked CWE-200
{ __schema { types { name } } }

# ✅ Legitimate — passes all layers
mutation {
  register(name: "John Smith", email: "john@example.com") { id }
}
```
