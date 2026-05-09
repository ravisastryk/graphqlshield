# GraphQLShield Playground Queries

Copy these into http://localhost:8080/playground to test each attack vector.
For queries with variables, paste the **Query** in the left panel and the
**Variables** in the "Query Variables" tab at the bottom.

---

## 1. SQL Injection (CWE-89) -- expect 400

**Query:**
```graphql
mutation CreateUser($name: String!, $email: String!) {
  createUser(name: $name, email: $email) {
    id
  }
}
```

**Variables:**
```json
{
  "name": "'; DROP TABLE users;--",
  "email": "x@x.com"
}
```

---

## 2. Cross-Site Scripting (CWE-79) -- expect 400

**Query:**
```graphql
mutation PostComment($body: String!) {
  addComment(body: $body) {
    id
  }
}
```

**Variables:**
```json
{
  "body": "<script>document.cookie</script>"
}
```

---

## 3. Command Injection (CWE-78) -- expect 400

**Query:**
```graphql
mutation RunDiagnostic($cmd: String!) {
  diagnostic(cmd: $cmd) {
    result
  }
}
```

**Variables:**
```json
{
  "cmd": "$(cat /etc/passwd)"
}
```

---

## 4. Path Traversal (CWE-22) -- expect 400

**Query:**
```graphql
query ReadFile($path: String!) {
  file(path: $path) {
    content
  }
}
```

**Variables:**
```json
{
  "path": "../../etc/shadow"
}
```

---

## 5. NoSQL Injection (CWE-943) -- expect 400

**Query:**
```graphql
query FindUser($filter: String!) {
  findUser(filter: $filter) {
    id
  }
}
```

**Variables:**
```json
{
  "filter": "{\"$ne\": null}"
}
```

---

## 6. Depth-based DoS (CWE-400) -- expect 400

**Query (no variables needed):**
```graphql
{
  a {
    b {
      c {
        d {
          e {
            f {
              secret
            }
          }
        }
      }
    }
  }
}
```

---

## 7. Introspection Leak (CWE-200) -- expect 403

**Query (no variables needed):**
```graphql
{
  __schema {
    types {
      name
    }
  }
}
```

---

## 8. Legitimate Request (clean) -- expect 200

**Query:**
```graphql
mutation Register($name: String!, $email: String!) {
  register(name: $name, email: $email) {
    id
  }
}
```

**Variables:**
```json
{
  "name": "John Smith",
  "email": "john@example.com"
}
```
