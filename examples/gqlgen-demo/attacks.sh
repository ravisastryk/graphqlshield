#!/usr/bin/env bash
# attacks.sh — fires 7 attack vectors + 1 legit request against the demo server.
# Start the server first:  go run server.go
# Then:                    bash attacks.sh
set -euo pipefail

HOST=${1:-localhost:8080}
DEV="http://$HOST/graphql"        # introspection allowed (playground-friendly)
PROD="http://$HOST/graphql-prod"  # introspection blocked
PASS=0; FAIL=0

fire() {
  local label="$1" expect="$2" body="$3" url="${4:-$DEV}"
  echo ""
  printf '  %-55s' "$label"
  code=$(curl -s -o /tmp/shield_resp -w "%{http_code}" \
    -X POST "$url" -H "Content-Type: application/json" -d "$body")
  resp=$(cat /tmp/shield_resp)
  if [ "$code" = "$expect" ]; then
    printf 'PASS  HTTP %s\n' "$code"; PASS=$((PASS+1))
  else
    printf 'FAIL  HTTP %s (want %s)\n' "$code" "$expect"; FAIL=$((FAIL+1))
    echo "     Response: $(echo "$resp" | head -c 200)"
  fi
}

echo ""
echo "GraphQLShield x gqlgen -- Attack Demo"
echo "--------------------------------------"

# 1. SQL Injection (CWE-89)
fire "1/8  SQL Injection          (CWE-89  -> 400)" "400" \
'{"operationName":"CreateUser","query":"mutation CreateUser($name:String!,$email:String!){createUser(name:$name,email:$email){id}}","variables":{"name":"'"'"'; DROP TABLE users;--","email":"x@x.com"}}'

# 2. XSS (CWE-79)
fire "2/8  Cross-Site Scripting   (CWE-79  -> 400)" "400" \
'{"operationName":"PostComment","query":"mutation PostComment($body:String!){addComment(body:$body){id}}","variables":{"body":"<script>document.cookie<\/script>"}}'

# 3. Command Injection (CWE-78)
fire "3/8  Command Injection      (CWE-78  -> 400)" "400" \
'{"operationName":"RunDiagnostic","query":"mutation RunDiagnostic($cmd:String!){diagnostic(cmd:$cmd){result}}","variables":{"cmd":"$(cat /etc/passwd)"}}'

# 4. Path Traversal (CWE-22)
fire "4/8  Path Traversal         (CWE-22  -> 400)" "400" \
'{"operationName":"ReadFile","query":"query ReadFile($path:String!){file(path:$path){content}}","variables":{"path":"../../etc/shadow"}}'

# 5. NoSQL Injection (CWE-943)
fire "5/8  NoSQL Injection        (CWE-943 -> 400)" "400" \
'{"operationName":"FindUser","query":"query FindUser($filter:String!){findUser(filter:$filter){id}}","variables":{"filter":"{\"$ne\":null}"}}'

# 6. Depth DoS (CWE-400) — depth 14 > /graphql limit (12).
#    /graphql's depth limit is loosened to 12 so the playground's standard
#    IntrospectionQuery (depth ~8) can populate the Docs panel; this payload
#    nests deep enough to trip it anyway. /graphql-prod still uses MaxDepth=5.
fire "6/8  Depth-based DoS        (CWE-400 -> 400)" "400" \
'{"query":"{ a { b { c { d { e { f { g { h { i { j { k { l { m { secret } } } } } } } } } } } } } }"}'

# 7. Introspection (CWE-200) — must hit the prod endpoint where introspection is blocked
fire "7/8  Introspection leak     (CWE-200 -> 403)" "403" \
'{"query":"{ __schema { types { name } } }"}' \
"$PROD"

# 8. Legitimate request — MUST PASS
fire "8/8  Legitimate register    (clean   -> 200)" "200" \
'{"operationName":"Register","query":"mutation Register($name:String!,$email:String!){register(name:$name,email:$email){id}}","variables":{"name":"John Smith","email":"john@example.com"}}'

echo ""
echo "--------------------------------------"
printf "Result: %d/%d tests passed\n" $PASS $((PASS+FAIL))
echo "--------------------------------------"
echo ""
[ $FAIL -eq 0 ] && echo "PASS  GraphQLShield is working correctly." || { echo "FAIL  $FAIL test(s) failed."; exit 1; }
