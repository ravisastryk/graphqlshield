package graphqlshield_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	shield "github.com/ravisastryk/graphqlshield"
)

// passHandler counts how many times it was reached.
var passHandler = http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`{"data":{}}`))
})

// post fires a POST /graphql request with the given body.
func post(h http.Handler, body any) *httptest.ResponseRecorder {
	b, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/graphql", bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// cweCode pulls the CWE extension code from a shield error response.
func cweCode(t *testing.T, rec *httptest.ResponseRecorder) string {
	t.Helper()
	var resp struct {
		Errors []struct {
			Extensions struct{ Code string } `json:"extensions"`
		} `json:"errors"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil || len(resp.Errors) == 0 {
		t.Fatalf("could not parse CWE from response: %s", rec.Body.String())
	}
	return resp.Errors[0].Extensions.Code
}

// cweURL pulls the CWE reference URL from a shield error response.
func cweURL(t *testing.T, rec *httptest.ResponseRecorder) string {
	t.Helper()
	var resp struct {
		Errors []struct {
			Extensions struct {
				URL string `json:"cwe_url"`
			} `json:"extensions"`
		} `json:"errors"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil || len(resp.Errors) == 0 {
		t.Fatalf("could not parse cwe_url from response: %s", rec.Body.String())
	}
	return resp.Errors[0].Extensions.URL
}

// ─── Layer 1: depth ──────────────────────────────────────────────────────────

func TestDepth_Pass(t *testing.T) {
	h := shield.New(shield.WithMaxDepth(5)).Wrap(passHandler)
	rec := post(h, map[string]any{"query": `{ user { name email } }`})
	if rec.Code != 200 {
		t.Fatalf("want 200, got %d: %s", rec.Code, rec.Body)
	}
}

func TestDepth_Block(t *testing.T) {
	h := shield.New(shield.WithMaxDepth(3)).Wrap(passHandler)
	// depth = 4: { a { b { c { d } } } }
	rec := post(h, map[string]any{"query": `{ a { b { c { d } } } }`})
	if rec.Code != 400 {
		t.Fatalf("want 400, got %d", rec.Code)
	}
	if got := cweCode(t, rec); got != "CWE-400" {
		t.Fatalf("want CWE-400, got %s", got)
	}
}

// ─── Layer 1: introspection ───────────────────────────────────────────────────

func TestIntrospection_Block(t *testing.T) {
	h := shield.New(shield.WithBlockIntrospection()).Wrap(passHandler)
	rec := post(h, map[string]any{"query": `{ __schema { types { name } } }`})
	if rec.Code != 403 {
		t.Fatalf("want 403, got %d", rec.Code)
	}
	if got := cweCode(t, rec); got != "CWE-200" {
		t.Fatalf("want CWE-200, got %s", got)
	}
}

func TestIntrospection_AllowedWhenNotBlocked(t *testing.T) {
	h := shield.New().Wrap(passHandler) // no WithBlockIntrospection
	rec := post(h, map[string]any{"query": `{ __schema { types { name } } }`})
	if rec.Code != 200 {
		t.Fatalf("introspection should pass when not blocked, got %d", rec.Code)
	}
}

// ─── Layer 1: sensitive fields ────────────────────────────────────────────────

func TestSensitiveField_Block(t *testing.T) {
	h := shield.New(shield.WithBlockSensitiveFields("password", "ssn")).Wrap(passHandler)
	rec := post(h, map[string]any{"query": `{ user { id password } }`})
	if rec.Code != 403 {
		t.Fatalf("want 403, got %d", rec.Code)
	}
	if got := cweCode(t, rec); got != "CWE-200" {
		t.Fatalf("want CWE-200, got %s", got)
	}
}

func TestSensitiveField_Pass(t *testing.T) {
	h := shield.New(shield.WithBlockSensitiveFields("password")).Wrap(passHandler)
	rec := post(h, map[string]any{"query": `{ user { id email name } }`})
	if rec.Code != 200 {
		t.Fatalf("safe query should pass, got %d: %s", rec.Code, rec.Body)
	}
}

// ─── Layer 2: SQL injection (CWE-89) ─────────────────────────────────────────

func TestSQLInjection_Block(t *testing.T) {
	h := shield.New().Wrap(passHandler)
	rec := post(h, map[string]any{
		"query":     `mutation CreateUser($name:String!){createUser(name:$name){id}}`,
		"variables": map[string]any{"name": "'; DROP TABLE users; --"},
	})
	if rec.Code != 400 {
		t.Fatalf("want 400, got %d: %s", rec.Code, rec.Body)
	}
	if got := cweCode(t, rec); got != "CWE-89" {
		t.Fatalf("want CWE-89, got %s", got)
	}
}

func TestSQLInjection_LegitPass(t *testing.T) {
	h := shield.New().Wrap(passHandler)
	rec := post(h, map[string]any{
		"query":     `mutation CreateUser($name:String!,$email:String!){createUser(name:$name,email:$email){id}}`,
		"variables": map[string]any{"name": "John Smith", "email": "john@example.com"},
	})
	if rec.Code != 200 {
		t.Fatalf("legit request should pass, got %d: %s", rec.Code, rec.Body)
	}
}

// ─── Layer 2: XSS (CWE-79) ───────────────────────────────────────────────────

func TestXSS_Block(t *testing.T) {
	h := shield.New().Wrap(passHandler)
	rec := post(h, map[string]any{
		"query":     `mutation PostComment($body:String!){addComment(body:$body){id}}`,
		"variables": map[string]any{"body": "<script>document.cookie</script>"},
	})
	if rec.Code != 400 {
		t.Fatalf("want 400, got %d: %s", rec.Code, rec.Body)
	}
	if got := cweCode(t, rec); got != "CWE-79" {
		t.Fatalf("want CWE-79, got %s", got)
	}
}

// ─── Layer 2: command injection (CWE-78) ─────────────────────────────────────

func TestCommandInjection_Block(t *testing.T) {
	h := shield.New().Wrap(passHandler)
	rec := post(h, map[string]any{
		"query":     `mutation Run($cmd:String!){diagnostic(cmd:$cmd){result}}`,
		"variables": map[string]any{"cmd": "$(cat /etc/passwd)"},
	})
	if rec.Code != 400 {
		t.Fatalf("want 400, got %d: %s", rec.Code, rec.Body)
	}
	if got := cweCode(t, rec); got != "CWE-78" {
		t.Fatalf("want CWE-78, got %s", got)
	}
}

// ─── Layer 2: path traversal (CWE-22) ────────────────────────────────────────

func TestPathTraversal_Block(t *testing.T) {
	h := shield.New().Wrap(passHandler)
	rec := post(h, map[string]any{
		"query":     `query ReadFile($path:String!){file(path:$path){content}}`,
		"variables": map[string]any{"path": "../../etc/shadow"},
	})
	if rec.Code != 400 {
		t.Fatalf("want 400, got %d: %s", rec.Code, rec.Body)
	}
	if got := cweCode(t, rec); got != "CWE-22" {
		t.Fatalf("want CWE-22, got %s", got)
	}
}

// ─── Layer 2: NoSQL injection (CWE-943) ──────────────────────────────────────

func TestNoSQLInjection_Block(t *testing.T) {
	h := shield.New().Wrap(passHandler)
	rec := post(h, map[string]any{
		"query":     `query FindUser($filter:String!){findUser(filter:$filter){id}}`,
		"variables": map[string]any{"filter": `{"$ne": null}`},
	})
	if rec.Code != 400 {
		t.Fatalf("want 400, got %d: %s", rec.Code, rec.Body)
	}
	if got := cweCode(t, rec); got != "CWE-943" {
		t.Fatalf("want CWE-943, got %s", got)
	}
}

// ─── Legitimate request passes all layers ─────────────────────────────────────

func TestLegitimateRequest_PassesAll(t *testing.T) {
	h := shield.New(
		shield.WithMaxDepth(5),
		shield.WithBlockIntrospection(),
		shield.WithBlockSensitiveFields("password", "ssn"),
	).Wrap(passHandler)

	rec := post(h, map[string]any{
		"query": `mutation Register($name:String!,$email:String!){
			register(name:$name,email:$email){id createdAt}
		}`,
		"variables": map[string]any{
			"name":  "John Smith",
			"email": "john@example.com",
		},
	})
	if rec.Code != 200 {
		t.Fatalf("legit request should pass all layers, got %d: %s", rec.Code, rec.Body)
	}
}

// ─── Non-POST passthrough ─────────────────────────────────────────────────────

func TestGET_PassThrough(t *testing.T) {
	h := shield.New(shield.WithMaxDepth(1)).Wrap(passHandler)
	req := httptest.NewRequest(http.MethodGet, "/graphql", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Fatalf("GET should pass through, got %d", rec.Code)
	}
}

// ─── Depth precision edge cases ──────────────────────────────────────────────

func TestDepth_ExactlyAtLimit_Passes(t *testing.T) {
	// depth exactly 3: { a { b { c } } }
	h := shield.New(shield.WithMaxDepth(3)).Wrap(passHandler)
	rec := post(h, map[string]any{"query": `{ a { b { c } } }`})
	if rec.Code != 200 {
		t.Fatalf("depth==limit should pass, got %d: %s", rec.Code, rec.Body)
	}
}

func TestDepth_OneOverLimit_Blocks(t *testing.T) {
	// depth 4 > limit 3
	h := shield.New(shield.WithMaxDepth(3)).Wrap(passHandler)
	rec := post(h, map[string]any{"query": `{ a { b { c { d } } } }`})
	if rec.Code != 400 {
		t.Fatalf("depth > limit should block, got %d", rec.Code)
	}
}

// ─── CWE reference URL plumbing ──────────────────────────────────────────────

// TestBlockResponse_IncludesCWEURL asserts that a blocked response carries the
// MITRE reference URL alongside the CWE code, matching the canonical
// https://cwe.mitre.org/data/definitions/<n>.html shape.
func TestBlockResponse_IncludesCWEURL(t *testing.T) {
	h := shield.New().Wrap(passHandler)
	rec := post(h, map[string]any{
		"query":     `mutation($name:String!){ createUser(name:$name){ id } }`,
		"variables": map[string]any{"name": "'; DROP TABLE users;--"},
	})
	if rec.Code != 400 {
		t.Fatalf("want 400, got %d: %s", rec.Code, rec.Body)
	}
	if got := cweCode(t, rec); got != "CWE-89" {
		t.Fatalf("want CWE-89, got %s", got)
	}
	if got, want := cweURL(t, rec), "https://cwe.mitre.org/data/definitions/89.html"; got != want {
		t.Fatalf("cwe_url: want %q, got %q", want, got)
	}
}

// TestCWEError_URL covers the *CWEError.URL accessor and the static resolver,
// including the numeric fallback for an identifier not in the static table.
func TestCWEError_URL(t *testing.T) {
	known := &shield.CWEError{CWE: "CWE-79", Name: "Cross-Site Scripting"}
	if got, want := known.URL(), "https://cwe.mitre.org/data/definitions/79.html"; got != want {
		t.Fatalf("known CWE: want %q, got %q", want, got)
	}
	// Not in cweURLs — must still resolve via the numeric fallback.
	unknown := &shield.CWEError{CWE: "CWE-1004"}
	if got, want := unknown.URL(), "https://cwe.mitre.org/data/definitions/1004.html"; got != want {
		t.Fatalf("fallback CWE: want %q, got %q", want, got)
	}
	// Malformed identifier resolves to empty.
	if got := (&shield.CWEError{CWE: "not-a-cwe"}).URL(); got != "" {
		t.Fatalf("malformed CWE: want empty, got %q", got)
	}
	// Nil receiver is safe.
	var nilErr *shield.CWEError
	if got := nilErr.URL(); got != "" {
		t.Fatalf("nil receiver: want empty, got %q", got)
	}
}

// TestSetURLResolver verifies the resolver seam can be swapped and restored.
func TestSetURLResolver(t *testing.T) {
	t.Cleanup(func() { shield.SetURLResolver(nil) }) // restore default

	shield.SetURLResolver(resolverFunc(func(cwe string) string {
		return "https://internal.example/cwe/" + cwe
	}))
	if got, want := (&shield.CWEError{CWE: "CWE-89"}).URL(), "https://internal.example/cwe/CWE-89"; got != want {
		t.Fatalf("custom resolver: want %q, got %q", want, got)
	}

	// Passing nil restores the built-in static resolver.
	shield.SetURLResolver(nil)
	if got, want := (&shield.CWEError{CWE: "CWE-89"}).URL(), "https://cwe.mitre.org/data/definitions/89.html"; got != want {
		t.Fatalf("after reset: want %q, got %q", want, got)
	}
}

// resolverFunc adapts a func to the shield.URLResolver interface.
type resolverFunc func(string) string

func (f resolverFunc) URL(cwe string) string { return f(cwe) }
