package graphqlshield

import "fmt"

// CWEReferenceBaseURL is the canonical MITRE CWE definition URL prefix.
// Each CWE-N entry resolves to "<base>/<N>.html" — e.g.
// https://cwe.mitre.org/data/definitions/89.html for CWE-89.
const CWEReferenceBaseURL = "https://cwe.mitre.org/data/definitions"

// cweURLs is a compile-time registry of MITRE CWE reference URLs for every
// CWE class GraphQLShield emits today.
//
// The table is STATICALLY LOADED, which keeps the middleware:
//   - dependency-free (no network call at startup)
//   - air-gap friendly (works in offline / FedRAMP environments)
//   - allocation-free on the hot path (map lookup, no fetch)
//
// FUTURE — dynamic loading:
// If a deployment needs a fresher catalog (CWE descriptions change between
// MITRE releases, internal teams may keep a curated mirror, etc.), callers
// can install a custom resolver via SetURLResolver below. A future "dynamic"
// implementation could:
//   - pull CWE metadata from https://cwe-api.mitre.org/api/v1 on startup
//   - cache the result on disk with a TTL
//   - refresh out-of-band on a goroutine without blocking requests
//   - fall back to this static table if the upstream fetch fails
//
// See the URLResolver interface for the seam.
var cweURLs = map[string]string{
	"CWE-22":  "https://cwe.mitre.org/data/definitions/22.html",  // Path Traversal
	"CWE-78":  "https://cwe.mitre.org/data/definitions/78.html",  // OS Command Injection
	"CWE-79":  "https://cwe.mitre.org/data/definitions/79.html",  // Cross-Site Scripting
	"CWE-89":  "https://cwe.mitre.org/data/definitions/89.html",  // SQL Injection
	"CWE-200": "https://cwe.mitre.org/data/definitions/200.html", // Sensitive Data Exposure
	"CWE-321": "https://cwe.mitre.org/data/definitions/321.html", // Hardcoded Cryptographic Key
	"CWE-327": "https://cwe.mitre.org/data/definitions/327.html", // Weak Crypto Algorithm
	"CWE-328": "https://cwe.mitre.org/data/definitions/328.html", // Weak Hash
	"CWE-338": "https://cwe.mitre.org/data/definitions/338.html", // Insecure Randomness
	"CWE-400": "https://cwe.mitre.org/data/definitions/400.html", // Resource Exhaustion
	"CWE-601": "https://cwe.mitre.org/data/definitions/601.html", // Open Redirect
	"CWE-798": "https://cwe.mitre.org/data/definitions/798.html", // Hard-coded Credentials
	"CWE-862": "https://cwe.mitre.org/data/definitions/862.html", // Missing Authorization
	"CWE-943": "https://cwe.mitre.org/data/definitions/943.html", // NoSQL Injection
}

// URLResolver resolves a CWE identifier (e.g. "CWE-89") to a reference URL.
//
// The default implementation reads from the statically compiled cweURLs
// table above and falls back to deriving the URL from the numeric portion
// of the identifier. Implementations may pull from a remote registry, an
// internal cache, or a signed offline mirror — anything that satisfies
// this interface. Install a custom resolver with SetURLResolver.
type URLResolver interface {
	URL(cwe string) string
}

// staticResolver is the default URLResolver: static map + numeric fallback.
type staticResolver struct{}

func (staticResolver) URL(cwe string) string {
	if u, ok := cweURLs[cwe]; ok {
		return u
	}
	// Fallback: derive the URL from the numeric portion if the caller asks
	// about a CWE we did not pre-register. This keeps the response useful
	// for custom CWEs surfaced by downstream resolvers (Layer 3 audit, user
	// extensions) without forcing a table update for every new identifier.
	var n int
	if _, err := fmt.Sscanf(cwe, "CWE-%d", &n); err == nil && n > 0 {
		return fmt.Sprintf("%s/%d.html", CWEReferenceBaseURL, n)
	}
	return ""
}

// urlResolver is the active resolver. Swap it with SetURLResolver to plug
// in a dynamic source (e.g. MITRE REST API or an internal catalog).
var urlResolver URLResolver = staticResolver{}

// SetURLResolver installs a custom URLResolver. Pass nil to restore the
// built-in static resolver.
//
// This is the extension point for future dynamic-loading strategies. The
// Shield itself stays synchronous and side-effect-free; resolvers handle
// any I/O, caching, or refresh policy on their own schedule.
func SetURLResolver(r URLResolver) {
	if r == nil {
		urlResolver = staticResolver{}
		return
	}
	urlResolver = r
}

// CWEError is a security error tagged with a MITRE CWE identifier.
// Every block decision GraphQLShield makes returns one of these.
type CWEError struct {
	CWE    string // e.g. "CWE-89"
	Name   string // e.g. "SQL Injection"
	Field  string // GraphQL variable name, if applicable
	Detail string // human-readable reason
}

func (e *CWEError) Error() string {
	if e.Field != "" {
		return fmt.Sprintf("[%s] %s in variable %q: %s", e.CWE, e.Name, e.Field, e.Detail)
	}
	return fmt.Sprintf("[%s] %s: %s", e.CWE, e.Name, e.Detail)
}

// URL returns the MITRE CWE reference URL for this error, e.g.
// "https://cwe.mitre.org/data/definitions/89.html" for CWE-89.
// Returns "" if the CWE identifier is malformed.
func (e *CWEError) URL() string {
	if e == nil {
		return ""
	}
	return urlResolver.URL(e.CWE)
}

// Pre-built constructors for every CWE class GraphQLShield covers.
var (
	newDepthExceeded = func(got, max int) *CWEError {
		return &CWEError{CWE: "CWE-400", Name: "Resource Exhaustion",
			Detail: fmt.Sprintf("query depth %d exceeds limit %d", got, max)}
	}
	errIntrospectionBlocked = &CWEError{CWE: "CWE-200", Name: "Sensitive Data Exposure",
		Detail: "introspection is disabled in this environment"}

	newSQLi = func(f string) *CWEError {
		return &CWEError{CWE: "CWE-89", Name: "SQL Injection", Field: f,
			Detail: "SQL injection pattern detected"}
	}
	newXSS = func(f string) *CWEError {
		return &CWEError{CWE: "CWE-79", Name: "Cross-Site Scripting", Field: f,
			Detail: "XSS payload detected"}
	}
	newCmdInjection = func(f string) *CWEError {
		return &CWEError{CWE: "CWE-78", Name: "OS Command Injection", Field: f,
			Detail: "shell metacharacter detected"}
	}
	newPathTraversal = func(f string) *CWEError {
		return &CWEError{CWE: "CWE-22", Name: "Path Traversal", Field: f,
			Detail: "directory traversal sequence detected"}
	}
	newNoSQLInjection = func(f string) *CWEError {
		return &CWEError{CWE: "CWE-943", Name: "NoSQL Injection", Field: f,
			Detail: "NoSQL operator injection detected"}
	}
	newSensitiveField = func(f string) *CWEError {
		return &CWEError{CWE: "CWE-200", Name: "Sensitive Data Exposure", Field: f,
			Detail: "field is blocked by shield policy"}
	}
)
