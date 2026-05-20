// Package graphqlshield is a zero-config security middleware for Go GraphQL APIs.
//
// It wraps any http.Handler — including the handler produced by gqlgen,
// graph-gophers/graphql-go, or any other Go GraphQL library — and enforces
// three layers of defence before a request reaches your resolvers.
//
// # Quick start
//
//	// 1. build your gqlgen handler the normal way
//	srv := handler.NewDefaultServer(graph.NewExecutableSchema(cfg))
//
//	// 2. wrap it with GraphQLShield (one line)
//	s := graphqlshield.New(
//	    graphqlshield.WithMaxDepth(5),
//	    graphqlshield.WithBlockIntrospection(),
//	    graphqlshield.WithBlockSensitiveFields("password", "token"),
//	)
//	http.Handle("/graphql", s.Wrap(srv))
//
// # Three layers
//
//  1. Static controls    – MaxDepth (CWE-400), introspection blocking (CWE-200),
//     sensitive-field blocking (CWE-200).
//  2. Runtime sanitizer  – CWE-89/79/78/22/943 on every variable, powered by
//     go-safeinput (github.com/ravisastryk/go-safeinput).
//  3. Resolver auditing  – cryptoguard-go subprocess; see package audit.
package graphqlshield

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"time"
)

// ─── Options ─────────────────────────────────────────────────────────────────

// Option configures a Shield.
type Option func(*Shield)

// WithMaxDepth sets the maximum allowed GraphQL query nesting depth.
// Queries exceeding this limit are rejected with HTTP 400 [CWE-400].
// Sensible production values are 5–8.  Default: 0 (unlimited).
func WithMaxDepth(n int) Option { return func(s *Shield) { s.maxDepth = n } }

// WithBlockIntrospection rejects __schema and __type queries [CWE-200].
func WithBlockIntrospection() Option { return func(s *Shield) { s.blockIntro = true } }

// WithBlockSensitiveFields rejects any query that requests the named fields
// (e.g. "password", "ssn", "creditCard") [CWE-200].
func WithBlockSensitiveFields(fields ...string) Option {
	return func(s *Shield) { s.sensitiveFields = append(s.sensitiveFields, fields...) }
}

// WithLogger sets a custom structured logger.  Defaults to slog.Default().
func WithLogger(l *slog.Logger) Option { return func(s *Shield) { s.log = l } }

// ─── Shield ───────────────────────────────────────────────────────────────────

// Shield is the configured middleware.  Create one with New and reuse it.
type Shield struct {
	maxDepth        int
	blockIntro      bool
	sensitiveFields []string
	log             *slog.Logger
}

// New creates a Shield with the given options.
func New(opts ...Option) *Shield {
	s := &Shield{log: slog.Default()}
	for _, o := range opts {
		o(s)
	}
	return s
}

// Wrap returns an http.Handler that enforces all shield policies before
// delegating to next.  It is compatible with any Go GraphQL HTTP handler.
func (s *Shield) Wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Only inspect POST requests; pass everything else straight through.
		if r.Method != http.MethodPost {
			next.ServeHTTP(w, r)
			return
		}

		start := time.Now()

		// Read and buffer the body so we can inspect it and replay it.
		body, err := io.ReadAll(io.LimitReader(r.Body, 2<<20)) // 2 MiB
		if err != nil {
			s.block(w, r, http.StatusBadRequest, nil)
			return
		}
		r.Body = io.NopCloser(bytes.NewReader(body))

		var req struct {
			Query         string         `json:"query"`
			Variables     map[string]any `json:"variables"`
			OperationName string         `json:"operationName"`
		}
		if err := json.Unmarshal(body, &req); err != nil {
			// Not a JSON GraphQL body (could be multipart upload etc.) — pass through.
			next.ServeHTTP(w, r)
			return
		}

		// ── Layer 1a: depth limit ──────────────────────────────────────────────
		if s.maxDepth > 0 {
			if d := queryDepth(req.Query); d > s.maxDepth {
				s.block(w, r, http.StatusBadRequest, newDepthExceeded(d, s.maxDepth))
				return
			}
		}

		// ── Layer 1b: introspection block ──────────────────────────────────────
		if s.blockIntro && isIntrospection(req.Query) {
			s.block(w, r, http.StatusForbidden, errIntrospectionBlocked)
			return
		}

		// ── Layer 1c: sensitive field block ────────────────────────────────────
		for _, f := range s.sensitiveFields {
			if containsField(req.Query, f) {
				s.block(w, r, http.StatusForbidden, newSensitiveField(f))
				return
			}
		}

		// ── Layer 2: CWE-aware variable sanitization ───────────────────────────
		if len(req.Variables) > 0 {
			if cwe := checkVariables(req.Variables); cwe != nil {
				s.block(w, r, http.StatusBadRequest, cwe)
				return
			}
		}

		// ── All checks passed ──────────────────────────────────────────────────
		s.log.Debug("graphqlshield: passed",
			"op", req.OperationName,
			"depth", queryDepth(req.Query),
			"latency_us", time.Since(start).Microseconds(),
		)
		r.Body = io.NopCloser(bytes.NewReader(body))
		next.ServeHTTP(w, r)
	})
}

// ─── block helper ────────────────────────────────────────────────────────────

// block writes a standard GraphQL error response and logs the decision.
//
// The response body matches the GraphQL spec's "errors" shape and carries two
// pieces of metadata in extensions:
//
//   - code     — the CWE identifier (e.g. "CWE-89")
//   - cwe_url  — the MITRE reference URL (e.g. "https://cwe.mitre.org/data/definitions/89.html")
//
// URL resolution is delegated to the package-level URLResolver (see errors.go),
// which is statically loaded by default and pluggable for future dynamic
// sources via SetURLResolver.
func (s *Shield) block(w http.ResponseWriter, r *http.Request, status int, cwe *CWEError) {
	msg, code, url := "blocked by GraphQLShield", "SHIELD_BLOCKED", ""
	if cwe != nil {
		msg, code, url = cwe.Error(), cwe.CWE, cwe.URL()
	}
	s.log.Warn("graphqlshield: blocked",
		"status", status,
		"cwe", code,
		"cwe_url", url,
		"reason", msg,
		"remote", r.RemoteAddr,
	)

	ext := map[string]string{"code": code}
	if url != "" {
		ext["cwe_url"] = url
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"errors": []map[string]any{{
			"message":    msg,
			"extensions": ext,
		}},
	})
}
