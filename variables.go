package graphqlshield

import (
	"fmt"
	"regexp"
	"strings"

	safeinput "github.com/ravisastryk/go-safeinput"
)

// nosqlRe detects MongoDB operator injection patterns inside string values.
// e.g. {"$ne": null}, {"$where": "..."}, {"$gt": ""}
var nosqlRe = regexp.MustCompile(
	`\$(?:ne|eq|gt|gte|lt|lte|in|nin|and|or|not|nor|exists|type|mod|regex|where|all|size|elemMatch|slice)\b`,
)

// cmdInjRe detects actual shell injection patterns: command substitution,
// backticks, pipes, semicolons, etc. — not benign characters like @ that
// safeinput.ShellArg also strips.
var cmdInjRe = regexp.MustCompile(
	`\$\(|` + // $(...)
		"`" + `|` + // backtick substitution
		`[;|&]` + `|` + // command chaining
		`>\s*/` + `|` + // redirect to absolute path
		`<\(`, // process substitution
)

// san is the shared go-safeinput sanitizer (goroutine-safe).
var san = safeinput.Default()

// checkVariables walks every string in the GraphQL variables map and runs the
// full go-safeinput CWE pipeline on each value.
// Returns the first violation found, or nil when all values are clean.
func checkVariables(vars map[string]any) *CWEError {
	for k, v := range vars {
		if err := checkValue(k, v); err != nil {
			return err
		}
	}
	return nil
}

func checkValue(key string, v any) *CWEError {
	switch val := v.(type) {
	case string:
		return checkString(key, val)
	case map[string]any:
		return checkVariables(val)
	case []any:
		for i, item := range val {
			if s, ok := item.(string); ok {
				if err := checkString(fmt.Sprintf("%s[%d]", key, i), s); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

// checkString applies each security check in order, returning on first hit.
func checkString(field, value string) *CWEError {
	// ── CWE-89: SQL Injection ─────────────────────────────────────────────────
	// go-safeinput SQLValue.Sanitize returns a non-nil error on injection patterns.
	if _, err := san.Sanitize(value, safeinput.SQLValue); err != nil {
		return newSQLi(field)
	}

	// ── CWE-79: XSS ───────────────────────────────────────────────────────────
	// SanitizeBody strips dangerous HTML; if output ≠ input the value was dirty.
	if cleaned, _ := san.Sanitize(value, safeinput.HTMLBody); cleaned != value {
		return newXSS(field)
	}

	// ── CWE-78: OS Command Injection ──────────────────────────────────────────
	// Use a targeted regex for dangerous shell patterns rather than ShellArg,
	// which strips benign characters like @ that appear in emails.
	if cmdInjRe.MatchString(value) {
		return newCmdInjection(field)
	}

	// ── CWE-22: Path Traversal ────────────────────────────────────────────────
	// FilePath.Sanitize errors on ../ sequences and absolute path escapes.
	if _, err := san.Sanitize(value, safeinput.FilePath); err != nil {
		return newPathTraversal(field)
	}

	// ── CWE-943: NoSQL Injection ──────────────────────────────────────────────
	// go-safeinput has no NoSQL context; a targeted regexp covers it.
	if nosqlRe.MatchString(value) {
		return newNoSQLInjection(field)
	}

	// ── CWE-601: Open Redirect (bonus) ────────────────────────────────────────
	if strings.HasPrefix(strings.ToLower(strings.TrimSpace(value)), "javascript:") {
		return &CWEError{CWE: "CWE-601", Name: "Open Redirect", Field: field,
			Detail: "javascript: URI scheme blocked"}
	}

	return nil
}
