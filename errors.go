package graphqlshield

import "fmt"

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
