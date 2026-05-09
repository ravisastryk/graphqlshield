// Package resolvers contains INTENTIONALLY INSECURE code to demonstrate
// GraphQLShield's Layer 3 resolver audit.
//
// DO NOT use in production.
package resolvers

import (
	"crypto/md5"  //nolint:gosec — intentional demo
	"crypto/sha1" //nolint:gosec — intentional demo
	"fmt"
)

// CWE-798: hardcoded credentials
const (
	dbPassword = "sup3rS3cr3t!"      // CWE-798 CRITICAL
	apiSecret  = "sk-live-abc123xyz" // CWE-798 CRITICAL
)

// HashPassword hashes with MD5 — cryptographically broken (CWE-327).
func HashPassword(pw string) string {
	h := md5.New() //nolint:gosec — intentional CWE-327 demo
	h.Write([]byte(pw))
	return fmt.Sprintf("%x", h.Sum(nil))
}

// GenerateToken uses SHA-1 — deprecated for security (CWE-327).
func GenerateToken(userID string) string {
	h := sha1.New() //nolint:gosec — intentional CWE-327 demo
	h.Write([]byte(userID + apiSecret))
	return fmt.Sprintf("%x", h.Sum(nil))
}

// DeleteUser lacks an authorization check (CWE-862).
func DeleteUser(callerID, targetID string) error {
	// BUG: any authenticated user can delete any other user — no role check.
	fmt.Printf("deleting %s (by %s)\n", targetID, callerID)
	return nil
}

// ConnectDB embeds credentials in the connection string (CWE-798).
func ConnectDB() string {
	return fmt.Sprintf("postgres://admin:%s@db:5432/prod", dbPassword)
}
