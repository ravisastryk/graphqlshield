// Package audit implements GraphQLShield Layer 3: resolver code auditing.
//
// It uses cryptoguard-go (github.com/ravisastryk/cryptoguard-go) as a
// subprocess when installed, falling back to a built-in regexp scanner that
// covers the most critical CWE classes with no extra tooling.
//
// # Quick start
//
//	findings, _ := audit.RunBuiltin("./resolvers")
//	audit.PrintReport(findings)
//
//	// With cryptoguard-go installed (deeper AST + taint analysis):
//	// go install github.com/ravisastryk/cryptoguard-go/cmd/cryptoguard@latest
//	findings, _ = audit.Scan("./resolvers/...")
//	audit.PrintReport(findings)
package audit

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
)

// Finding represents one security issue discovered in resolver source code.
type Finding struct {
	CWE      string // e.g. "CWE-327"
	Severity string // CRITICAL | HIGH | MEDIUM | LOW
	Rule     string // e.g. "CRYPTO001"
	Message  string
	File     string
	Line     int
}

// ─── cryptoguard-go integration ───────────────────────────────────────────────

// Scan invokes cryptoguard-go and returns parsed findings.
// If cryptoguard is not installed, returns an error — use RunBuiltin instead.
func Scan(pkgPattern string) ([]Finding, error) {
	cg, err := exec.LookPath("cryptoguard")
	if err != nil {
		return nil, fmt.Errorf(
			"cryptoguard not found in PATH\n" +
				"Install: go install github.com/ravisastryk/cryptoguard-go/cmd/cryptoguard@latest",
		)
	}
	out, _ := exec.Command(cg, pkgPattern).CombinedOutput()
	return parseCryptoguardOutput(string(out)), nil
}

// parseCryptoguardOutput converts cryptoguard-go text output to findings.
func parseCryptoguardOutput(out string) []Finding {
	var (
		sevRE  = regexp.MustCompile(`^(CRITICAL|HIGH|MEDIUM|LOW):\s+(.+)`)
		ruleRE = regexp.MustCompile(`Rule:\s+(\S+)\s+\((\S+)\)`)
		fileRE = regexp.MustCompile(`File:\s+(.+):(\d+)`)

		findings []Finding
		cur      Finding
	)
	for line := range strings.SplitSeq(out, "\n") {
		if m := sevRE.FindStringSubmatch(line); m != nil {
			if cur.Severity != "" {
				findings = append(findings, cur)
			}
			cur = Finding{Severity: m[1], Message: m[2]}
		} else if m := ruleRE.FindStringSubmatch(line); m != nil {
			cur.Rule, cur.CWE = m[1], m[2]
		} else if m := fileRE.FindStringSubmatch(line); m != nil {
			cur.File = m[1]
			_, _ = fmt.Sscanf(m[2], "%d", &cur.Line)
		}
	}
	if cur.Severity != "" {
		findings = append(findings, cur)
	}
	return findings
}

// ─── built-in scanner (no extra tools required) ───────────────────────────────

type rule struct {
	re       *regexp.Regexp
	cwe      string
	severity string
	message  string
}

var builtinRules = []rule{
	{regexp.MustCompile(`md5\.New\b|md5\.Sum\b`), "CWE-327", "HIGH",
		"MD5 is cryptographically broken — use SHA-256 or bcrypt/argon2"},
	{regexp.MustCompile(`sha1\.New\b|sha1\.Sum\b`), "CWE-327", "HIGH",
		"SHA-1 is deprecated for security use — use SHA-256"},
	{regexp.MustCompile(`des\.NewCipher\b`), "CWE-327", "HIGH",
		"DES/3DES is insecure — use AES-GCM"},
	{regexp.MustCompile(`rc4\.NewCipher\b`), "CWE-327", "HIGH",
		"RC4 is broken — use ChaCha20-Poly1305 or AES-GCM"},
	{regexp.MustCompile(`rand\.Intn\b|rand\.Int\b|rand\.Float`), "CWE-338", "MEDIUM",
		"math/rand is not cryptographically secure — use crypto/rand"},
	{regexp.MustCompile(`(?i)password\s*(?::?=|:)\s*"[^"]{4,}"`), "CWE-798", "CRITICAL",
		"Hardcoded password literal detected"},
	{regexp.MustCompile(`(?i)secret\s*(?::?=|:)\s*"[^"]{4,}"`), "CWE-798", "CRITICAL",
		"Hardcoded secret literal detected"},
	{regexp.MustCompile(`(?i)api_?key\s*(?::?=|:)\s*"[^"]{4,}"`), "CWE-798", "HIGH",
		"Hardcoded API key detected"},
}

// RunBuiltin scans Go source files under dir using built-in regexp rules.
// No extra tooling is required.
func RunBuiltin(dir string) ([]Finding, error) {
	var findings []Finding
	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || !strings.HasSuffix(path, ".go") {
			return err
		}
		ff, ferr := scanFile(path)
		if ferr != nil {
			return ferr
		}
		findings = append(findings, ff...)
		return nil
	})
	return findings, err
}

func scanFile(path string) ([]Finding, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()

	var findings []Finding
	sc := bufio.NewScanner(f)
	line := 0
	for sc.Scan() {
		line++
		text := sc.Text()
		trimmed := strings.TrimSpace(text)
		if strings.HasPrefix(trimmed, "//") {
			continue // skip comment lines
		}
		for _, r := range builtinRules {
			if r.re.MatchString(text) {
				findings = append(findings, Finding{
					CWE: r.cwe, Severity: r.severity,
					Message: r.message, File: path, Line: line,
				})
			}
		}
	}
	return findings, sc.Err()
}

// ─── reporting ────────────────────────────────────────────────────────────────

// PrintReport writes a human-readable summary to stdout.
func PrintReport(findings []Finding) {
	if len(findings) == 0 {
		fmt.Println("PASS  graphqlshield audit: no issues found")
		return
	}
	fmt.Printf("WARN  graphqlshield audit: %d issue(s)\n\n", len(findings))
	for i, f := range findings {
		fmt.Printf("%d. [%s] %s — %s\n", i+1, f.CWE, f.Severity, f.Message)
		if f.File != "" {
			fmt.Printf("   %s:%d\n", f.File, f.Line)
		}
		fmt.Println()
	}
}
