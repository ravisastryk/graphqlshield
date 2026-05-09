// audit-demo demonstrates GraphQLShield Layer 3: resolver code auditing.
//
// Run:
//
//	go run main.go
//
// For deeper analysis, install cryptoguard-go first:
//
//	go install github.com/ravisastryk/cryptoguard-go/cmd/cryptoguard@latest
//	go run main.go
package main

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/ravisastryk/graphqlshield/audit"
)

func main() {
	// Resolve resolvers/ next to this source file so the demo runs from any CWD,
	// e.g. `go run examples/audit-demo/main.go` from the repo root.
	_, thisFile, _, _ := runtime.Caller(0)
	dir := filepath.Join(filepath.Dir(thisFile), "resolvers")
	fmt.Println("GraphQLShield - Layer 3: Resolver Audit")
	fmt.Println(strings.Repeat("-", 40))
	fmt.Printf("\nScanning: %s\n\n", dir)

	// Built-in scanner — works without any extra tools
	fmt.Println("-- Built-in scanner ------------------------------------")
	findings, err := audit.RunBuiltin(dir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	audit.PrintReport(findings)

	// cryptoguard-go — deeper AST + taint analysis
	fmt.Println("-- cryptoguard-go (deeper analysis) --------------------")
	cgf, err := audit.Scan(dir + "/...")
	if err != nil {
		fmt.Printf("INFO  %v\n\n", err)
	} else {
		audit.PrintReport(cgf)
	}

	// CI gate: exit non-zero on CRITICAL
	for _, f := range findings {
		if f.Severity == "CRITICAL" {
			fmt.Fprintln(os.Stderr, "FAIL  CRITICAL findings -- failing CI")
			os.Exit(2)
		}
	}
}
