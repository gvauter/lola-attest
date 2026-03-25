// lola-attest reads a Lola module directory and outputs an in-toto Statement v1
// attestation with the module's structure as the predicate. The output is JSON
// written to stdout, suitable for piping to ampel verify.
//
// Usage:
//
//	lola-attest <module-directory>
//	lola-attest ./module/ > module.intoto.json
package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/gvauter/lola-attest/attest"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintf(os.Stderr, "Usage: lola-attest <module-directory>\n")
		os.Exit(1)
	}

	dir := os.Args[1]

	info, err := os.Stat(dir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	if !info.IsDir() {
		fmt.Fprintf(os.Stderr, "Error: %s is not a directory\n", dir)
		os.Exit(1)
	}

	stmt, err := attest.BuildStatement(dir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(stmt); err != nil {
		fmt.Fprintf(os.Stderr, "Error encoding JSON: %v\n", err)
		os.Exit(1)
	}
}
