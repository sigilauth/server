// Package main provides a simple utility to generate Sigil API keys.
//
// Usage:
//   go run cmd/keygen/main.go [keyID]
//
// Example:
//   go run cmd/keygen/main.go production
//   # Output: production=sgk_live_abc123...
package main

import (
	"fmt"
	"os"

	"github.com/sigilauth/server/internal/apikey"
)

func main() {
	keyID := "default"
	if len(os.Args) > 1 {
		keyID = os.Args[1]
	}

	key := apikey.Generate()
	fmt.Printf("%s=%s\n", keyID, key)
	fmt.Fprintf(os.Stderr, "\nAPI key generated for ID: %s\n", keyID)
	fmt.Fprintf(os.Stderr, "Format for SIGIL_API_KEYS: %s=%s\n", keyID, key)
	fmt.Fprintf(os.Stderr, "\nWARNING: This key is shown only once. Save it now.\n")
}
