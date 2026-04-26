package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"sort"

	"github.com/sigilauth/server/internal/crypto"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "Usage: sigil-cryptosign <domain> [flags]")
		fmt.Fprintln(os.Stderr, "Domains: auth, mpa, decrypt, conv")
		os.Exit(1)
	}

	domain := os.Args[1]
	switch domain {
	case "auth":
		runAuthSign(os.Args[2:])
	case "mpa":
		runMPASign(os.Args[2:])
	case "decrypt":
		runDecryptSign(os.Args[2:])
	case "conv":
		runConvSign(os.Args[2:])
	default:
		fmt.Fprintf(os.Stderr, "Unknown domain: %s\n", domain)
		os.Exit(1)
	}
}

func runAuthSign(args []string) {
	if len(args) < 6 {
		fmt.Fprintln(os.Stderr, "Usage: sigil-cryptosign auth --priv-hex <hex> --challenge-hex <hex> --action-context-json '<json>'")
		os.Exit(1)
	}

	var privHex, challengeHex, actionContextJSON string
	for i := 0; i < len(args); i += 2 {
		if i+1 >= len(args) {
			break
		}
		switch args[i] {
		case "--priv-hex":
			privHex = args[i+1]
		case "--challenge-hex":
			challengeHex = args[i+1]
		case "--action-context-json":
			actionContextJSON = args[i+1]
		}
	}

	privKeyBytes, err := hex.DecodeString(privHex)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Invalid private key hex: %v\n", err)
		os.Exit(1)
	}

	challengeBytes, err := hex.DecodeString(challengeHex)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Invalid challenge hex: %v\n", err)
		os.Exit(1)
	}
	if len(challengeBytes) != 32 {
		fmt.Fprintf(os.Stderr, "Challenge must be 32 bytes, got %d\n", len(challengeBytes))
		os.Exit(1)
	}

	canonicalJSON, err := canonicalizeJSON(actionContextJSON)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to canonicalize action_context: %v\n", err)
		os.Exit(1)
	}

	actionHash := sha256.Sum256([]byte(canonicalJSON))
	message := append(challengeBytes, actionHash[:]...)

	signAndOutput(privKeyBytes, crypto.DomainAuth, message)
}

func runMPASign(args []string) {
	if len(args) < 4 {
		fmt.Fprintln(os.Stderr, "Usage: sigil-cryptosign mpa --priv-hex <hex> --message-hex <hex>")
		os.Exit(1)
	}

	var privHex, messageHex string
	for i := 0; i < len(args); i += 2 {
		if i+1 >= len(args) {
			break
		}
		switch args[i] {
		case "--priv-hex":
			privHex = args[i+1]
		case "--message-hex":
			messageHex = args[i+1]
		}
	}

	privKeyBytes, err := hex.DecodeString(privHex)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Invalid private key hex: %v\n", err)
		os.Exit(1)
	}

	messageBytes, err := hex.DecodeString(messageHex)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Invalid message hex: %v\n", err)
		os.Exit(1)
	}

	signAndOutput(privKeyBytes, crypto.DomainMPA, messageBytes)
}

func runDecryptSign(args []string) {
	if len(args) < 4 {
		fmt.Fprintln(os.Stderr, "Usage: sigil-cryptosign decrypt --priv-hex <hex> --message-hex <hex>")
		os.Exit(1)
	}

	var privHex, messageHex string
	for i := 0; i < len(args); i += 2 {
		if i+1 >= len(args) {
			break
		}
		switch args[i] {
		case "--priv-hex":
			privHex = args[i+1]
		case "--message-hex":
			messageHex = args[i+1]
		}
	}

	privKeyBytes, err := hex.DecodeString(privHex)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Invalid private key hex: %v\n", err)
		os.Exit(1)
	}

	messageBytes, err := hex.DecodeString(messageHex)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Invalid message hex: %v\n", err)
		os.Exit(1)
	}

	signAndOutput(privKeyBytes, crypto.DomainDecrypt, messageBytes)
}

func runConvSign(args []string) {
	if len(args) < 4 {
		fmt.Fprintln(os.Stderr, "Usage: sigil-cryptosign conv --priv-hex <hex> --message-hex <hex>")
		os.Exit(1)
	}

	var privHex, messageHex string
	for i := 0; i < len(args); i += 2 {
		if i+1 >= len(args) {
			break
		}
		switch args[i] {
		case "--priv-hex":
			privHex = args[i+1]
		case "--message-hex":
			messageHex = args[i+1]
		}
	}

	privKeyBytes, err := hex.DecodeString(privHex)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Invalid private key hex: %v\n", err)
		os.Exit(1)
	}

	messageBytes, err := hex.DecodeString(messageHex)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Invalid message hex: %v\n", err)
		os.Exit(1)
	}

	signAndOutput(privKeyBytes, crypto.DomainConv, messageBytes)
}

func signAndOutput(privKeyBytes []byte, domainTag string, message []byte) {
	d := new(big.Int).SetBytes(privKeyBytes)
	privKey := &ecdsa.PrivateKey{
		PublicKey: ecdsa.PublicKey{
			Curve: elliptic.P256(),
		},
		D: d,
	}
	privKey.PublicKey.X, privKey.PublicKey.Y = privKey.PublicKey.Curve.ScalarBaseMult(d.Bytes())

	signature, err := crypto.SignWithDomain(privKey, domainTag, message)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Signing failed: %v\n", err)
		os.Exit(1)
	}

	fmt.Println(hex.EncodeToString(signature))
}

func canonicalizeJSON(jsonStr string) (string, error) {
	var data interface{}
	if err := json.Unmarshal([]byte(jsonStr), &data); err != nil {
		return "", err
	}

	canonical := canonicalizeValue(data)
	result, err := json.Marshal(canonical)
	if err != nil {
		return "", err
	}

	return string(result), nil
}

func canonicalizeValue(v interface{}) interface{} {
	switch val := v.(type) {
	case map[string]interface{}:
		keys := make([]string, 0, len(val))
		for k := range val {
			keys = append(keys, k)
		}
		sort.Strings(keys)

		result := make(map[string]interface{})
		for _, k := range keys {
			result[k] = canonicalizeValue(val[k])
		}
		return result
	case []interface{}:
		result := make([]interface{}, len(val))
		for i, item := range val {
			result[i] = canonicalizeValue(item)
		}
		return result
	default:
		return val
	}
}
