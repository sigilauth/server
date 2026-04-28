package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"sort"

	"github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
	"github.com/sigilauth/server/internal/crypto"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "Usage: sigil-cryptosign <domain> [flags]")
		fmt.Fprintln(os.Stderr, "Domains: auth, mpa, decrypt, conv, envelope-decrypt")
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
	case "envelope-decrypt":
		runEnvelopeDecrypt(os.Args[2:])
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

func runEnvelopeDecrypt(args []string) {
	if len(args) < 4 {
		fmt.Fprintln(os.Stderr, "Usage: sigil-cryptosign envelope-decrypt --recipient-priv-hex <hex> --envelope-base64 <base64>")
		os.Exit(1)
	}

	var privHex, envelopeB64 string
	for i := 0; i < len(args); i += 2 {
		if i+1 >= len(args) {
			break
		}
		switch args[i] {
		case "--recipient-priv-hex":
			privHex = args[i+1]
		case "--envelope-base64":
			envelopeB64 = args[i+1]
		}
	}

	if privHex == "" || envelopeB64 == "" {
		fmt.Fprintln(os.Stderr, "missing required arguments")
		os.Exit(1)
	}

	// Parse recipient private key
	privKeyBytes, err := hex.DecodeString(privHex)
	if err != nil || len(privKeyBytes) != 32 {
		fmt.Fprintln(os.Stderr, "invalid recipient private key")
		os.Exit(1)
	}

	d := new(big.Int).SetBytes(privKeyBytes)
	recipientPrivKey := &ecdsa.PrivateKey{
		PublicKey: ecdsa.PublicKey{
			Curve: elliptic.P256(),
		},
		D: d,
	}
	recipientPrivKey.PublicKey.X, recipientPrivKey.PublicKey.Y = recipientPrivKey.PublicKey.Curve.ScalarBaseMult(d.Bytes())

	// Decode base64 envelope
	outerCiphertext, err := base64.StdEncoding.DecodeString(envelopeB64)
	if err != nil {
		fmt.Fprintln(os.Stderr, "ENVELOPE_INVALID")
		os.Exit(2)
	}

	if len(outerCiphertext) < 33+12+16 {
		fmt.Fprintln(os.Stderr, "ENVELOPE_INVALID")
		os.Exit(2)
	}

	// Decrypt ECIES outer layer
	recipientFingerprint := crypto.FingerprintFromPublicKey(&recipientPrivKey.PublicKey)
	innerJSON, err := crypto.Decrypt(recipientPrivKey, outerCiphertext, recipientFingerprint, "SIGIL-CONV-V1-AES256")
	if err != nil {
		fmt.Fprintln(os.Stderr, "ENVELOPE_INVALID")
		os.Exit(2)
	}

	// Parse inner envelope structure
	var innerEnvelope struct {
		ClientPublicKey string `json:"client_public_key"`
		Payload         string `json:"payload"`
		Signature       string `json:"signature"`
	}

	if err := json.Unmarshal(innerJSON, &innerEnvelope); err != nil {
		fmt.Fprintln(os.Stderr, "MALFORMED_ENVELOPE")
		os.Exit(2)
	}

	// Verify required fields
	if innerEnvelope.ClientPublicKey == "" || innerEnvelope.Payload == "" || innerEnvelope.Signature == "" {
		fmt.Fprintln(os.Stderr, "MALFORMED_ENVELOPE")
		os.Exit(2)
	}

	// Decode sender public key
	senderPubKeyBytes, err := base64.StdEncoding.DecodeString(innerEnvelope.ClientPublicKey)
	if err != nil {
		fmt.Fprintln(os.Stderr, "MALFORMED_ENVELOPE")
		os.Exit(2)
	}

	senderPubKey, err := crypto.DecompressPublicKey(senderPubKeyBytes)
	if err != nil {
		fmt.Fprintln(os.Stderr, "MALFORMED_ENVELOPE")
		os.Exit(2)
	}

	// Decode signature
	signature, err := base64.StdEncoding.DecodeString(innerEnvelope.Signature)
	if err != nil {
		fmt.Fprintln(os.Stderr, "MALFORMED_ENVELOPE")
		os.Exit(2)
	}

	// Parse payload and validate required fields (ADV-07 protection)
	var payload struct {
		Action    string                 `json:"action"`
		Nonce     string                 `json:"nonce"`
		Timestamp int64                  `json:"timestamp"`
		Audience  string                 `json:"audience"`
		Body      map[string]interface{} `json:"body"`
	}
	if err := json.Unmarshal([]byte(innerEnvelope.Payload), &payload); err != nil {
		fmt.Fprintln(os.Stderr, "ENVELOPE_INVALID")
		os.Exit(2)
	}

	// Validate all required fields present (ADV-07 protection)
	if payload.Action == "" || payload.Nonce == "" || payload.Timestamp == 0 || payload.Audience == "" || payload.Body == nil {
		fmt.Fprintln(os.Stderr, "ENVELOPE_INVALID")
		os.Exit(2)
	}

	// Re-canonicalize payload before signature verification (ADV-10 protection)
	payloadCanonical, err := jsoncanonicalizer.Transform([]byte(innerEnvelope.Payload))
	if err != nil {
		fmt.Fprintln(os.Stderr, "ENVELOPE_INVALID")
		os.Exit(2)
	}

	// Verify signature with SIGIL-CONV-V1 domain tag against canonical payload
	if err := crypto.VerifyWithDomain(senderPubKey, crypto.DomainConv, payloadCanonical, signature); err != nil {
		fmt.Fprintln(os.Stderr, "INVALID_SIGNATURE")
		os.Exit(2)
	}

	// Output canonical JSON payload
	fmt.Print(string(payloadCanonical))
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
