package crypto

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/big"
	"strings"

	"github.com/tyler-smith/go-bip32"
	"github.com/tyler-smith/go-bip39"
)

// GenerateMnemonic generates a new 24-word BIP39 mnemonic from hardware RNG.
//
// Uses crypto/rand for entropy generation (256 bits = 24 words).
// Returns a space-separated lowercase mnemonic per BIP39 specification.
func GenerateMnemonic() (string, error) {
	entropy := make([]byte, 32)
	if _, err := rand.Read(entropy); err != nil {
		return "", fmt.Errorf("failed to generate entropy: %w", err)
	}

	mnemonic, err := bip39.NewMnemonic(entropy)
	if err != nil {
		return "", fmt.Errorf("failed to create mnemonic: %w", err)
	}

	return mnemonic, nil
}

// EntropyToMnemonic converts 32 bytes of entropy to a 24-word BIP39 mnemonic.
//
// Per Knox §3.1: BIP39 English wordlist only for MVP.
func EntropyToMnemonic(entropy []byte) (string, error) {
	if len(entropy) != 32 {
		return "", fmt.Errorf("entropy must be 32 bytes (256 bits), got %d", len(entropy))
	}

	mnemonic, err := bip39.NewMnemonic(entropy)
	if err != nil {
		return "", fmt.Errorf("failed to create mnemonic from entropy: %w", err)
	}

	return mnemonic, nil
}

// MnemonicToEntropy converts a BIP39 mnemonic to 32 bytes of entropy.
//
// Validates checksum and returns error if mnemonic is invalid.
func MnemonicToEntropy(mnemonic string) ([]byte, error) {
	entropy, err := bip39.EntropyFromMnemonic(mnemonic)
	if err != nil {
		return nil, fmt.Errorf("invalid mnemonic: %w", err)
	}

	if len(entropy) != 32 {
		return nil, fmt.Errorf("mnemonic entropy must be 32 bytes, got %d", len(entropy))
	}

	return entropy, nil
}

// VerificationCode computes a 6-character verification code from a mnemonic.
//
// Algorithm per test-vectors/bip39.json:
// 1. Take mnemonic string (space-separated, lowercase, trimmed)
// 2. Compute SHA-256 hash
// 3. Return first 6 hex characters (uppercase)
//
// This enables two-phase mnemonic verification without exposing the full mnemonic.
func VerificationCode(mnemonic string) string {
	normalized := strings.TrimSpace(mnemonic)
	hash := sha256.Sum256([]byte(normalized))
	code := hex.EncodeToString(hash[:])[:6]
	return strings.ToUpper(code)
}

// DeriveServerKeypair derives an ECDSA P-256 keypair from a BIP39 mnemonic.
//
// Path: m/44'/0'/0'/0/0 per Knox §3.1
//
// This is the stateless server's identity. The same mnemonic always produces
// the same keypair (deterministic).
func DeriveServerKeypair(mnemonic string) (*ecdsa.PrivateKey, error) {
	if !bip39.IsMnemonicValid(mnemonic) {
		return nil, fmt.Errorf("invalid mnemonic")
	}

	seed := bip39.NewSeed(mnemonic, "")

	masterKey, err := bip32.NewMasterKey(seed)
	if err != nil {
		return nil, fmt.Errorf("failed to derive master key: %w", err)
	}

	path := []uint32{
		0x8000002C,
		0x80000000,
		0x80000000,
		0,
		0,
	}

	key := masterKey
	for _, index := range path {
		key, err = key.NewChildKey(index)
		if err != nil {
			return nil, fmt.Errorf("failed to derive child key at path: %w", err)
		}
	}

	privateKeyBytes := key.Key
	if len(privateKeyBytes) != 32 {
		return nil, fmt.Errorf("derived key must be 32 bytes, got %d", len(privateKeyBytes))
	}

	d := new(big.Int).SetBytes(privateKeyBytes)
	curve := elliptic.P256()

	privateKey := &ecdsa.PrivateKey{
		D: d,
	}
	privateKey.PublicKey.Curve = curve
	privateKey.PublicKey.X, privateKey.PublicKey.Y = curve.ScalarBaseMult(d.Bytes())

	return privateKey, nil
}
