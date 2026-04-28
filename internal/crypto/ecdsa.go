package crypto

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/big"

	"github.com/codahale/rfc6979"
)

// Sign creates an ECDSA signature for the given message using the private key.
//
// Returns a fixed 64-byte signature (r || s) with RFC 6979 deterministic signing
// and BIP-62 low-S normalization. The message is hashed with SHA-256 before signing.
//
// Uses github.com/codahale/rfc6979 for deterministic nonce generation.
// Guarantees: same private key + message = same signature (no randomness).
func Sign(privateKey *ecdsa.PrivateKey, message []byte) ([]byte, error) {
	hash := sha256.Sum256(message)

	// RFC 6979 deterministic signing (codahale library)
	r, s, err := rfc6979.SignECDSA(privateKey, hash[:], sha256.New)
	if err != nil {
		return nil, fmt.Errorf("RFC 6979 signing failed: %w", err)
	}

	// BIP-62 low-S normalization
	curve := privateKey.Curve
	halfOrder := HalfOrder(curve)

	if s.Cmp(halfOrder) > 0 {
		s = new(big.Int).Sub(curve.Params().N, s)
	}

	// Convert to 64-byte fixed format (r || s)
	signature := make([]byte, 64)
	r.FillBytes(signature[0:32])
	s.FillBytes(signature[32:64])

	return signature, nil
}

// SignWithDomain creates an ECDSA signature with domain separation.
//
// Prepends the domain tag to the message before hashing and signing.
// Per api/domain-separation.md, prevents cross-protocol signature replay.
//
// Algorithm: signature = ECDSA-Sign(SHA256(domain_tag || message))
func SignWithDomain(privateKey *ecdsa.PrivateKey, domainTag string, message []byte) ([]byte, error) {
	tagged := make([]byte, 0, len(domainTag)+len(message))
	tagged = append(tagged, []byte(domainTag)...)
	tagged = append(tagged, message...)

	return Sign(privateKey, tagged)
}

// Verify checks an ECDSA signature against a message and public key.
//
// Signature must be exactly 64 bytes (r || s). Message is hashed with SHA-256.
// Rejects high-S signatures per BIP-62 (SIG-2026-002) to prevent signature malleability.
func Verify(publicKey *ecdsa.PublicKey, message, signature []byte) error {
	if len(signature) != 64 {
		return fmt.Errorf("signature must be 64 bytes, got %d", len(signature))
	}

	hash := sha256.Sum256(message)

	r := new(big.Int).SetBytes(signature[0:32])
	s := new(big.Int).SetBytes(signature[32:64])

	// BIP-62: Reject high-S signatures (SIG-2026-002)
	// Malicious signatures can have s > order/2, which creates signature malleability
	curve := publicKey.Curve
	halfOrder := HalfOrder(curve)
	if s.Cmp(halfOrder) > 0 {
		return fmt.Errorf("signature rejected: high-S value violates BIP-62 (s > order/2)")
	}

	if !ecdsa.Verify(publicKey, hash[:], r, s) {
		return fmt.Errorf("invalid signature")
	}

	return nil
}

// VerifyWithDomain checks an ECDSA signature with domain separation.
//
// Prepends the domain tag to the message before hashing and verifying.
// Per api/domain-separation.md, prevents cross-protocol signature replay.
//
// Algorithm: verify ECDSA-Verify(SHA256(domain_tag || message), signature)
func VerifyWithDomain(publicKey *ecdsa.PublicKey, domainTag string, message, signature []byte) error {
	tagged := make([]byte, 0, len(domainTag)+len(message))
	tagged = append(tagged, []byte(domainTag)...)
	tagged = append(tagged, message...)

	return Verify(publicKey, tagged, signature)
}

// HalfOrder returns N/2 where N is the curve order.
// Used for low-S normalization check.
func HalfOrder(curve elliptic.Curve) *big.Int {
	return new(big.Int).Rsh(curve.Params().N, 1)
}

// ExtractS extracts the S component from a 64-byte signature.
func ExtractS(signature []byte) *big.Int {
	if len(signature) != 64 {
		return nil
	}
	return new(big.Int).SetBytes(signature[32:64])
}

// CompressPublicKey converts an ECDSA public key to compressed 33-byte format.
//
// Format: 0x02/0x03 (Y parity) + X coordinate (32 bytes)
func CompressPublicKey(publicKey *ecdsa.PublicKey) []byte {
	compressed := make([]byte, 33)

	publicKey.X.FillBytes(compressed[1:33])

	if publicKey.Y.Bit(0) == 0 {
		compressed[0] = 0x02
	} else {
		compressed[0] = 0x03
	}

	return compressed
}

// DecompressPublicKey reconstructs a public key from compressed 33-byte format.
//
// Returns error if the compressed key is invalid or not on the curve.
func DecompressPublicKey(compressed []byte) (*ecdsa.PublicKey, error) {
	if len(compressed) != 33 {
		return nil, fmt.Errorf("compressed public key must be 33 bytes, got %d", len(compressed))
	}

	prefix := compressed[0]
	if prefix != 0x02 && prefix != 0x03 {
		return nil, fmt.Errorf("invalid compressed key: first byte must be 0x02 or 0x03")
	}

	curve := elliptic.P256()
	params := curve.Params()
	x := new(big.Int).SetBytes(compressed[1:33])

	ySquared := p256Polynomial(x, params)
	y := new(big.Int).ModSqrt(ySquared, params.P)

	if y == nil {
		return nil, fmt.Errorf("invalid compressed key: point not on curve")
	}

	if (prefix == 0x02 && y.Bit(0) == 1) || (prefix == 0x03 && y.Bit(0) == 0) {
		y = new(big.Int).Sub(params.P, y)
	}

	publicKey := &ecdsa.PublicKey{
		Curve: curve,
		X:     x,
		Y:     y,
	}

	if !curve.IsOnCurve(x, y) {
		return nil, fmt.Errorf("decompressed point is not on curve")
	}

	return publicKey, nil
}

// p256Polynomial computes y^2 = x^3 - 3x + b (mod p) for P-256
func p256Polynomial(x *big.Int, params *elliptic.CurveParams) *big.Int {
	x3 := new(big.Int).Mul(x, x)
	x3.Mul(x3, x)

	threeX := new(big.Int).Lsh(x, 1)
	threeX.Add(threeX, x)

	x3.Sub(x3, threeX)
	x3.Add(x3, params.B)
	x3.Mod(x3, params.P)

	return x3
}

// FingerprintFromPublicKey computes SHA-256 hash of compressed public key.
//
// This is the canonical device fingerprint used throughout Sigil Auth.
// Returns 32-byte hash.
func FingerprintFromPublicKey(publicKey *ecdsa.PublicKey) []byte {
	compressed := CompressPublicKey(publicKey)
	hash := sha256.Sum256(compressed)
	return hash[:]
}

// FingerprintHex returns hex-encoded fingerprint (64 characters).
func FingerprintHex(fingerprint []byte) string {
	return hex.EncodeToString(fingerprint)
}
