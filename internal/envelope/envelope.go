package envelope

import (
	"crypto/ecdsa"
	"encoding/base64"
	"encoding/json"
	"fmt"

	"github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
	"github.com/sigilauth/server/internal/crypto"
)

type RequestPayload struct {
	Action    string                 `json:"action"`
	Body      map[string]interface{} `json:"body"`
	Timestamp int64                  `json:"timestamp"`
	Nonce     string                 `json:"nonce"`
	Audience  string                 `json:"audience"`
}

type ResponsePayload struct {
	Status    string                 `json:"status"`
	Body      map[string]interface{} `json:"body"`
	Timestamp int64                  `json:"timestamp"`
	Nonce     string                 `json:"nonce"`
}

type InnerEnvelope struct {
	ClientPublicKey string `json:"client_public_key"`
	Payload         string `json:"payload"`
	Signature       string `json:"signature"`
}

type ResponseInnerEnvelope struct {
	ServerPublicKey string `json:"server_public_key"`
	Payload         string `json:"payload"`
	Signature       string `json:"signature"`
}

type OuterEnvelope struct {
	Envelope string `json:"envelope"`
}

func DecryptRequest(serverPrivateKey *ecdsa.PrivateKey, envelopeB64 string) (*RequestPayload, *ecdsa.PublicKey, error) {
	ciphertext, err := base64.StdEncoding.DecodeString(envelopeB64)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid base64 envelope: %w", err)
	}

	fingerprint := crypto.FingerprintFromPublicKey(&serverPrivateKey.PublicKey)
	innerJSON, err := crypto.Decrypt(serverPrivateKey, ciphertext, fingerprint, "sigil-envelope-v1")
	if err != nil {
		return nil, nil, fmt.Errorf("ECIES decrypt failed: %w", err)
	}

	var inner InnerEnvelope
	if err := json.Unmarshal(innerJSON, &inner); err != nil {
		return nil, nil, fmt.Errorf("invalid inner envelope JSON: %w", err)
	}

	clientPubBytes, err := base64.StdEncoding.DecodeString(inner.ClientPublicKey)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid client public key: %w", err)
	}

	clientPub, err := crypto.DecompressPublicKey(clientPubBytes)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid client public key: %w", err)
	}

	signatureBytes, err := base64.StdEncoding.DecodeString(inner.Signature)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid signature: %w", err)
	}

	if err := crypto.VerifyWithDomain(clientPub, crypto.DomainConv, []byte(inner.Payload), signatureBytes); err != nil {
		return nil, nil, fmt.Errorf("signature verification failed: %w", err)
	}

	var payload RequestPayload
	if err := json.Unmarshal([]byte(inner.Payload), &payload); err != nil {
		return nil, nil, fmt.Errorf("invalid payload JSON: %w", err)
	}

	return &payload, clientPub, nil
}

func EncryptResponse(serverPrivateKey *ecdsa.PrivateKey, clientPub *ecdsa.PublicKey, payload *ResponsePayload) (string, error) {
	payloadJSON, err := canonicalJSON(payload)
	if err != nil {
		return "", fmt.Errorf("failed to canonicalize payload: %w", err)
	}

	signature, err := crypto.SignWithDomain(serverPrivateKey, crypto.DomainConv, payloadJSON)
	if err != nil {
		return "", fmt.Errorf("failed to sign payload: %w", err)
	}

	serverPubCompressed := crypto.CompressPublicKey(&serverPrivateKey.PublicKey)

	inner := ResponseInnerEnvelope{
		ServerPublicKey: base64.StdEncoding.EncodeToString(serverPubCompressed),
		Payload:         string(payloadJSON),
		Signature:       base64.StdEncoding.EncodeToString(signature),
	}

	innerJSON, err := canonicalJSON(inner)
	if err != nil {
		return "", fmt.Errorf("failed to canonicalize inner envelope: %w", err)
	}

	fingerprint := crypto.FingerprintFromPublicKey(clientPub)
	ciphertext, err := crypto.Encrypt(clientPub, innerJSON, fingerprint, "sigil-envelope-v1")
	if err != nil {
		return "", fmt.Errorf("ECIES encrypt failed: %w", err)
	}

	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

func canonicalJSON(v interface{}) ([]byte, error) {
	jsonBytes, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	return jsoncanonicalizer.Transform(jsonBytes)
}
