package harness

import (
	"context"
	"fmt"
)

// ServerConfig holds configuration for connecting to a Sigil server.
type ServerConfig struct {
	ServerURL   string
	RelayURL    string
	ServerID    string
	Name        string
	PublicKey   []byte
	Pictogram   []string
	Speakable   string
}

// RegisterWithRelay registers the device's push token with the relay.
// BLOCKED: Requires B2 (relay) to be implemented.
func (d *SimulatedDevice) RegisterWithRelay(ctx context.Context, relayURL, pushToken string) error {
	return fmt.Errorf("BLOCKED: B2 (relay) not implemented - RegisterWithRelay pending")
}

// RespondToChallenge signs and submits a challenge response to the server.
// BLOCKED: Requires B1 (server) to be implemented.
func (d *SimulatedDevice) RespondToChallenge(ctx context.Context, challengeID string, approve bool) error {
	return fmt.Errorf("BLOCKED: B1 (server) not implemented - RespondToChallenge pending")
}

// RespondToMPA signs and submits an MPA response to the server.
// BLOCKED: Requires B1 (server) to be implemented.
func (d *SimulatedDevice) RespondToMPA(ctx context.Context, requestID string, approve bool) error {
	return fmt.Errorf("BLOCKED: B1 (server) not implemented - RespondToMPA pending")
}

// ReceivePush simulates receiving a push notification from the mock relay.
// Returns the challenge that was pushed.
// BLOCKED: Requires B2 (relay) mock to be implemented.
func (d *SimulatedDevice) ReceivePush(ctx context.Context) (*Challenge, error) {
	return nil, fmt.Errorf("BLOCKED: B2 (relay) mock not implemented - ReceivePush pending")
}

// VerifyServerSignature verifies the server's signature on a challenge.
// BLOCKED: Requires B1 (server) public key format to be finalized.
func (d *SimulatedDevice) VerifyServerSignature(challenge *Challenge, serverPubKey []byte) error {
	return fmt.Errorf("BLOCKED: B1 (server) not implemented - VerifyServerSignature pending")
}
