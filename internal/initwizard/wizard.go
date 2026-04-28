// Package initwizard provides an interactive CLI for initializing the Sigil server.
//
// Workflow:
// 1. Prompt: generate new mnemonic or enter existing
// 2. If generating: display 24-word BIP39 mnemonic with save warning
// 3. If entering: validate mnemonic
// 4. Derive server keypair via BIP32 (m/44'/0'/0'/0/0)
// 5. Display server ID (fingerprint) and pictogram
// 6. Transition state from "uninitialized" to "operational"
// 7. Save identity to file for persistence
package initwizard

import (
	"bufio"
	"crypto/ecdsa"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/sigilauth/server/internal/crypto"
	"github.com/sigilauth/server/pkg/pictogram"
	"github.com/tyler-smith/go-bip39"
)

// ServerIdentity represents the derived server identity from mnemonic.
type ServerIdentity struct {
	ServerID           string   `json:"server_id"`           // Fingerprint hex
	PublicKey          string   `json:"public_key"`          // Compressed public key hex
	Pictogram          []string `json:"pictogram"`           // 5 words
	PictogramSpeakable string   `json:"pictogram_speakable"` // Dash-separated
	PrivateKey         *ecdsa.PrivateKey `json:"-"` // Not serialized
}

// Wizard manages the initialization flow.
type Wizard struct {
	state  string
	input  io.Reader
	output io.Writer
}

// New creates a new initialization wizard.
func New() *Wizard {
	return &Wizard{
		state:  "uninitialized",
		input:  os.Stdin,
		output: os.Stdout,
	}
}

// SetInput sets the input reader (for testing).
func (w *Wizard) SetInput(r io.Reader) {
	w.input = r
}

// SetOutput sets the output writer (for testing).
func (w *Wizard) SetOutput(wr io.Writer) {
	w.output = wr
}

// GetState returns the current wizard state.
func (w *Wizard) GetState() string {
	return w.state
}

// TransitionToOperational transitions the wizard to operational state.
func (w *Wizard) TransitionToOperational(identity *ServerIdentity) error {
	if identity == nil {
		return fmt.Errorf("identity cannot be nil")
	}

	w.state = "operational"
	return nil
}

// GenerateMnemonic generates a new 24-word BIP39 mnemonic.
func GenerateMnemonic() (string, error) {
	entropy, err := bip39.NewEntropy(256) // 256 bits = 24 words
	if err != nil {
		return "", fmt.Errorf("failed to generate entropy: %w", err)
	}

	mnemonic, err := bip39.NewMnemonic(entropy)
	if err != nil {
		return "", fmt.Errorf("failed to generate mnemonic: %w", err)
	}

	return mnemonic, nil
}

// ValidateMnemonic checks if a mnemonic is valid BIP39.
func ValidateMnemonic(mnemonic string) bool {
	return bip39.IsMnemonicValid(mnemonic)
}

// DeriveServerIdentity derives server identity from mnemonic.
//
// Uses BIP32 path m/44'/0'/0'/0/0 to derive server keypair.
// Returns ServerIdentity with fingerprint, public key, and pictogram.
func DeriveServerIdentity(mnemonic string) (*ServerIdentity, error) {
	if !bip39.IsMnemonicValid(mnemonic) {
		return nil, fmt.Errorf("invalid mnemonic")
	}

	// Derive server keypair using existing crypto.DeriveServerKeypair
	privateKey, err := crypto.DeriveServerKeypair(mnemonic)
	if err != nil {
		return nil, fmt.Errorf("failed to derive keypair: %w", err)
	}

	publicKey := &privateKey.PublicKey

	// Generate fingerprint
	fingerprint := crypto.FingerprintFromPublicKey(publicKey)
	fingerprintHex := crypto.FingerprintHex(fingerprint)

	// Compress public key for transmission
	compressedPubKey := crypto.CompressPublicKey(publicKey)

	// Generate pictogram
	pg := pictogram.Derive(fingerprint)

	return &ServerIdentity{
		ServerID:           fingerprintHex,
		PublicKey:          hex.EncodeToString(compressedPubKey),
		Pictogram:          pg.Words,
		PictogramSpeakable: pg.Speakable(),
		PrivateKey:         privateKey,
	}, nil
}

// RunInteractive runs the interactive initialization wizard.
//
// Returns ServerIdentity on success.
func (w *Wizard) RunInteractive() (*ServerIdentity, error) {
	fmt.Fprintln(w.output, "")
	fmt.Fprintln(w.output, "╔═══════════════════════════════════════════════════════════╗")
	fmt.Fprintln(w.output, "║          Sigil Auth Server Initialization                ║")
	fmt.Fprintln(w.output, "╚═══════════════════════════════════════════════════════════╝")
	fmt.Fprintln(w.output, "")
	fmt.Fprintln(w.output, "This wizard will initialize your Sigil Auth server.")
	fmt.Fprintln(w.output, "")
	fmt.Fprintln(w.output, "Choose an option:")
	fmt.Fprintln(w.output, "  1. Generate a new mnemonic")
	fmt.Fprintln(w.output, "  2. Enter an existing mnemonic")
	fmt.Fprintln(w.output, "")
	fmt.Fprint(w.output, "Enter choice (1 or 2): ")

	scanner := bufio.NewScanner(w.input)
	scanner.Scan()
	choice := strings.TrimSpace(scanner.Text())

	var mnemonic string
	var err error

	switch choice {
	case "1":
		// Generate new mnemonic
		mnemonic, err = GenerateMnemonic()
		if err != nil {
			return nil, fmt.Errorf("failed to generate mnemonic: %w", err)
		}

		fmt.Fprintln(w.output, "")
		fmt.Fprintln(w.output, "╔═══════════════════════════════════════════════════════════╗")
		fmt.Fprintln(w.output, "║  ⚠️  CRITICAL: WRITE DOWN THIS MNEMONIC IMMEDIATELY     ║")
		fmt.Fprintln(w.output, "╚═══════════════════════════════════════════════════════════╝")
		fmt.Fprintln(w.output, "")
		fmt.Fprintln(w.output, "Your 24-word recovery mnemonic:")
		fmt.Fprintln(w.output, "")
		fmt.Fprintf(w.output, "  %s\n", mnemonic)
		fmt.Fprintln(w.output, "")
		fmt.Fprintln(w.output, "IMPORTANT:")
		fmt.Fprintln(w.output, "- Write these words on paper and store safely")
		fmt.Fprintln(w.output, "- This mnemonic will NEVER be shown again")
		fmt.Fprintln(w.output, "- Loss of mnemonic = loss of server identity")
		fmt.Fprintln(w.output, "- All devices will need to re-register if lost")
		fmt.Fprintln(w.output, "")
		fmt.Fprint(w.output, "Have you written down the mnemonic? (y/n): ")

		scanner.Scan()
		confirm := strings.ToLower(strings.TrimSpace(scanner.Text()))
		if confirm != "y" && confirm != "yes" {
			return nil, fmt.Errorf("initialization cancelled")
		}

	case "2":
		// Enter existing mnemonic
		fmt.Fprintln(w.output, "")
		fmt.Fprintln(w.output, "Enter your 24-word mnemonic (space-separated):")
		fmt.Fprint(w.output, "> ")

		for {
			scanner.Scan()
			mnemonic = strings.TrimSpace(scanner.Text())

			if ValidateMnemonic(mnemonic) {
				break
			}

			fmt.Fprintln(w.output, "")
			fmt.Fprintln(w.output, "❌ Invalid mnemonic. Please check and try again.")
			fmt.Fprintln(w.output, "")
			fmt.Fprint(w.output, "> ")
		}

	default:
		return nil, fmt.Errorf("invalid choice: %s", choice)
	}

	// Derive server identity
	identity, err := DeriveServerIdentity(mnemonic)
	if err != nil {
		return nil, fmt.Errorf("failed to derive identity: %w", err)
	}

	// Display identity
	fmt.Fprintln(w.output, "")
	fmt.Fprintln(w.output, "╔═══════════════════════════════════════════════════════════╗")
	fmt.Fprintln(w.output, "║              Server Identity Derived                     ║")
	fmt.Fprintln(w.output, "╚═══════════════════════════════════════════════════════════╝")
	fmt.Fprintln(w.output, "")
	fmt.Fprintf(w.output, "Server ID (Fingerprint): %s\n", identity.ServerID)
	fmt.Fprintln(w.output, "")
	fmt.Fprintln(w.output, "Pictogram (for visual verification):")
	for i, word := range identity.Pictogram {
		fmt.Fprintf(w.output, "  %d. %s\n", i+1, word)
	}
	fmt.Fprintf(w.output, "\nSpeakable: %s\n", identity.PictogramSpeakable)
	fmt.Fprintln(w.output, "")
	fmt.Fprintln(w.output, "✅ Initialization complete!")
	fmt.Fprintln(w.output, "")

	return identity, nil
}

// SaveToFile saves server identity to a JSON file.
func (identity *ServerIdentity) SaveToFile(path string) error {
	data, err := json.MarshalIndent(identity, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal identity: %w", err)
	}

	if err := os.WriteFile(path, data, 0600); err != nil {
		return fmt.Errorf("failed to write identity file: %w", err)
	}

	return nil
}

// LoadFromFile loads server identity from a JSON file.
func LoadFromFile(path string) (*ServerIdentity, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read identity file: %w", err)
	}

	var identity ServerIdentity
	if err := json.Unmarshal(data, &identity); err != nil {
		return nil, fmt.Errorf("failed to unmarshal identity: %w", err)
	}

	return &identity, nil
}
