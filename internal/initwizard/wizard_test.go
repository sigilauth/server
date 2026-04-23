package initwizard_test

import (
	"bytes"
	"strings"
	"testing"

	"github.com/sigilauth/server/internal/initwizard"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewWizard(t *testing.T) {
	wizard := initwizard.New()
	require.NotNil(t, wizard)
}

func TestGenerateMnemonic(t *testing.T) {
	mnemonic, err := initwizard.GenerateMnemonic()
	require.NoError(t, err)

	// BIP39 24-word mnemonic
	words := strings.Fields(mnemonic)
	assert.Len(t, words, 24, "should generate 24-word mnemonic")

	// Each word should be non-empty
	for i, word := range words {
		assert.NotEmpty(t, word, "word %d should not be empty", i+1)
	}

	// Verify mnemonic is valid
	valid := initwizard.ValidateMnemonic(mnemonic)
	assert.True(t, valid, "generated mnemonic should be valid")
}

func TestValidateMnemonic(t *testing.T) {
	// Generate a valid mnemonic
	validMnemonic, _ := initwizard.GenerateMnemonic()
	assert.True(t, initwizard.ValidateMnemonic(validMnemonic))

	// Invalid mnemonic (wrong word)
	invalidMnemonic := "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon invalid"
	assert.False(t, initwizard.ValidateMnemonic(invalidMnemonic))

	// Invalid mnemonic (wrong word count)
	shortMnemonic := "abandon abandon abandon"
	assert.False(t, initwizard.ValidateMnemonic(shortMnemonic))

	// Empty mnemonic
	assert.False(t, initwizard.ValidateMnemonic(""))
}

func TestDeriveServerIdentity(t *testing.T) {
	mnemonic, _ := initwizard.GenerateMnemonic()

	identity, err := initwizard.DeriveServerIdentity(mnemonic)
	require.NoError(t, err)

	// Should have server ID (fingerprint)
	assert.NotEmpty(t, identity.ServerID)
	assert.Len(t, identity.ServerID, 64, "fingerprint should be 64 hex chars")

	// Should have public key
	assert.NotEmpty(t, identity.PublicKey)
	assert.Len(t, identity.PublicKey, 66, "compressed public key should be 66 hex chars (33 bytes)")

	// Should have pictogram
	assert.Len(t, identity.Pictogram, 5, "pictogram should have 5 words")
	assert.NotEmpty(t, identity.PictogramSpeakable)

	// Should have private key (for internal use)
	assert.NotNil(t, identity.PrivateKey)
}

func TestDeriveServerIdentityDeterministic(t *testing.T) {
	mnemonic, _ := initwizard.GenerateMnemonic()

	identity1, _ := initwizard.DeriveServerIdentity(mnemonic)
	identity2, _ := initwizard.DeriveServerIdentity(mnemonic)

	// Same mnemonic should produce same identity
	assert.Equal(t, identity1.ServerID, identity2.ServerID)
	assert.Equal(t, identity1.PublicKey, identity2.PublicKey)
	assert.Equal(t, identity1.Pictogram, identity2.Pictogram)
}

func TestRunInteractive(t *testing.T) {
	// Simulate user choosing to generate new mnemonic
	input := "1\ny\n" // Option 1 (generate), confirm

	wizard := initwizard.New()
	wizard.SetInput(strings.NewReader(input))

	var output bytes.Buffer
	wizard.SetOutput(&output)

	identity, err := wizard.RunInteractive()
	require.NoError(t, err)

	assert.NotEmpty(t, identity.ServerID)
	assert.Len(t, identity.Pictogram, 5)

	// Output should contain mnemonic warning
	outputStr := output.String()
	assert.Contains(t, outputStr, "WRITE DOWN", "should warn user to save mnemonic")
	assert.Contains(t, outputStr, "Pictogram", "should display pictogram")
}

func TestRunInteractiveWithExistingMnemonic(t *testing.T) {
	// Generate a test mnemonic
	testMnemonic, _ := initwizard.GenerateMnemonic()

	// Simulate user entering existing mnemonic
	input := "2\n" + testMnemonic + "\n" // Option 2 (enter existing)

	wizard := initwizard.New()
	wizard.SetInput(strings.NewReader(input))

	var output bytes.Buffer
	wizard.SetOutput(&output)

	identity, err := wizard.RunInteractive()
	require.NoError(t, err)

	assert.NotEmpty(t, identity.ServerID)

	// Verify it's the expected identity
	expectedIdentity, _ := initwizard.DeriveServerIdentity(testMnemonic)
	assert.Equal(t, expectedIdentity.ServerID, identity.ServerID)
}

func TestRunInteractiveInvalidMnemonicRetry(t *testing.T) {
	// Simulate user entering invalid mnemonic, then valid one
	validMnemonic, _ := initwizard.GenerateMnemonic()
	input := "2\ninvalid mnemonic\n" + validMnemonic + "\n"

	wizard := initwizard.New()
	wizard.SetInput(strings.NewReader(input))

	var output bytes.Buffer
	wizard.SetOutput(&output)

	identity, err := wizard.RunInteractive()
	require.NoError(t, err)
	assert.NotEmpty(t, identity.ServerID)

	// Should show error message
	outputStr := output.String()
	assert.Contains(t, outputStr, "Invalid mnemonic", "should show error for invalid mnemonic")
}

func TestSaveToFile(t *testing.T) {
	// Create a temp file
	tmpFile := t.TempDir() + "/sigil-server.key"

	identity := &initwizard.ServerIdentity{
		ServerID:            "test-server-id",
		PublicKey:           "test-public-key",
		Pictogram:           []string{"word1", "word2", "word3", "word4", "word5"},
		PictogramSpeakable:  "word1-word2-word3-word4-word5",
	}

	err := identity.SaveToFile(tmpFile)
	require.NoError(t, err)

	// Load and verify
	loaded, err := initwizard.LoadFromFile(tmpFile)
	require.NoError(t, err)

	assert.Equal(t, identity.ServerID, loaded.ServerID)
	assert.Equal(t, identity.PublicKey, loaded.PublicKey)
	assert.Equal(t, identity.Pictogram, loaded.Pictogram)
}

func TestStateTransition(t *testing.T) {
	wizard := initwizard.New()

	// Initial state should be uninitialized
	assert.Equal(t, "uninitialized", wizard.GetState())

	// Generate identity
	mnemonic, _ := initwizard.GenerateMnemonic()
	identity, _ := initwizard.DeriveServerIdentity(mnemonic)

	// Transition to operational
	err := wizard.TransitionToOperational(identity)
	require.NoError(t, err)

	assert.Equal(t, "operational", wizard.GetState())
}
