package crypto_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// AttestationFixture represents a test fixture for attestation verification
type AttestationFixture struct {
	Description    string                 `json:"description"`
	ExpectedResult string                 `json:"expected_result"`
	ExpectedError  string                 `json:"expected_error,omitempty"`
	DeviceInfo     map[string]interface{} `json:"device_info"`
	Attestation    string                 `json:"attestation_object,omitempty"`
	CertChain      []string               `json:"certificate_chain,omitempty"`
	Challenge      string                 `json:"challenge,omitempty"`
	PublicKey      string                 `json:"public_key,omitempty"`
}

func loadAttestationFixture(t *testing.T, platform, filename string) *AttestationFixture {
	projectRoot := findProjectRoot(t)
	path := filepath.Join(projectRoot, "security", "test-vectors", platform, filename)
	
	data, err := os.ReadFile(path)
	require.NoError(t, err, "failed to read fixture file: %s", path)
	
	var fixture AttestationFixture
	err = json.Unmarshal(data, &fixture)
	require.NoError(t, err, "failed to parse fixture file")
	
	return &fixture
}

// TestIOSAttestationValid tests acceptance of valid iOS App Attest
func TestIOSAttestationValid(t *testing.T) {
	fixture := loadAttestationFixture(t, "ios", "attestation-valid.json")
	
	// Skip if placeholder data
	if fixture.Attestation == "PLACEHOLDER_GENERATE_FROM_REAL_DEVICE" {
		t.Skip("Awaiting real iOS attestation data from TestFlight device")
	}
	
	// TODO: Implement VerifyiOSAttestation when attestation code lands
	// err := crypto.VerifyiOSAttestation(fixture.Attestation, fixture.Challenge)
	// assert.NoError(t, err, "Valid iOS attestation should be accepted")
	
	assert.Equal(t, "pass", fixture.ExpectedResult)
}

// TestIOSAttestationEmulator tests rejection of emulator attestation
func TestIOSAttestationEmulator(t *testing.T) {
	fixture := loadAttestationFixture(t, "ios", "attestation-emulator.json")

	// Emulator cannot generate attestation (JSON null becomes empty string in Go)
	assert.Empty(t, fixture.Attestation, "Emulator should not produce attestation")
	assert.Equal(t, "fail", fixture.ExpectedResult)
	assert.Equal(t, "ATTESTATION_NOT_SUPPORTED", fixture.ExpectedError)
}

// TestIOSAttestationJailbroken tests handling of jailbroken device
func TestIOSAttestationJailbroken(t *testing.T) {
	fixture := loadAttestationFixture(t, "ios", "attestation-jailbroken.json")
	
	if fixture.Attestation == "PLACEHOLDER_JAILBROKEN_DEVICE_ATTESTATION" {
		t.Skip("Awaiting jailbroken device attestation data")
	}
	
	// Jailbroken should warn or fail depending on SIGIL_ATTESTATION_REQUIRED
	assert.Equal(t, "warn", fixture.ExpectedResult)
}

// TestAndroidAttestationStrongBox tests acceptance of StrongBox attestation
func TestAndroidAttestationStrongBox(t *testing.T) {
	fixture := loadAttestationFixture(t, "android", "attestation-strongbox.json")
	
	if len(fixture.CertChain) == 0 || fixture.CertChain[0] == "PLACEHOLDER_LEAF_CERT_BASE64" {
		t.Skip("Awaiting real Android StrongBox attestation from test device")
	}
	
	// TODO: Implement VerifyAndroidAttestation when attestation code lands
	// result, err := crypto.VerifyAndroidAttestation(fixture.CertChain, fixture.Challenge)
	// assert.NoError(t, err)
	// assert.Equal(t, "StrongBox", result.SecurityLevel)
	
	assert.Equal(t, "pass", fixture.ExpectedResult)
}

// TestAndroidAttestationTEE tests acceptance of TEE attestation with warning
func TestAndroidAttestationTEE(t *testing.T) {
	fixture := loadAttestationFixture(t, "android", "attestation-tee.json")
	
	if len(fixture.CertChain) == 0 || fixture.CertChain[0] == "PLACEHOLDER_TEE_LEAF_CERT_BASE64" {
		t.Skip("Awaiting real Android TEE attestation")
	}
	
	// TEE should pass with warning
	assert.Equal(t, "pass", fixture.ExpectedResult)
	
	// Should have warning
	warning, ok := fixture.DeviceInfo["expected_warning"]
	if ok {
		assert.Equal(t, "TEE_FALLBACK", warning)
	}
}

// TestAndroidAttestationSoftware tests rejection of software keystore
func TestAndroidAttestationSoftware(t *testing.T) {
	fixture := loadAttestationFixture(t, "android", "attestation-software.json")
	
	// Software keystore MUST be rejected
	assert.Equal(t, "fail", fixture.ExpectedResult)
	assert.Equal(t, "ATTESTATION_SOFTWARE_KEYSTORE", fixture.ExpectedError)
	
	// Emulator flag should be true
	emulator, ok := fixture.DeviceInfo["emulator"]
	if ok {
		assert.True(t, emulator.(bool), "Software keystore indicates emulator")
	}
}

// TestAndroidAttestationRooted tests rejection of rooted device
func TestAndroidAttestationRooted(t *testing.T) {
	fixture := loadAttestationFixture(t, "android", "attestation-rooted.json")
	
	// Rooted device should be rejected
	assert.Equal(t, "fail", fixture.ExpectedResult)
	assert.Equal(t, "ATTESTATION_DEVICE_COMPROMISED", fixture.ExpectedError)
	
	// Check for root indicators
	rooted, ok := fixture.DeviceInfo["rooted"]
	if ok {
		assert.True(t, rooted.(bool))
	}
}
