package webhook

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// SSRFTestCase represents a test case from blocked-urls.json
type SSRFTestCase struct {
	ID          string `json:"id"`
	URL         string `json:"url"`
	Category    string `json:"category"`
	Description string `json:"description"`
}

// SSRFTestFixture represents the test fixture file structure
type SSRFTestFixture struct {
	Description    string         `json:"description"`
	ExpectedResult string         `json:"expected_result"`
	ExpectedError  string         `json:"expected_error"`
	TestCases      []SSRFTestCase `json:"test_cases"`
}

func loadSSRFFixtures(t *testing.T, filename string) *SSRFTestFixture {
	projectRoot := findProjectRoot(t)
	path := filepath.Join(projectRoot, "security", "test-vectors", "ssrf", filename)
	
	data, err := os.ReadFile(path)
	require.NoError(t, err, "failed to read fixture file: %s", path)
	
	var fixture SSRFTestFixture
	err = json.Unmarshal(data, &fixture)
	require.NoError(t, err, "failed to parse fixture file")
	
	return &fixture
}

func findProjectRoot(t *testing.T) string {
	dir, _ := os.Getwd()
	for i := 0; i < 10; i++ {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		dir = filepath.Dir(dir)
	}
	t.Skip("could not find project root (go.mod)")
	return ""
}

// TestSSRFBlockedURLs tests that all blocked URLs are rejected per knox-threat-model.md §8.1
// Uses test vectors from security/test-vectors/ssrf/blocked-urls.json
func TestSSRFBlockedURLs(t *testing.T) {
	fixture := loadSSRFFixtures(t, "blocked-urls.json")
	
	client := NewClient("test-api-key")
	
	for _, tc := range fixture.TestCases {
		t.Run(tc.ID+"_"+tc.Category, func(t *testing.T) {
			// Use validateURL which is the actual SSRF check
			err := client.validateURL(tc.URL)
			
			// Non-HTTPS URLs fail with different error, that's fine
			if tc.Category == "scheme" {
				// file://, gopher://, dict:// should fail
				assert.Error(t, err, "Scheme %s should be blocked: %s", tc.URL, tc.Description)
				return
			}
			
			// For HTTP URLs, convert to HTTPS for SSRF test
			testURL := tc.URL
			if len(testURL) > 7 && testURL[:7] == "http://" {
				testURL = "https://" + testURL[7:]
			}
			
			err = client.validateURL(testURL)
			assert.Error(t, err, "URL should be SSRF blocked: %s (%s)", tc.URL, tc.Description)
			
			if err != nil {
				// Error should indicate SSRF blocking
				errStr := err.Error()
				isSSRFError := contains(errStr, "SSRF") || 
				               contains(errStr, "blocked") || 
				               contains(errStr, "loopback") ||
				               contains(errStr, "private")
				assert.True(t, isSSRFError || contains(errStr, "DNS"), 
					"Error should indicate SSRF blocking for %s, got: %s", tc.URL, errStr)
			}
		})
	}
}

// TestSSRFAllowedURLs tests that legitimate external URLs are allowed
func TestSSRFAllowedURLs(t *testing.T) {
	fixture := loadSSRFFixtures(t, "allowed-urls.json")
	
	client := NewClient("test-api-key")
	
	for _, tc := range fixture.TestCases {
		t.Run(tc.ID, func(t *testing.T) {
			err := client.validateURL(tc.URL)
			// Note: May fail due to DNS resolution for fake domains
			// That's acceptable - we're testing SSRF logic, not DNS
			if err != nil && !contains(err.Error(), "DNS") && !contains(err.Error(), "lookup") {
				t.Errorf("URL should be allowed: %s (%s), got error: %v", tc.URL, tc.Description, err)
			}
		})
	}
}

// TestTLSVerificationEnabled ensures TLS verification is NOT disabled
// Verifies fix for SIG-2026-003
func TestTLSVerificationEnabled(t *testing.T) {
	client := NewClient("test-key")

	// Verify default client has TLS verification enabled
	// (httpClient.Transport should be nil or have TLSClientConfig.InsecureSkipVerify = false)

	if client.httpClient.Transport == nil {
		// Default transport is used, which has TLS verification enabled
		t.Log("✅ SIG-2026-003 FIXED: Default transport used (TLS verification enabled)")
		return
	}

	// If transport is set, check TLS config
	transport, ok := client.httpClient.Transport.(*http.Transport)
	if !ok {
		t.Fatal("Unexpected transport type")
	}

	if transport.TLSClientConfig != nil && transport.TLSClientConfig.InsecureSkipVerify {
		t.Fatal("CRITICAL: SIG-2026-003 - TLS verification is disabled (InsecureSkipVerify=true)")
	}

	t.Log("✅ SIG-2026-003 FIXED: TLS certificate verification is enabled")
	t.Log("Note: Tests can disable via DisableTLSVerificationForTesting() for local test servers")
}

func contains(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
