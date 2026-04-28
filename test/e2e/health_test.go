package e2e

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Health check tests verify the docker-compose stack is running correctly.
// These tests run first to validate the test environment before E2E scenarios.

func getSigilURL() string {
	if url := os.Getenv("SIGIL_SERVER_URL"); url != "" {
		return url
	}
	return "https://localhost:8443"
}

func getRelayURL() string {
	if url := os.Getenv("SIGIL_RELAY_URL"); url != "" {
		return url
	}
	return "http://localhost:8080"
}

// newHTTPClient creates an HTTP client for test requests.
// Skips TLS verification for self-signed certs in test environment.
func newHTTPClient() *http.Client {
	return &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}
}

// TestSigilHealth verifies the Sigil server is reachable.
func TestSigilHealth(t *testing.T) {
	requireDockerStack(t)

	client := newHTTPClient()
	url := getSigilURL() + "/health"

	resp, err := client.Get(url)
	require.NoError(t, err, "failed to reach Sigil server at %s", url)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode, "Sigil health check failed")

	body, _ := io.ReadAll(resp.Body)
	t.Logf("Sigil health response: %s", string(body))
}

// TestRelayHealth verifies the push relay is reachable.
func TestRelayHealth(t *testing.T) {
	requireDockerStack(t)

	client := newHTTPClient()
	url := getRelayURL() + "/health"

	resp, err := client.Get(url)
	require.NoError(t, err, "failed to reach relay at %s", url)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode, "Relay health check failed")

	body, _ := io.ReadAll(resp.Body)
	t.Logf("Relay health response: %s", string(body))
}

// TestSigilInfo verifies the Sigil /info endpoint returns expected structure.
func TestSigilInfo(t *testing.T) {
	requireDockerStack(t)

	client := newHTTPClient()
	url := getSigilURL() + "/info"

	resp, err := client.Get(url)
	require.NoError(t, err, "failed to reach Sigil /info")
	defer resp.Body.Close()

	// Info endpoint might return 501 if stub, 200 if implemented
	if resp.StatusCode == http.StatusNotImplemented {
		t.Skip("Sigil /info returns 501 (stub) - awaiting B1 implementation")
	}

	require.Equal(t, http.StatusOK, resp.StatusCode)

	var info struct {
		ServerID        string   `json:"server_id"`
		ServerName      string   `json:"server_name"`
		ServerPublicKey string   `json:"server_public_key"`
		ServerPictogram []string `json:"server_pictogram"`
		Version         string   `json:"version"`
		Mode            string   `json:"mode"`
	}

	body, _ := io.ReadAll(resp.Body)
	err = json.Unmarshal(body, &info)
	require.NoError(t, err, "failed to parse /info response")

	assert.NotEmpty(t, info.ServerPublicKey, "server_public_key should be present")
	assert.Len(t, info.ServerPictogram, 5, "server_pictogram should have 5 emojis")

	t.Logf("Sigil server: %s (mode: %s, version: %s)", info.ServerName, info.Mode, info.Version)
}

// TestRelayDevicesEndpoint checks if relay registration endpoint exists.
func TestRelayDevicesEndpoint(t *testing.T) {
	requireDockerStack(t)

	client := newHTTPClient()
	url := getRelayURL() + "/devices/register"

	// Just check the endpoint exists (should return 400 or 405 for GET, 501 for stub)
	resp, err := client.Get(url)
	require.NoError(t, err, "failed to reach relay /devices/register")
	defer resp.Body.Close()

	// 405 = endpoint exists, method not allowed (good)
	// 501 = stub not implemented yet
	// 400 = endpoint exists, bad request (good)
	// 404 = endpoint doesn't exist yet
	validCodes := []int{
		http.StatusMethodNotAllowed,
		http.StatusNotImplemented,
		http.StatusBadRequest,
	}

	found := false
	for _, code := range validCodes {
		if resp.StatusCode == code {
			found = true
			break
		}
	}

	if resp.StatusCode == http.StatusNotFound {
		t.Skip("Relay /devices/register returns 404 - awaiting B2 implementation")
	}

	assert.True(t, found, "unexpected status code: %d", resp.StatusCode)
	t.Logf("Relay /devices/register status: %d", resp.StatusCode)
}

// TestStackEndpoints provides a summary of endpoint availability.
func TestStackEndpoints(t *testing.T) {
	requireDockerStack(t)

	client := newHTTPClient()

	endpoints := []struct {
		name   string
		url    string
		method string
	}{
		{"Sigil /health", getSigilURL() + "/health", "GET"},
		{"Sigil /info", getSigilURL() + "/info", "GET"},
		{"Sigil /challenge", getSigilURL() + "/challenge", "POST"},
		{"Sigil /respond", getSigilURL() + "/respond", "POST"},
		{"Sigil /mpa/request", getSigilURL() + "/mpa/request", "POST"},
		{"Sigil /mpa/respond", getSigilURL() + "/mpa/respond", "POST"},
		{"Sigil /v1/secure/decrypt", getSigilURL() + "/v1/secure/decrypt", "POST"},
		{"Relay /health", getRelayURL() + "/health", "GET"},
		{"Relay /devices/register", getRelayURL() + "/devices/register", "POST"},
		{"Relay /push", getRelayURL() + "/push", "POST"},
	}

	t.Log("\n=== Endpoint Availability ===")
	for _, ep := range endpoints {
		var resp *http.Response
		var err error

		if ep.method == "GET" {
			resp, err = client.Get(ep.url)
		} else {
			resp, err = client.Post(ep.url, "application/json", nil)
		}

		status := "❌ ERROR"
		if err == nil {
			defer resp.Body.Close()
			switch resp.StatusCode {
			case http.StatusOK, http.StatusCreated:
				status = "✅ OK"
			case http.StatusBadRequest, http.StatusUnauthorized, http.StatusMethodNotAllowed:
				status = "✅ EXISTS (needs auth/body)"
			case http.StatusNotImplemented:
				status = "⏳ STUB (501)"
			case http.StatusNotFound:
				status = "❌ NOT FOUND"
			default:
				status = fmt.Sprintf("⚠️  %d", resp.StatusCode)
			}
		}

		t.Logf("  %s: %s", ep.name, status)
	}
}
