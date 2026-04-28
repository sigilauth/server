package sigilauth

import (
	"crypto/tls"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestClientTLSPinning(t *testing.T) {
	t.Run("invalid cert pinning", func(t *testing.T) {
		os.Setenv("SIGIL_API_KEY", "sgk_test_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
		defer os.Unsetenv("SIGIL_API_KEY")

		client, err := New(Config{
			ServiceURL:     "https://sigil.example.com",
			TLSCertPinning: []string{"invalid-cert"},
		})

		require.Error(t, err)
		assert.Nil(t, client)
	})
}

func TestClientTLSMinVersion(t *testing.T) {
	os.Setenv("SIGIL_API_KEY", "sgk_test_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	defer os.Unsetenv("SIGIL_API_KEY")

	client, err := New(Config{
		ServiceURL: "https://sigil.example.com",
	})
	require.NoError(t, err)

	transport := client.httpClient.Transport.(*http.Transport)
	assert.Equal(t, uint16(tls.VersionTLS12), transport.TLSClientConfig.MinVersion)
}

func TestConfigDefaults(t *testing.T) {
	os.Setenv("SIGIL_API_KEY", "sgk_test_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	defer os.Unsetenv("SIGIL_API_KEY")

	cfg := Config{
		ServiceURL: "https://sigil.example.com",
	}

	err := cfg.Validate()
	require.NoError(t, err)

	assert.Equal(t, 30*time.Second, cfg.HTTPTimeout)
	assert.Equal(t, 3, cfg.MaxRetries)
	assert.Equal(t, 100*time.Millisecond, cfg.RetryWaitMin)
	assert.Equal(t, 400*time.Millisecond, cfg.RetryWaitMax)
}
