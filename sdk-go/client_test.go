package sigilauth

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNew(t *testing.T) {
	tests := []struct {
		name     string
		config   Config
		setupEnv func()
		wantErr  bool
	}{
		{
			name: "valid client",
			config: Config{
				ServiceURL: "https://sigil.example.com",
			},
			setupEnv: func() {
				os.Setenv("SIGIL_API_KEY", "sgk_test_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
			},
			wantErr: false,
		},
		{
			name: "invalid config",
			config: Config{
				ServiceURL: "",
			},
			setupEnv: func() {
				os.Setenv("SIGIL_API_KEY", "sgk_test_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.setupEnv()
			defer os.Unsetenv("SIGIL_API_KEY")

			client, err := New(tt.config)
			if tt.wantErr {
				require.Error(t, err)
				assert.Nil(t, client)
			} else {
				require.NoError(t, err)
				require.NotNil(t, client)
				assert.NotNil(t, client.Auth)
				assert.NotNil(t, client.MPA)
				assert.NotNil(t, client.Webhooks)
			}
		})
	}
}

func TestClientHTTPClientDefaults(t *testing.T) {
	os.Setenv("SIGIL_API_KEY", "sgk_test_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	defer os.Unsetenv("SIGIL_API_KEY")

	client, err := New(Config{
		ServiceURL: "https://sigil.example.com",
	})
	require.NoError(t, err)

	assert.Equal(t, "https://sigil.example.com", client.config.ServiceURL)
	assert.NotNil(t, client.httpClient)
	assert.NotZero(t, client.httpClient.Timeout)
}
