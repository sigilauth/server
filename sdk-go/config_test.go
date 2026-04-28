package sigilauth

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestConfigValidation(t *testing.T) {
	tests := []struct {
		name      string
		config    Config
		setupEnv  func()
		wantErr   bool
		errString string
	}{
		{
			name: "valid config with env var",
			config: Config{
				ServiceURL: "https://sigil.example.com",
			},
			setupEnv: func() {
				os.Setenv("SIGIL_API_KEY", "sgk_test_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
			},
			wantErr: false,
		},
		{
			name: "missing service URL",
			config: Config{
				APIKey: "",
			},
			setupEnv: func() {
				os.Setenv("SIGIL_API_KEY", "sgk_test_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
			},
			wantErr:   true,
			errString: "service URL is required",
		},
		{
			name: "hardcoded API key rejected",
			config: Config{
				ServiceURL: "https://sigil.example.com",
				APIKey:     "sgk_test_hardcoded",
			},
			setupEnv: func() {
				os.Unsetenv("SIGIL_API_KEY")
			},
			wantErr:   true,
			errString: "API key must be loaded from environment variable SIGIL_API_KEY",
		},
		{
			name: "missing API key",
			config: Config{
				ServiceURL: "https://sigil.example.com",
			},
			setupEnv: func() {
				os.Unsetenv("SIGIL_API_KEY")
			},
			wantErr:   true,
			errString: "API key is required",
		},
		{
			name: "invalid API key format",
			config: Config{
				ServiceURL: "https://sigil.example.com",
			},
			setupEnv: func() {
				os.Setenv("SIGIL_API_KEY", "invalid_key")
			},
			wantErr:   true,
			errString: "API key must start with sgk_live_ or sgk_test_",
		},
		{
			name: "invalid service URL",
			config: Config{
				ServiceURL: "not-a-url",
			},
			setupEnv: func() {
				os.Setenv("SIGIL_API_KEY", "sgk_test_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
			},
			wantErr:   true,
			errString: "service URL must be a valid HTTPS URL",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.setupEnv()
			defer os.Unsetenv("SIGIL_API_KEY")

			err := tt.config.Validate()
			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errString)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestConfigLoadAPIKey(t *testing.T) {
	tests := []struct {
		name     string
		envValue string
		want     string
		wantErr  bool
	}{
		{
			name:     "load from env",
			envValue: "sgk_test_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			want:     "sgk_test_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			wantErr:  false,
		},
		{
			name:     "missing env var",
			envValue: "",
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.envValue != "" {
				os.Setenv("SIGIL_API_KEY", tt.envValue)
				defer os.Unsetenv("SIGIL_API_KEY")
			} else {
				os.Unsetenv("SIGIL_API_KEY")
			}

			cfg := Config{ServiceURL: "https://sigil.example.com"}
			err := cfg.loadAPIKey()

			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.want, cfg.APIKey)
			}
		})
	}
}

func TestRedactAPIKey(t *testing.T) {
	tests := []struct {
		name   string
		apiKey string
		want   string
	}{
		{
			name:   "normal key",
			apiKey: "sgk_test_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			want:   "sgk_test_****cdef",
		},
		{
			name:   "short key",
			apiKey: "sgk_test_abc",
			want:   "sgk_test_****_abc",
		},
		{
			name:   "empty key",
			apiKey: "",
			want:   "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := redactAPIKey(tt.apiKey)
			assert.Equal(t, tt.want, got)
		})
	}
}
