package sigilauth

import (
	"errors"
	"os"
	"strings"
	"time"
)

var (
	ErrServiceURLRequired = errors.New("service URL is required")
	ErrAPIKeyRequired     = errors.New("API key is required")
	ErrAPIKeyHardcoded    = errors.New("API key must be loaded from environment variable SIGIL_API_KEY")
	ErrInvalidAPIKey      = errors.New("API key must start with sgk_live_ or sgk_test_")
	ErrInvalidServiceURL  = errors.New("service URL must be a valid HTTPS URL")
)

type Config struct {
	ServiceURL string
	APIKey     string

	HTTPTimeout  time.Duration
	MaxRetries   int
	RetryWaitMin time.Duration
	RetryWaitMax time.Duration

	TLSCertPinning []string
}

func (c *Config) Validate() error {
	if c.ServiceURL == "" {
		return ErrServiceURLRequired
	}

	if !strings.HasPrefix(c.ServiceURL, "https://") {
		return ErrInvalidServiceURL
	}

	if c.APIKey != "" {
		return ErrAPIKeyHardcoded
	}

	if err := c.loadAPIKey(); err != nil {
		return err
	}

	if !strings.HasPrefix(c.APIKey, "sgk_live_") && !strings.HasPrefix(c.APIKey, "sgk_test_") {
		return ErrInvalidAPIKey
	}

	if c.HTTPTimeout == 0 {
		c.HTTPTimeout = 30 * time.Second
	}

	if c.MaxRetries == 0 {
		c.MaxRetries = 3
	}

	if c.RetryWaitMin == 0 {
		c.RetryWaitMin = 100 * time.Millisecond
	}

	if c.RetryWaitMax == 0 {
		c.RetryWaitMax = 400 * time.Millisecond
	}

	return nil
}

func (c *Config) loadAPIKey() error {
	apiKey := os.Getenv("SIGIL_API_KEY")
	if apiKey == "" {
		return ErrAPIKeyRequired
	}
	c.APIKey = apiKey
	return nil
}

func redactAPIKey(key string) string {
	if key == "" {
		return ""
	}
	if len(key) <= 7 {
		return "***_" + key[len(key)-3:]
	}
	return key[:9] + "****" + key[len(key)-4:]
}
