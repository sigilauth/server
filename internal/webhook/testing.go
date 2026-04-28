package webhook

import (
	"crypto/tls"
	"net/http"
	"time"
)

// DisableSSRFForTesting disables SSRF protection for testing with local servers.
// DO NOT USE IN PRODUCTION.
func (c *Client) DisableSSRFForTesting() {
	c.disableSSRFCheck = true
}

// SetFastRetryForTesting sets fast retry delays for testing (0ms, 10ms, 20ms, 30ms).
// DO NOT USE IN PRODUCTION.
func (c *Client) SetFastRetryForTesting() {
	c.retryDelays = []time.Duration{0, 10 * time.Millisecond, 20 * time.Millisecond, 30 * time.Millisecond}
}

// DisableTLSVerificationForTesting disables TLS certificate verification for tests.
// DO NOT USE IN PRODUCTION - this allows MITM attacks (SIG-2026-003).
func (c *Client) DisableTLSVerificationForTesting() {
	c.httpClient = &http.Client{
		Timeout: Timeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}
}
