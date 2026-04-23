package webhook

import "time"

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
