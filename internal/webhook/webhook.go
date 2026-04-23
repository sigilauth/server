// Package webhook handles webhook delivery to integrator applications.
//
// Implements HMAC-SHA256 signature with timestamp, SSRF protection, retries with backoff.
package webhook

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"sync"
	"time"
)

const (
	MaxRetries = 3
	Timeout    = 5 * time.Second
	MaxTimestampAge = 5 * time.Minute
)

// Client manages webhook delivery with retry and circuit breaker.
type Client struct {
	apiKey string
	httpClient *http.Client
	disableSSRFCheck bool
	retryDelays []time.Duration

	mu sync.RWMutex
	circuitBreakers map[string]*circuitBreaker
}

type circuitBreaker struct {
	consecutiveFailures int
	state string
	lastFailure time.Time
}

// NewClient creates a new webhook client.
func NewClient(apiKey string) *Client {
	return &Client{
		apiKey: apiKey,
		httpClient: &http.Client{
			Timeout: Timeout,
			// DO NOT set InsecureSkipVerify - that disables TLS verification (SIG-2026-003)
		},
		retryDelays: []time.Duration{0, 1 * time.Second, 5 * time.Second, 30 * time.Second},
		circuitBreakers: make(map[string]*circuitBreaker),
	}
}

// Deliver sends a webhook with HMAC signature, retries, and SSRF protection.
//
// Per Knox §7.4:
// - HMAC-SHA256(timestamp || body, api_key)
// - Timestamp in X-Sigil-Timestamp header
// - Reject timestamp > 5min old
// - HTTPS only
// - SSRF protection (RFC-1918 + 127/8 + link-local blocked)
// - Retry 3x with backoff (1s, 5s, 30s)
func (c *Client) Deliver(ctx context.Context, webhookURL string, payload []byte) error {
	if err := c.validateURL(webhookURL); err != nil {
		return err
	}

	cb := c.getCircuitBreaker(webhookURL)
	if cb.state == "open" {
		if time.Since(cb.lastFailure) < 30*time.Second {
			return fmt.Errorf("circuit breaker open for %s", webhookURL)
		}
		cb.state = "half-open"
	}

	var lastErr error

	for attempt := 0; attempt <= MaxRetries; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(c.retryDelays[attempt]):
			}
		}

		timestamp := time.Now().Unix()
		signature := ComputeSignature(c.apiKey, payload, timestamp)

		req, err := http.NewRequestWithContext(ctx, "POST", webhookURL, bytes.NewReader(payload))
		if err != nil {
			return fmt.Errorf("failed to create request: %w", err)
		}

		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Sigil-Signature", signature)
		req.Header.Set("X-Sigil-Timestamp", strconv.FormatInt(timestamp, 10))

		resp, err := c.httpClient.Do(req)
		if err != nil {
			lastErr = fmt.Errorf("request failed: %w (will retry if timeout or network error)", err)
			c.recordFailure(webhookURL)
			continue
		}

		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()

		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			c.recordSuccess(webhookURL)
			return nil
		}

		if resp.StatusCode >= 500 {
			lastErr = fmt.Errorf("server error %d (will retry)", resp.StatusCode)
			c.recordFailure(webhookURL)
			continue
		}

		return fmt.Errorf("webhook returned %d (not retrying client error)", resp.StatusCode)
	}

	c.recordFailure(webhookURL)
	return fmt.Errorf("webhook delivery failed after %d attempts: %w", MaxRetries+1, lastErr)
}

// validateURL checks HTTPS and SSRF protection.
func (c *Client) validateURL(webhookURL string) error {
	parsed, err := url.Parse(webhookURL)
	if err != nil {
		return fmt.Errorf("invalid URL: %w", err)
	}

	if parsed.Scheme != "https" {
		return fmt.Errorf("HTTPS required, got %s", parsed.Scheme)
	}

	if c.disableSSRFCheck {
		return nil
	}

	host := parsed.Hostname()

	// Check for obfuscated IP notation (octal, hex, decimal, etc.)
	// Per Raven SSRF-020: reject URLs with leading zeros or 0x prefix
	if containsObfuscatedIP(host) {
		return fmt.Errorf("SSRF protection: obfuscated IP notation not allowed")
	}

	ip := net.ParseIP(host)

	if ip == nil {
		ips, err := net.LookupIP(host)
		if err != nil {
			return fmt.Errorf("DNS lookup failed: %w", err)
		}
		if len(ips) > 0 {
			ip = ips[0]
		}
	}

	if ip != nil {
		if isBlockedIP(ip) {
			return fmt.Errorf("SSRF protection: blocked IP %s", ip.String())
		}
	}

	return nil
}

// containsObfuscatedIP detects obfuscated IP notation.
//
// Blocks:
// - Octal: 0177.0.0.1 (leading zero)
// - Hex: 0x7f.0.0.1
// - Decimal: 2130706433 (32-bit integer form)
func containsObfuscatedIP(host string) bool {
	// Remove brackets for IPv6
	if len(host) > 0 && host[0] == '[' {
		return false // IPv6 addresses are okay
	}

	// Check for octal (leading zero in any octet)
	// Example: 0177.0.0.1 or 127.0.0.01
	for i := 0; i < len(host); i++ {
		if host[i] == '0' {
			// Check if next char is a digit (making it octal)
			if i+1 < len(host) && host[i+1] >= '0' && host[i+1] <= '9' {
				// Check if this is at start or after a dot
				if i == 0 || host[i-1] == '.' {
					return true // Octal notation detected
				}
			}
		}
		// Check for hex notation (0x prefix)
		if i+1 < len(host) && host[i] == '0' && (host[i+1] == 'x' || host[i+1] == 'X') {
			return true
		}
	}

	// Check for pure decimal (no dots, all digits)
	// Example: 2130706433 = 127.0.0.1
	if len(host) > 0 {
		allDigits := true
		for i := 0; i < len(host); i++ {
			if host[i] < '0' || host[i] > '9' {
				allDigits = false
				break
			}
		}
		if allDigits && len(host) > 3 {
			// Pure decimal IP (too long to be a port)
			return true
		}
	}

	return false
}

// isBlockedIP checks if an IP is in the SSRF blocklist.
//
// Blocks per Knox §8.1 + Raven SSRF test vectors:
// - 127.0.0.0/8 (loopback IPv4)
// - ::1/128 (loopback IPv6)
// - 0.0.0.0/8 (unspecified / "this network")
// - ::/128 (unspecified IPv6)
// - 10.0.0.0/8 (RFC-1918 private)
// - 172.16.0.0/12 (RFC-1918 private)
// - 192.168.0.0/16 (RFC-1918 private)
// - 169.254.0.0/16 (link-local IPv4)
// - fe80::/10 (link-local IPv6)
// - fc00::/7 (unique local IPv6)
func isBlockedIP(ip net.IP) bool {
	// Check for unspecified address (0.0.0.0 or ::)
	if ip.IsUnspecified() {
		return true
	}

	// Check for loopback
	if ip.IsLoopback() {
		return true
	}

	// Check for link-local
	if ip.IsLinkLocalUnicast() {
		return true
	}

	// Check for private ranges and unique local IPv6
	blockedRanges := []string{
		"0.0.0.0/8",        // Unspecified / "this network"
		"10.0.0.0/8",       // RFC-1918 private
		"172.16.0.0/12",    // RFC-1918 private
		"192.168.0.0/16",   // RFC-1918 private
		"fc00::/7",         // IPv6 unique local addresses
	}

	for _, cidr := range blockedRanges {
		_, network, _ := net.ParseCIDR(cidr)
		if network.Contains(ip) {
			return true
		}
	}

	return false
}

// ComputeSignature computes HMAC-SHA256 signature for webhook.
//
// Signature payload: timestamp || body
// Returns: "sha256=<hex>"
func ComputeSignature(apiKey string, payload []byte, timestamp int64) string {
	message := fmt.Sprintf("%d%s", timestamp, string(payload))
	h := hmac.New(sha256.New, []byte(apiKey))
	h.Write([]byte(message))
	return "sha256=" + hex.EncodeToString(h.Sum(nil))
}

// VerifySignature verifies webhook HMAC signature and timestamp.
//
// Returns false if:
// - Signature invalid
// - Timestamp > 5min old
func VerifySignature(apiKey string, payload []byte, timestamp int64, signature string) bool {
	if time.Now().Unix() - timestamp > int64(MaxTimestampAge.Seconds()) {
		return false
	}

	expected := ComputeSignature(apiKey, payload, timestamp)
	return hmac.Equal([]byte(signature), []byte(expected))
}

// getCircuitBreaker retrieves or creates circuit breaker for URL.
func (c *Client) getCircuitBreaker(url string) *circuitBreaker {
	c.mu.RLock()
	cb, exists := c.circuitBreakers[url]
	c.mu.RUnlock()

	if exists {
		return cb
	}

	c.mu.Lock()
	cb = &circuitBreaker{
		consecutiveFailures: 0,
		state: "closed",
	}
	c.circuitBreakers[url] = cb
	c.mu.Unlock()

	return cb
}

// recordSuccess resets circuit breaker on successful delivery.
func (c *Client) recordSuccess(url string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if cb, exists := c.circuitBreakers[url]; exists {
		cb.consecutiveFailures = 0
		cb.state = "closed"
	}
}

// recordFailure increments failure counter and opens circuit if threshold reached.
func (c *Client) recordFailure(url string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	cb := c.circuitBreakers[url]
	if cb == nil {
		return
	}

	cb.consecutiveFailures++
	cb.lastFailure = time.Now()

	if cb.consecutiveFailures >= 5 {
		cb.state = "open"
	}
}

// CircuitState returns the circuit breaker state for a URL.
func (c *Client) CircuitState(url string) string {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if cb, exists := c.circuitBreakers[url]; exists {
		return cb.state
	}
	return "closed"
}
