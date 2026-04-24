package sigilauth

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

func (c *Client) doRequest(req *http.Request, result interface{}) error {
	var lastErr error

	for attempt := 0; attempt <= c.config.MaxRetries; attempt++ {
		if attempt > 0 {
			backoff := c.config.RetryWaitMin * time.Duration(1<<uint(attempt-1))
			if backoff > c.config.RetryWaitMax {
				backoff = c.config.RetryWaitMax
			}
			time.Sleep(backoff)
		}

		resp, err := c.httpClient.Do(req)
		if err != nil {
			lastErr = fmt.Errorf("request failed: %w", err)
			continue
		}

		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			lastErr = fmt.Errorf("read response: %w", err)
			continue
		}

		if resp.StatusCode >= 400 {
			var errResp ErrorResponse
			if err := json.Unmarshal(body, &errResp); err != nil {
				lastErr = fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(body))
			} else {
				lastErr = fmt.Errorf("API error %s: %s", errResp.Error.Code, errResp.Error.Message)
			}

			if shouldRetry(resp.StatusCode) && attempt < c.config.MaxRetries {
				continue
			}
			return lastErr
		}

		if result != nil {
			if err := json.Unmarshal(body, result); err != nil {
				return fmt.Errorf("decode response: %w", err)
			}
		}

		return nil
	}

	return lastErr
}

func shouldRetry(statusCode int) bool {
	return statusCode == http.StatusTooManyRequests || statusCode >= 500
}
