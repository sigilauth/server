package sigilauth

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

type MPAService struct {
	client *Client
}

func (s *MPAService) Request(ctx context.Context, req *MPARequest) (*MPAResult, error) {
	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("marshal request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, "POST", s.client.config.ServiceURL+"/mpa/request", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}

	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Authorization", "Bearer "+s.client.config.APIKey)

	var result MPAResult
	if err := s.client.doRequest(httpReq, &result); err != nil {
		return nil, err
	}

	return &result, nil
}

func (s *MPAService) GetStatus(ctx context.Context, requestID string) (*MPAStatus, error) {
	httpReq, err := http.NewRequestWithContext(ctx, "GET", s.client.config.ServiceURL+"/mpa/status/"+requestID, nil)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}

	httpReq.Header.Set("Authorization", "Bearer "+s.client.config.APIKey)

	var result MPAStatus
	if err := s.client.doRequest(httpReq, &result); err != nil {
		return nil, err
	}

	return &result, nil
}

func (s *MPAService) AwaitResult(ctx context.Context, requestID string, opts *AwaitOptions) (*MPAStatus, error) {
	if opts == nil {
		opts = &AwaitOptions{
			PollInterval: 1000,
			MaxAttempts:  30,
		}
	}

	for i := 0; i < opts.MaxAttempts; i++ {
		status, err := s.GetStatus(ctx, requestID)
		if err != nil {
			return nil, err
		}

		if status.Status == "approved" || status.Status == "rejected" || status.Status == "timeout" {
			return status, nil
		}

		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(time.Duration(opts.PollInterval) * time.Millisecond):
		}
	}

	return nil, ErrMaxAttemptsReached
}
