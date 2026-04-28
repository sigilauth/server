package sigilauth

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"
)

var (
	ErrMaxAttemptsReached = errors.New("max polling attempts reached")
)

type AuthService struct {
	client *Client
}

func (s *AuthService) CreateChallenge(ctx context.Context, req *ChallengeRequest) (*ChallengeResult, error) {
	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("marshal request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, "POST", s.client.config.ServiceURL+"/challenge", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}

	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Authorization", "Bearer "+s.client.config.APIKey)

	var result ChallengeResult
	if err := s.client.doRequest(httpReq, &result); err != nil {
		return nil, err
	}

	return &result, nil
}

func (s *AuthService) GetStatus(ctx context.Context, challengeID string) (*ChallengeStatus, error) {
	httpReq, err := http.NewRequestWithContext(ctx, "GET", s.client.config.ServiceURL+"/v1/auth/challenge/"+challengeID+"/status", nil)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}

	httpReq.Header.Set("Authorization", "Bearer "+s.client.config.APIKey)

	var result ChallengeStatus
	if err := s.client.doRequest(httpReq, &result); err != nil {
		return nil, err
	}

	return &result, nil
}

type AwaitOptions struct {
	PollInterval int
	MaxAttempts  int
}

func (s *AuthService) AwaitResult(ctx context.Context, challengeID string, opts *AwaitOptions) (*ChallengeStatus, error) {
	if opts == nil {
		opts = &AwaitOptions{
			PollInterval: 1000,
			MaxAttempts:  30,
		}
	}

	for i := 0; i < opts.MaxAttempts; i++ {
		status, err := s.GetStatus(ctx, challengeID)
		if err != nil {
			return nil, err
		}

		if status.Status == "verified" || status.Status == "rejected" || status.Status == "expired" {
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
