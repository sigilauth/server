// Package mpa manages multi-party authorization sessions.
//
// MPA requires M-of-N group approvals, with groups ensuring different people approve.
// All state is ephemeral (in-memory). Lost on restart.
package mpa

import (
	"context"
	"crypto/ecdsa"
	"fmt"
	"sync"
	"time"

	"github.com/sigilauth/server/internal/crypto"
)

// Action represents the action requiring authorization.
type Action struct {
	Type        string
	Description string
	Params      map[string]interface{}
}

// Member represents a device in an approval group.
type Member struct {
	Fingerprint     string
	DevicePublicKey []byte
}

// Group represents a collection of devices, one of which must approve.
type Group struct {
	Members []Member
}

// CreateRequest is the input for creating an MPA request.
type CreateRequest struct {
	RequestID    string
	Action       Action
	Groups       []Group
	Required     int
	RejectPolicy string
	ExpiresIn    time.Duration
	ServerKey    *ecdsa.PrivateKey
}

// Response is a device's response to an MPA request.
type Response struct {
	RequestID   string
	Fingerprint string
	Signature   []byte
	Decision    string
}

// Approval records a single approval.
type Approval struct {
	Fingerprint string
	Decision    string
	Timestamp   time.Time
}

// Request represents an active MPA session.
type Request struct {
	RequestID       string
	Action          Action
	Groups          []Group
	Required        int
	GroupsTotal     int
	RejectPolicy    string
	Status          string
	GroupsSatisfied []int
	Approvals       []Approval
	ExpiresAt       time.Time
	CreatedAt       time.Time
	CompletedAt     *time.Time
}

// Store manages in-memory MPA sessions.
type Store struct {
	mu       sync.RWMutex
	requests map[string]*Request
}

// NewStore creates a new MPA store.
func NewStore() *Store {
	return &Store{
		requests: make(map[string]*Request),
	}
}

// CreateRequest creates a new MPA request.
func (s *Store) CreateRequest(ctx context.Context, req CreateRequest) (*Request, error) {
	if req.Required < 1 {
		return nil, fmt.Errorf("required must be at least 1")
	}

	if req.Required > len(req.Groups) {
		return nil, fmt.Errorf("required (%d) cannot exceed groups count (%d)", req.Required, len(req.Groups))
	}

	now := time.Now()
	expiresAt := now.Add(req.ExpiresIn)

	request := &Request{
		RequestID:       req.RequestID,
		Action:          req.Action,
		Groups:          req.Groups,
		Required:        req.Required,
		GroupsTotal:     len(req.Groups),
		RejectPolicy:    req.RejectPolicy,
		Status:          "pending",
		GroupsSatisfied: []int{},
		Approvals:       []Approval{},
		ExpiresAt:       expiresAt,
		CreatedAt:       now,
		CompletedAt:     nil,
	}

	s.mu.Lock()
	s.requests[req.RequestID] = request
	s.mu.Unlock()

	return request, nil
}

// GetRequest retrieves an MPA request by ID.
func (s *Store) GetRequest(ctx context.Context, requestID string) (*Request, error) {
	s.mu.RLock()
	request, exists := s.requests[requestID]
	s.mu.RUnlock()

	if !exists {
		return nil, fmt.Errorf("request not found")
	}

	if time.Now().After(request.ExpiresAt) && request.Status == "pending" {
		s.mu.Lock()
		request.Status = "timeout"
		now := time.Now()
		request.CompletedAt = &now
		s.mu.Unlock()
		return nil, fmt.Errorf("request expired")
	}

	return request, nil
}

// Respond processes a device's response to an MPA request.
//
// Returns the updated request state.
// Errors if:
// - Request not found or expired
// - Device not in any group
// - Group already satisfied
// - Invalid signature
func (s *Store) Respond(ctx context.Context, resp Response) (*Request, error) {
	request, err := s.GetRequest(ctx, resp.RequestID)
	if err != nil {
		return nil, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if request.Status != "pending" {
		return nil, fmt.Errorf("request already completed with status: %s", request.Status)
	}

	// Find group and member by fingerprint
	groupIdx, member := s.findMember(request, resp.Fingerprint)
	if groupIdx == -1 {
		return nil, fmt.Errorf("device not in any group")
	}

	// Use stored device public key for verification
	devicePubKey, err := crypto.DecompressPublicKey(member.DevicePublicKey)
	if err != nil {
		return nil, fmt.Errorf("invalid stored device public key: %w", err)
	}

	if err := crypto.Verify(devicePubKey, []byte(resp.RequestID), resp.Signature); err != nil {
		return nil, fmt.Errorf("signature verification failed: %w", err)
	}

	if s.isGroupSatisfied(request, groupIdx) {
		return nil, fmt.Errorf("group already satisfied")
	}

	now := time.Now()
	request.Approvals = append(request.Approvals, Approval{
		Fingerprint: resp.Fingerprint,
		Decision:    resp.Decision,
		Timestamp:   now,
	})

	if resp.Decision == "approved" {
		request.GroupsSatisfied = append(request.GroupsSatisfied, groupIdx)

		if len(request.GroupsSatisfied) >= request.Required {
			request.Status = "approved"
			request.CompletedAt = &now
		}
	} else if resp.Decision == "rejected" {
		if request.RejectPolicy == "reject_on_first" {
			request.Status = "rejected"
			request.CompletedAt = &now
		} else {
			remainingGroups := request.GroupsTotal - len(request.GroupsSatisfied) - 1
			if remainingGroups < request.Required {
				request.Status = "rejected"
				request.CompletedAt = &now
			}
		}
	}

	return request, nil
}

// findMember returns the group index and member matching the fingerprint.
// Returns -1 and nil if not found.
func (s *Store) findMember(request *Request, fingerprint string) (int, *Member) {
	for groupIdx, group := range request.Groups {
		for i, member := range group.Members {
			if member.Fingerprint == fingerprint {
				return groupIdx, &group.Members[i]
			}
		}
	}
	return -1, nil
}

// findGroupIndex returns the index of the group containing the fingerprint.
// Returns -1 if not found.
func (s *Store) findGroupIndex(request *Request, fingerprint string) int {
	idx, _ := s.findMember(request, fingerprint)
	return idx
}

// isGroupSatisfied checks if a group has already been satisfied.
func (s *Store) isGroupSatisfied(request *Request, groupIdx int) bool {
	for _, satisfied := range request.GroupsSatisfied {
		if satisfied == groupIdx {
			return true
		}
	}
	return false
}

// CleanExpired removes expired MPA requests.
func (s *Store) CleanExpired(ctx context.Context) int {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	removed := 0

	for id, request := range s.requests {
		if now.After(request.ExpiresAt) && request.Status == "pending" {
			request.Status = "timeout"
			request.CompletedAt = &now
			delete(s.requests, id)
			removed++
		}
	}

	return removed
}
