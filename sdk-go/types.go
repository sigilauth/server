package sigilauth

import "time"

type Action struct {
	Type        string                 `json:"type"`
	Description string                 `json:"description"`
	Params      map[string]interface{} `json:"params,omitempty"`
}

type ChallengeRequest struct {
	Fingerprint     string `json:"fingerprint"`
	DevicePublicKey string `json:"device_public_key"`
	Action          Action `json:"action"`
}

type ChallengeResult struct {
	ChallengeID        string    `json:"challenge_id"`
	Fingerprint        string    `json:"fingerprint"`
	Pictogram          []string  `json:"pictogram"`
	PictogramSpeakable string    `json:"pictogram_speakable"`
	ExpiresAt          time.Time `json:"expires_at"`
}

type ChallengeStatus struct {
	ChallengeID        string    `json:"challenge_id"`
	Status             string    `json:"status"`
	Fingerprint        string    `json:"fingerprint,omitempty"`
	Pictogram          []string  `json:"pictogram,omitempty"`
	PictogramSpeakable string    `json:"pictogram_speakable,omitempty"`
	Decision           string    `json:"decision,omitempty"`
	VerifiedAt         time.Time `json:"verified_at,omitempty"`
}

type MPAGroupMember struct {
	Fingerprint     string `json:"fingerprint"`
	DevicePublicKey string `json:"device_public_key"`
}

type MPAGroup struct {
	Members []MPAGroupMember `json:"members"`
}

type MPARequest struct {
	RequestID        string     `json:"request_id"`
	Action           Action     `json:"action"`
	Required         int        `json:"required"`
	Groups           []MPAGroup `json:"groups"`
	RejectPolicy     string     `json:"reject_policy,omitempty"`
	ExpiresInSeconds int        `json:"expires_in_seconds,omitempty"`
}

type MPAResult struct {
	RequestID      string    `json:"request_id"`
	Status         string    `json:"status"`
	GroupsRequired int       `json:"groups_required"`
	GroupsTotal    int       `json:"groups_total"`
	ChallengesSent int       `json:"challenges_sent,omitempty"`
	ExpiresAt      time.Time `json:"expires_at"`
}

type MPAStatus struct {
	RequestID       string    `json:"request_id"`
	Status          string    `json:"status"`
	GroupsSatisfied []int     `json:"groups_satisfied,omitempty"`
	GroupsRequired  int       `json:"groups_required"`
	GroupsTotal     int       `json:"groups_total"`
	ExpiresAt       time.Time `json:"expires_at,omitempty"`
}

type ErrorResponse struct {
	Error struct {
		Code    string                 `json:"code"`
		Message string                 `json:"message"`
		Details map[string]interface{} `json:"details,omitempty"`
	} `json:"error"`
}
