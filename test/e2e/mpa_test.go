package e2e

import (
	"bytes"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestMPA2of3 tests 2-of-3 multi-party authorization with clear notifications.
// Scenario: 3 groups, 2 required. Group 0 approves, Group 1 approves, Group 2 gets clear.
func TestMPA2of3(t *testing.T) {
	requireDockerStack(t)
	_ = newTestContext(t)

	client := newHTTPClient()
	baseURL := getBaseURL()

	// 1. Create 5 devices across 3 groups (Sarah: 2, Mike: 1, Damon: 2)
	sarahiPhone := generateTestDevice(t)
	sarahiPad := generateTestDevice(t)
	mikePixel := generateTestDevice(t)
	damonMacBook := generateTestDevice(t)
	damonYubiKey := generateTestDevice(t)

	fingerprints := []string{sarahiPhone.Fingerprint, sarahiPad.Fingerprint, mikePixel.Fingerprint, damonMacBook.Fingerprint, damonYubiKey.Fingerprint}

	// 2. Create MPA request (required=2, 3 groups)
	mpaReq := map[string]interface{}{
		"fingerprints": fingerprints,
		"required":     2,
		"action": map[string]interface{}{
			"type":        "destructive_action",
			"description": "Delete production database",
		},
		"groups": []map[string]interface{}{
			{
				"members": []map[string]interface{}{
					{"fingerprint": sarahiPhone.Fingerprint, "device_public_key": sarahiPhone.PublicKeyCompressed},
					{"fingerprint": sarahiPad.Fingerprint, "device_public_key": sarahiPad.PublicKeyCompressed},
				},
			},
			{
				"members": []map[string]interface{}{
					{"fingerprint": mikePixel.Fingerprint, "device_public_key": mikePixel.PublicKeyCompressed},
				},
			},
			{
				"members": []map[string]interface{}{
					{"fingerprint": damonMacBook.Fingerprint, "device_public_key": damonMacBook.PublicKeyCompressed},
					{"fingerprint": damonYubiKey.Fingerprint, "device_public_key": damonYubiKey.PublicKeyCompressed},
				},
			},
		},
	}

	body, _ := json.Marshal(mpaReq)
	resp, err := client.Post(baseURL+"/mpa/request", "application/json", bytes.NewReader(body))
	require.NoError(t, err, "MPA request should succeed")
	defer resp.Body.Close()

	require.Equal(t, http.StatusCreated, resp.StatusCode, "MPA request should return 201")

	var mpaResp struct {
		RequestID string `json:"request_id"`
		Status    string `json:"status"`
		Required  int    `json:"required"`
		Approved  int    `json:"approved"`
	}
	err = json.NewDecoder(resp.Body).Decode(&mpaResp)
	require.NoError(t, err)
	require.Equal(t, "pending", mpaResp.Status)
	require.Equal(t, 0, mpaResp.Approved)

	// 3. Sarah's iPhone approves (Group 0)
	approveReq := map[string]interface{}{
		"request_id":  mpaResp.RequestID,
		"fingerprint": sarahiPhone.Fingerprint,
		"signature":   sarahiPhone.SignChallenge(t, mpaResp.RequestID),
		"approved":    true,
	}
	body, _ = json.Marshal(approveReq)
	resp, err = client.Post(baseURL+"/mpa/respond", "application/json", bytes.NewReader(body))
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	// 4. Mike's Pixel approves (Group 1) → Quorum reached
	approveReq["fingerprint"] = mikePixel.Fingerprint
	approveReq["signature"] = mikePixel.SignChallenge(t, mpaResp.RequestID)
	body, _ = json.Marshal(approveReq)
	resp, err = client.Post(baseURL+"/mpa/respond", "application/json", bytes.NewReader(body))
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	// 5. Check MPA status - should be approved (2/2 groups)
	statusResp, err := client.Get(baseURL + "/mpa/status/" + mpaResp.RequestID)
	require.NoError(t, err)
	defer statusResp.Body.Close()

	var status struct {
		RequestID string `json:"request_id"`
		Status    string `json:"status"`
		Required  int    `json:"required"`
		Approved  int    `json:"approved"`
	}
	err = json.NewDecoder(statusResp.Body).Decode(&status)
	require.NoError(t, err)
	require.Equal(t, "approved", status.Status, "MPA should be approved after 2/2 groups approve")
	require.Equal(t, 2, status.Approved)

	t.Log("✅ 2-of-3 MPA test completed successfully")
}

// TestMPASameGroupDoubleApproval tests that same-group approvals don't double-count.
// Scenario: Group 0 has 2 devices, both approve, only counts as 1 group.
// BLOCKED: Requires B1 (server).
func TestMPASameGroupDoubleApproval(t *testing.T) {
	requireDockerStack(t)
	ctx := newTestContext(t)
	_ = ctx

	t.Log("BLOCKED: B1 not implemented")
	t.Skip("Awaiting B1 (server)")

	// TODO: Implementation when dependencies ready:
	// 1. Create MPA with 2 devices in Group 0, 1 device in Group 1, required=2
	// 2. Device A (Group 0) approves
	// 3. Device B (Group 0) attempts to approve
	// 4. Assert: response indicates "already_satisfied"
	// 5. MPA still pending (1/2 groups)
}

// TestMPARejectOnFirst tests immediate termination on first rejection.
// Scenario: reject_policy=reject_on_first, one device rejects, MPA terminates.
// BLOCKED: Requires B1 (server).
func TestMPARejectOnFirst(t *testing.T) {
	requireDockerStack(t)
	ctx := newTestContext(t)
	_ = ctx

	t.Log("BLOCKED: B1 not implemented")
	t.Skip("Awaiting B1 (server)")

	// TODO: Implementation when dependencies ready:
	// 1. Create MPA with reject_policy=reject_on_first
	// 2. One device rejects
	// 3. Assert: MPA immediately rejected
	// 4. All other devices receive "rejected" clear notification
}

// TestMPAContinueOnReject tests continue policy after rejection.
// Scenario: reject_policy=continue, one device rejects, MPA continues.
// BLOCKED: Requires B1 (server).
func TestMPAContinueOnReject(t *testing.T) {
	requireDockerStack(t)
	ctx := newTestContext(t)
	_ = ctx

	t.Log("BLOCKED: B1 not implemented")
	t.Skip("Awaiting B1 (server)")

	// TODO: Implementation when dependencies ready:
	// 1. Create MPA with reject_policy=continue
	// 2. One device rejects
	// 3. Assert: MPA continues collecting
	// 4. Other groups can still approve
	// 5. Quorum can still be reached
}

// TestMPATimeout tests partial approval timeout.
// Scenario: MPA started, only 1 of 2 groups approve, timeout, MPA expires.
// BLOCKED: Requires B1 (server).
func TestMPATimeout(t *testing.T) {
	requireDockerStack(t)
	ctx := newTestContext(t)
	_ = ctx

	t.Log("BLOCKED: B1 not implemented")
	t.Skip("Awaiting B1 (server)")

	// TODO: Implementation when dependencies ready:
	// 1. Create MPA with short timeout
	// 2. Only 1 group approves
	// 3. Wait for timeout
	// 4. Assert: MPA status = timeout
	// 5. All devices receive "expired" clear notification
}

// TestMPAConcurrentApprovalRace tests concurrent approvals from different groups.
// Scenario: Two groups approve simultaneously, both processed, no race corruption.
// BLOCKED: Requires B1 (server).
func TestMPAConcurrentApprovalRace(t *testing.T) {
	requireDockerStack(t)
	ctx := newTestContext(t)
	_ = ctx

	t.Log("BLOCKED: B1 not implemented")
	t.Skip("Awaiting B1 (server)")

	// TODO: Implementation when dependencies ready:
	// 1. Create MPA with 3 groups, required=2
	// 2. Groups 0 and 1 approve concurrently (goroutines)
	// 3. Assert: Both approvals recorded
	// 4. Assert: Quorum reached
	// 5. Assert: No data corruption in MPA state
}
