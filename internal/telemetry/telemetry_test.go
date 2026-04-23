package telemetry_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/sigilauth/server/internal/telemetry"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewTelemetry(t *testing.T) {
	tel := telemetry.New(telemetry.Config{
		ServiceName: "sigil-test",
		Enabled:     true,
	})
	require.NotNil(t, tel)
}

func TestTelemetryDisabled(t *testing.T) {
	// SIGIL_TELEMETRY=none should disable all telemetry
	os.Setenv("SIGIL_TELEMETRY", "none")
	defer os.Unsetenv("SIGIL_TELEMETRY")

	tel := telemetry.New(telemetry.Config{
		ServiceName: "sigil-test",
	})

	assert.False(t, tel.IsEnabled(), "telemetry should be disabled when SIGIL_TELEMETRY=none")
}

func TestStructuredLogging(t *testing.T) {
	var buf bytes.Buffer

	tel := telemetry.New(telemetry.Config{
		ServiceName: "sigil-test",
		Enabled:     true,
		LogWriter:   &buf,
	})

	ctx := context.Background()
	tel.LogChallengeCreated(ctx, map[string]interface{}{
		"challenge_id": "test-123",
		"fingerprint":  "abcd1234",
		"action_type":  "step_up",
	})

	// Parse JSON log
	var logEntry map[string]interface{}
	err := json.Unmarshal(buf.Bytes(), &logEntry)
	require.NoError(t, err, "log output should be valid JSON")

	// slog JSON format uses "level" and "time" fields
	assert.Equal(t, "INFO", logEntry["level"])
	assert.Equal(t, "challenge.created", logEntry["event"])
	assert.Equal(t, "test-123", logEntry["challenge_id"])
	assert.Equal(t, "abcd1234", logEntry["fingerprint"])
	assert.Equal(t, "step_up", logEntry["action_type"])
	assert.NotEmpty(t, logEntry["time"], "slog uses 'time' field for timestamp")
}

func TestPrometheusMetrics(t *testing.T) {
	tel := telemetry.New(telemetry.Config{
		ServiceName: "sigil-test",
		Enabled:     true,
	})

	// Increment challenge counter
	tel.IncrementChallengesCreated("step_up")
	tel.IncrementChallengesCreated("step_up")
	tel.IncrementChallengesVerified("step_up", true)

	// Get metrics handler
	handler := tel.MetricsHandler()
	req := httptest.NewRequest("GET", "/metrics", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	body := w.Body.String()
	assert.Contains(t, body, "sigil_challenges_created_total", "should have challenge counter metric")
	assert.Contains(t, body, "sigil_challenges_verified_total", "should have verification counter metric")
	assert.Contains(t, body, `action_type="step_up"`, "should have action_type label")
}

func TestMetricsWhenDisabled(t *testing.T) {
	os.Setenv("SIGIL_TELEMETRY", "none")
	defer os.Unsetenv("SIGIL_TELEMETRY")

	tel := telemetry.New(telemetry.Config{
		ServiceName: "sigil-test",
	})

	// Metrics operations should not panic when disabled
	tel.IncrementChallengesCreated("test")
	tel.IncrementChallengesVerified("test", true)

	// Metrics endpoint should return 404 or empty when disabled
	handler := tel.MetricsHandler()
	req := httptest.NewRequest("GET", "/metrics", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	// Should either return 404 or valid but empty metrics
	assert.True(t, w.Code == http.StatusNotFound || w.Code == http.StatusOK)
}

func TestOpenTelemetrySpan(t *testing.T) {
	tel := telemetry.New(telemetry.Config{
		ServiceName: "sigil-test",
		Enabled:     true,
	})

	ctx := context.Background()
	ctx, span := tel.StartSpan(ctx, "test.operation")
	defer span.End()

	// Add attributes
	span.SetAttribute("fingerprint", "test-fingerprint")
	span.SetAttribute("action_type", "step_up")

	// Span should not panic
	assert.NotNil(t, span)
}

func TestOpenTelemetryWhenDisabled(t *testing.T) {
	os.Setenv("SIGIL_TELEMETRY", "none")
	defer os.Unsetenv("SIGIL_TELEMETRY")

	tel := telemetry.New(telemetry.Config{
		ServiceName: "sigil-test",
	})

	ctx := context.Background()
	ctx, span := tel.StartSpan(ctx, "test.operation")
	defer span.End()

	// Should return no-op span that doesn't panic
	assert.NotNil(t, span)
	span.SetAttribute("test", "value") // Should not panic
}

func TestAllEventsLogged(t *testing.T) {
	var buf bytes.Buffer

	tel := telemetry.New(telemetry.Config{
		ServiceName: "sigil-test",
		Enabled:     true,
		LogWriter:   &buf,
	})

	ctx := context.Background()

	// Test all event types from Knox §6
	tel.LogChallengeCreated(ctx, map[string]interface{}{
		"challenge_id": "ch-123",
	})

	tel.LogChallengeVerified(ctx, map[string]interface{}{
		"challenge_id": "ch-123",
		"verified":     true,
	})

	tel.LogMPARequest(ctx, map[string]interface{}{
		"request_id": "mpa-456",
		"required":   2,
	})

	tel.LogMPAQuorumSatisfied(ctx, map[string]interface{}{
		"request_id": "mpa-456",
	})

	logs := buf.String()
	lines := strings.Split(strings.TrimSpace(logs), "\n")
	assert.Len(t, lines, 4, "should have logged 4 events")

	// Parse and verify each event
	var events []map[string]interface{}
	for _, line := range lines {
		var event map[string]interface{}
		json.Unmarshal([]byte(line), &event)
		events = append(events, event)
	}

	assert.Equal(t, "challenge.created", events[0]["event"])
	assert.Equal(t, "challenge.verified", events[1]["event"])
	assert.Equal(t, "mpa.request", events[2]["event"])
	assert.Equal(t, "mpa.quorum_satisfied", events[3]["event"])
}

func TestRecordDuration(t *testing.T) {
	var buf bytes.Buffer

	tel := telemetry.New(telemetry.Config{
		ServiceName: "sigil-test",
		Enabled:     true,
		LogWriter:   &buf,
	})

	tel.RecordChallengeVerifyDuration(42.5)
	tel.RecordMPARequestDuration(100.0)

	// Check Prometheus metrics include histograms
	handler := tel.MetricsHandler()
	req := httptest.NewRequest("GET", "/metrics", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	body := w.Body.String()
	assert.Contains(t, body, "sigil_challenge_verify_duration", "should have duration histogram")
}
