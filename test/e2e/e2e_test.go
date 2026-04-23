package e2e

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// TestMain sets up the E2E test environment.
// BLOCKED: Requires B11 (docker-compose) to bring up test stack.
func TestMain(m *testing.M) {
	// Check if test stack is running
	if os.Getenv("SIGIL_E2E_ENABLED") != "true" {
		// Skip E2E tests if stack not running
		os.Exit(0)
	}
	
	os.Exit(m.Run())
}

// testTimeout is the default timeout for E2E operations.
const testTimeout = 30 * time.Second

// newTestContext creates a context with the test timeout.
func newTestContext(t *testing.T) context.Context {
	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	t.Cleanup(cancel)
	return ctx
}

// requireDockerStack skips the test if docker-compose stack isn't running.
func requireDockerStack(t *testing.T) {
	t.Helper()
	if os.Getenv("SIGIL_E2E_ENABLED") != "true" {
		t.Skip("BLOCKED: Set SIGIL_E2E_ENABLED=true with docker-compose stack running")
	}
}

// Placeholder assertion to satisfy imports until real tests implemented.
var _ = require.New
