package apikey_test

import (
	"context"
	"testing"

	"github.com/sigilauth/server/internal/apikey"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGenerate(t *testing.T) {
	key := apikey.Generate()

	// Knox §5.4: sgk_live_<64-hex>
	assert.True(t, len(key) > 70, "key should be at least 70 chars (sgk_live_ + 64 hex)")
	assert.Contains(t, key, "sgk_live_", "key should have sgk_live_ prefix")

	// Should be unique
	key2 := apikey.Generate()
	assert.NotEqual(t, key, key2, "generated keys should be unique")
}

func TestNewStore(t *testing.T) {
	store := apikey.NewStore()
	require.NotNil(t, store)
}

func TestAddKey(t *testing.T) {
	store := apikey.NewStore()
	ctx := context.Background()

	key := apikey.Generate()
	err := store.AddKey(ctx, "test-key-1", key)
	require.NoError(t, err)

	// Adding duplicate ID should fail
	key2 := apikey.Generate()
	err = store.AddKey(ctx, "test-key-1", key2)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "already exists")
}

func TestVerifyKey(t *testing.T) {
	store := apikey.NewStore()
	ctx := context.Background()

	key := apikey.Generate()
	store.AddKey(ctx, "prod-key", key)

	// Correct key should verify
	valid, keyID := store.VerifyKey(ctx, key)
	assert.True(t, valid, "correct key should verify")
	assert.Equal(t, "prod-key", keyID)

	// Wrong key should fail
	wrongKey := apikey.Generate()
	valid, _ = store.VerifyKey(ctx, wrongKey)
	assert.False(t, valid, "wrong key should not verify")

	// Modified key should fail
	modifiedKey := key[:len(key)-1] + "x"
	valid, _ = store.VerifyKey(ctx, modifiedKey)
	assert.False(t, valid, "modified key should not verify")
}

func TestRevokeKey(t *testing.T) {
	store := apikey.NewStore()
	ctx := context.Background()

	key := apikey.Generate()
	store.AddKey(ctx, "revoke-test", key)

	// Key should work before revocation
	valid, _ := store.VerifyKey(ctx, key)
	assert.True(t, valid)

	// Revoke
	err := store.RevokeKey(ctx, "revoke-test")
	require.NoError(t, err)

	// Key should not work after revocation
	valid, _ = store.VerifyKey(ctx, key)
	assert.False(t, valid, "revoked key should not verify")

	// Revoking again should error
	err = store.RevokeKey(ctx, "revoke-test")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

func TestListKeys(t *testing.T) {
	store := apikey.NewStore()
	ctx := context.Background()

	key1 := apikey.Generate()
	key2 := apikey.Generate()

	store.AddKey(ctx, "key-1", key1)
	store.AddKey(ctx, "key-2", key2)

	keys := store.ListKeys(ctx)
	assert.Len(t, keys, 2)

	keyIDs := []string{keys[0].ID, keys[1].ID}
	assert.Contains(t, keyIDs, "key-1")
	assert.Contains(t, keyIDs, "key-2")

	// Should not expose plaintext keys
	assert.Empty(t, keys[0].Plaintext, "plaintext should not be exposed in list")
	assert.Empty(t, keys[1].Plaintext)

	// Should have hashes
	assert.NotEmpty(t, keys[0].Hash)
	assert.NotEmpty(t, keys[1].Hash)
}

func TestRotateKey(t *testing.T) {
	store := apikey.NewStore()
	ctx := context.Background()

	oldKey := apikey.Generate()
	store.AddKey(ctx, "rotate-test", oldKey)

	// Old key works
	valid, _ := store.VerifyKey(ctx, oldKey)
	assert.True(t, valid)

	// Generate new key and rotate
	newKey := apikey.Generate()
	err := store.RotateKey(ctx, "rotate-test", newKey)
	require.NoError(t, err)

	// New key should work
	valid, keyID := store.VerifyKey(ctx, newKey)
	assert.True(t, valid)
	assert.Equal(t, "rotate-test", keyID)

	// Old key should not work
	valid, _ = store.VerifyKey(ctx, oldKey)
	assert.False(t, valid, "old key should not work after rotation")
}

func TestBcryptCost(t *testing.T) {
	store := apikey.NewStore()
	ctx := context.Background()

	key := apikey.Generate()
	store.AddKey(ctx, "cost-test", key)

	keys := store.ListKeys(ctx)
	hash := keys[0].Hash

	// Knox §5.4: bcrypt cost 12
	// bcrypt hash format: $2a$12$... (cost is after second $)
	assert.True(t, len(hash) > 7, "hash should be valid bcrypt")
	assert.Equal(t, "$2a$12$", hash[:7], "bcrypt cost should be 12")
}

func TestLoadFromEnv(t *testing.T) {
	// Test loading keys from environment variables
	// Format: SIGIL_API_KEY_<id>=<plaintext-key>

	ctx := context.Background()

	envKeys := map[string]string{
		"prod":    apikey.Generate(),
		"staging": apikey.Generate(),
	}

	store := apikey.LoadFromMap(envKeys)

	// Both keys should work
	for id, key := range envKeys {
		valid, keyID := store.VerifyKey(ctx, key)
		assert.True(t, valid, "key %s should verify", id)
		assert.Equal(t, id, keyID)
	}
}

func TestConcurrentAccess(t *testing.T) {
	store := apikey.NewStore()
	ctx := context.Background()

	key := apikey.Generate()
	store.AddKey(ctx, "concurrent-test", key)

	// 10 goroutines verifying concurrently
	done := make(chan bool, 10)
	for i := 0; i < 10; i++ {
		go func() {
			valid, keyID := store.VerifyKey(ctx, key)
			assert.True(t, valid)
			assert.Equal(t, "concurrent-test", keyID)
			done <- true
		}()
	}

	for i := 0; i < 10; i++ {
		<-done
	}
}
