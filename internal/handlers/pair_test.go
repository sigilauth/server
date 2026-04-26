package handlers

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/sigilauth/server/internal/crypto"
	"github.com/sigilauth/server/internal/pair"
	"github.com/sigilauth/server/internal/pictogram"
	"github.com/stretchr/testify/require"
)

func TestPairHandshake(t *testing.T) {
	err := pictogram.LoadPool("../../api/pictogram-pool-v1.json")
	if err != nil {
		t.Skip("Pictogram pool not found - run from server directory")
	}

	serverKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	clientKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	pairStore := pair.NewStore()
	handler := NewPairHandler(pairStore, serverKey, "test-server")

	t.Run("pair init returns session pictogram", func(t *testing.T) {
		clientPubCompressed := crypto.CompressPublicKey(&clientKey.PublicKey)
		clientPubB64 := base64.StdEncoding.EncodeToString(clientPubCompressed)

		req := httptest.NewRequest(http.MethodGet, "/pair/init?client_pub="+clientPubB64, nil)
		w := httptest.NewRecorder()

		handler.Init(w, req)

		require.Equal(t, http.StatusOK, w.Code)

		var resp map[string]interface{}
		err := json.NewDecoder(w.Body).Decode(&resp)
		require.NoError(t, err)

		require.Equal(t, "test-server", resp["server_id"])
		require.NotEmpty(t, resp["server_public_key"])
		require.NotEmpty(t, resp["server_nonce"])
		require.NotEmpty(t, resp["expires_at"])

		pictogramArr, ok := resp["session_pictogram"].([]interface{})
		require.True(t, ok)
		require.Len(t, pictogramArr, 6)

		pictogramSpeakable, ok := resp["session_pictogram_speakable"].(string)
		require.True(t, ok)
		require.NotEmpty(t, pictogramSpeakable)
	})

	t.Run("pair init rejects invalid client_pub", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/pair/init?client_pub=invalid", nil)
		w := httptest.NewRecorder()

		handler.Init(w, req)

		require.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("pair complete requires approval", func(t *testing.T) {
		clientPubCompressed := crypto.CompressPublicKey(&clientKey.PublicKey)
		clientPubB64 := base64.StdEncoding.EncodeToString(clientPubCompressed)

		initReq := httptest.NewRequest(http.MethodGet, "/pair/init?client_pub="+clientPubB64, nil)
		initW := httptest.NewRecorder()
		handler.Init(initW, initReq)

		var initResp map[string]interface{}
		json.NewDecoder(initW.Body).Decode(&initResp)
		serverNonce := initResp["server_nonce"].(string)

		completeReq := map[string]interface{}{
			"server_nonce":       serverNonce,
			"client_public_key":  clientPubB64,
			"device_info": map[string]string{
				"name":     "Test Device",
				"platform": "test",
			},
		}
		completeBody, _ := json.Marshal(completeReq)

		req := httptest.NewRequest(http.MethodPost, "/pair/complete", bytes.NewReader(completeBody))
		w := httptest.NewRecorder()

		handler.Complete(w, req)

		require.Equal(t, http.StatusForbidden, w.Code)

		var errResp map[string]interface{}
		json.NewDecoder(w.Body).Decode(&errResp)
		require.Equal(t, "NOT_APPROVED", errResp["error"])
	})
}
