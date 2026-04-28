package pictogram

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDeriveSessionPictogram(t *testing.T) {
	err := LoadPool("../../api/pictogram-pool-v1.json")
	if err != nil {
		t.Skip("Pictogram pool not found - run from server directory")
	}

	serverPub, _ := hex.DecodeString("0212345678" + "00000000000000000000000000000000000000000000000000000000")
	clientPub, _ := hex.DecodeString("0398765432" + "00000000000000000000000000000000000000000000000000000000")
	serverNonce, _ := hex.DecodeString("abcdefghijklmnopqrstuvwxyzabcdef")

	words, err := DeriveSessionPictogram(serverPub, clientPub, serverNonce)
	require.NoError(t, err)
	require.Len(t, words, 6)

	for _, word := range words {
		require.NotEmpty(t, word)
	}

	speakable := FormatSpeakable(words)
	require.NotEmpty(t, speakable)
	require.Contains(t, speakable, " ")
}

func TestDeriveSessionPictogramDeterministic(t *testing.T) {
	err := LoadPool("../../api/pictogram-pool-v1.json")
	if err != nil {
		t.Skip("Pictogram pool not found")
	}

	serverPub := make([]byte, 33)
	clientPub := make([]byte, 33)
	serverNonce := make([]byte, 32)

	words1, err := DeriveSessionPictogram(serverPub, clientPub, serverNonce)
	require.NoError(t, err)

	words2, err := DeriveSessionPictogram(serverPub, clientPub, serverNonce)
	require.NoError(t, err)

	require.Equal(t, words1, words2)
}
