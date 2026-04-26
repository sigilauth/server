package pictogram

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os"

	"golang.org/x/crypto/argon2"
)

const (
	poolSize      = 192
	pictogramSize = 6
	argon2Memory  = 64 * 1024
	argon2Time    = 10
	argon2Threads = 1
	argon2KeyLen  = 32
)

var argon2Salt = []byte("SIGIL-PAIR-V1\x00\x00\x00")

type Entry struct {
	Index int    `json:"index"`
	Emoji string `json:"emoji"`
	Name  string `json:"name"`
}

type Category struct {
	Name       string  `json:"name"`
	FirstIndex int     `json:"first_index"`
	Count      int     `json:"count"`
	Entries    []Entry `json:"entries"`
}

type Pool struct {
	Version    int        `json:"version"`
	PoolSize   int        `json:"pool_size"`
	Categories []Category `json:"categories"`
}

var globalPool *Pool

func LoadPool(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("failed to read pictogram pool: %w", err)
	}

	var pool Pool
	if err := json.Unmarshal(data, &pool); err != nil {
		return fmt.Errorf("failed to parse pictogram pool: %w", err)
	}

	if pool.PoolSize != poolSize {
		return fmt.Errorf("pool size mismatch: expected %d, got %d", poolSize, pool.PoolSize)
	}

	globalPool = &pool
	return nil
}

func DeriveSessionPictogram(serverPub, clientPub, serverNonce []byte) ([]string, error) {
	if globalPool == nil {
		return nil, fmt.Errorf("pictogram pool not loaded")
	}

	h := sha256.New()
	h.Write(serverPub)
	h.Write(clientPub)
	h.Write(serverNonce)
	passwordHash := h.Sum(nil)

	derived := argon2.IDKey(
		passwordHash,
		argon2Salt,
		argon2Time,
		argon2Memory,
		argon2Threads,
		argon2KeyLen,
	)

	indices := make([]int, pictogramSize)
	for i := 0; i < pictogramSize; i++ {
		wordIndex := binary.BigEndian.Uint16(derived[i*2 : i*2+2])
		indices[i] = int(wordIndex) % poolSize
	}

	words := make([]string, pictogramSize)
	for i, idx := range indices {
		entry, err := getEntry(idx)
		if err != nil {
			return nil, err
		}
		words[i] = entry.Name
	}

	return words, nil
}

func getEntry(index int) (*Entry, error) {
	for _, category := range globalPool.Categories {
		if index >= category.FirstIndex && index < category.FirstIndex+category.Count {
			localIndex := index - category.FirstIndex
			if localIndex < len(category.Entries) {
				return &category.Entries[localIndex], nil
			}
		}
	}
	return nil, fmt.Errorf("index %d out of range", index)
}

func FormatSpeakable(words []string) string {
	result := ""
	for i, word := range words {
		if i > 0 {
			result += " "
		}
		result += word
	}
	return result
}
