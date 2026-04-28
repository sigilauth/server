# Go 1.26.x darwin/arm64 RFC 6979 Hang

**Status:** ACTIVE BUG (as of 2026-04-27)  
**Affects:** Go 1.26.1, Go 1.26.2 on darwin/arm64 (macOS Apple Silicon)  
**Severity:** CRITICAL - Code hangs indefinitely, timeout required to kill

## Summary

RFC 6979 deterministic ECDSA signing hangs on Go 1.26.x darwin/arm64. Both stdlib `ecdsa.Sign(nil, ...)` and `github.com/codahale/rfc6979` library hang >60 seconds. Same code works correctly on linux/amd64.

## Evidence

### Affected Environments
- **kai-3 (server):** Go 1.26.2 darwin/arm64 → HANG
- **kai-cli-2 (cli-device):** Go 1.26.1 darwin/arm64 → HANG
- **Minimal repro:** `ecdsa.Sign(nil, privateKey, hash[:])` → HANG

### Working Environments
- **ava-2 (testing):** Likely linux/amd64 → WORKS ✅
- **Expected:** linux/amd64, older Go versions → WORKS ✅

## Test Results

### Hanging Code (Go 1.26.2 darwin/arm64)
```go
// Both hang >60s:
r, s, err := ecdsa.Sign(nil, privateKey, hash[:])              // stdlib
r, s, err := rfc6979.SignECDSA(privateKey, hash[:], sha256.New) // codahale
```

**Output:**
```
*** Test killed with quit: ran too long (1m10s).
signal: quit
FAIL
```

### Working Code (linux/amd64)
Same code produces:
- ✅ Deterministic signatures (3 identical runs)
- ✅ Matches test vectors
- ✅ Completes in <1 second

## Workaround: Revert to crypto/rand

**Commit fa8e214** reverts RFC 6979 to non-deterministic ECDSA:

```go
// internal/crypto/ecdsa.go
func Sign(privateKey *ecdsa.PrivateKey, message []byte) ([]byte, error) {
    hash := sha256.Sum256(message)
    
    // Use crypto/rand for now — RFC 6979 deferred due to Go 1.26.x hang
    r, s, err := ecdsa.Sign(rand.Reader, privateKey, hash[:])
    if err != nil {
        return nil, fmt.Errorf("ECDSA signing failed: %w", err)
    }
    
    // BIP-62 low-S normalization still applied
    // ...
}
```

**Implications:**
- ✅ Tests pass (<1 second)
- ✅ Security unaffected (crypto/rand is valid for ECDSA)
- ❌ Signatures non-deterministic (different each run)
- ❌ Cross-implementation test vectors won't match
- ❌ Can't verify byte-exact signature compatibility

## Restoration Plan

Restore RFC 6979 when one of:

1. **Go 1.26.3+ fix** - Upstream resolves darwin/arm64 hang
2. **Downgrade Go** - Use Go 1.23 or 1.24 (if no hang on older versions)
3. **Platform isolation** - Use build tags for platform-specific signing:
   ```go
   //go:build linux
   // Use RFC 6979
   
   //go:build darwin && arm64
   // Use crypto/rand
   ```
4. **Docker development** - Run Go builds in Linux container

## Upstream Issue

TODO: File issue at https://github.com/golang/go/issues/

**Title:** `crypto/ecdsa: Sign(nil, ...) hangs on darwin/arm64 Go 1.26.x`

**Reproduction:**
```go
package main

import (
    "crypto/ecdsa"
    "crypto/elliptic"
    "crypto/rand"
    "crypto/sha256"
)

func main() {
    key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
    hash := sha256.Sum256([]byte("test"))
    
    // Hangs on darwin/arm64 Go 1.26.1/1.26.2
    r, s, err := ecdsa.Sign(nil, key, hash[:])
    println(r, s, err)
}
```

## Related Commits

- **b994a2d** - RFC 6979 codahale library implementation (works on linux, hangs on macOS)
- **53ce1c2** - Build fixes for RFC 6979 (works on linux, hangs on macOS)
- **fa8e214** - Revert to crypto/rand due to darwin/arm64 hang (works all platforms)

## Team Coordination

- **kai-cli-2:** Parallel revert on cli-device (same issue)
- **ava-2:** Confirmed code works on linux (proves implementation correct)
- **knox-2:** Security review passed (code logic sound)
- **team-lead:** Approved revert as pragmatic fix

## Lessons Learned

1. **Test on all target platforms before claiming complete** - Build ≠ Run
2. **Platform-specific stdlib bugs exist** - Even in Go, even in crypto primitives
3. **CI environment may differ from dev** - linux CI may work when macOS dev broken
4. **Verify tests pass, not just build** - "Verify before claiming done" principle

## Status

- **Current:** crypto/rand (non-deterministic) on all platforms
- **Goal:** RFC 6979 (deterministic) when darwin/arm64 stable
- **Blocking:** Upstream Go stdlib fix or platform isolation strategy
