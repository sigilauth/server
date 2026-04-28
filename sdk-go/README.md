# Sigil Auth Go SDK

Official Go client for [Sigil Auth](https://sigilauth.com) — PKI-based strong authentication with hardware-backed keys.

## Installation

```bash
go get github.com/sigilauth/sdk-go
```

## Quick Start

```go
package main

import (
    "context"
    "log"
    "os"
    
    sigilauth "github.com/sigilauth/sdk-go"
)

func main() {
    client, err := sigilauth.New(sigilauth.Config{
        ServiceURL: "https://sigil.example.com",
        APIKey:     os.Getenv("SIGIL_API_KEY"),
    })
    if err != nil {
        log.Fatal(err)
    }
    
    ctx := context.Background()
    challenge, err := client.Auth.CreateChallenge(ctx, &sigilauth.ChallengeRequest{
        Fingerprint:     "a1b2c3d4...",
        DevicePublicKey: "Ag8xYzI3ZWRk...",
        Action: sigilauth.Action{
            Type:        "step_up",
            Description: "Add WebAuthn key",
        },
    })
    if err != nil {
        log.Fatal(err)
    }
    
    log.Printf("Challenge created: %s", challenge.ChallengeID)
}
```

## Features

- **Type-safe API** — structs match OpenAPI spec
- **Automatic retries** — exponential backoff for 429 + 5xx errors
- **Context support** — cancellation + timeout propagation
- **TLS verification** — mandatory by default, optional certificate pinning
- **Webhook helpers** — HMAC-SHA256 signature verification

## Security

- **API keys from environment only** — constructor rejects hardcoded keys
- **TLS verification mandatory** — cannot be disabled
- **Secrets redacted in logs** — last 4 characters only

## License

Apache-2.0 (API specification license)
