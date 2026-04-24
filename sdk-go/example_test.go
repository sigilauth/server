package sigilauth_test

import (
	"context"
	"fmt"
	"log"
	"os"

	sigilauth "github.com/sigilauth/sdk-go"
)

func ExampleNew() {
	os.Setenv("SIGIL_API_KEY", "sgk_test_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")

	client, err := sigilauth.New(sigilauth.Config{
		ServiceURL: "https://sigil.example.com",
	})
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Client configured successfully\n")
	_ = client
}

func ExampleAuthService_CreateChallenge() {
	os.Setenv("SIGIL_API_KEY", "sgk_test_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")

	client, _ := sigilauth.New(sigilauth.Config{
		ServiceURL: "https://sigil.example.com",
	})

	ctx := context.Background()
	challenge, err := client.Auth.CreateChallenge(ctx, &sigilauth.ChallengeRequest{
		Fingerprint:     "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2",
		DevicePublicKey: "Ag8xYzI3ZWRkNDUzYmNlYzVmMTJjNmI5MzA4OGY0",
		Action: sigilauth.Action{
			Type:        "step_up",
			Description: "Add WebAuthn key",
			Params: map[string]interface{}{
				"key_name": "Sarah's YubiKey",
			},
		},
	})
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Challenge ID: %s\n", challenge.ChallengeID)
	fmt.Printf("Pictogram: %v\n", challenge.Pictogram)
}

func ExampleAuthService_AwaitResult() {
	os.Setenv("SIGIL_API_KEY", "sgk_test_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")

	client, _ := sigilauth.New(sigilauth.Config{
		ServiceURL: "https://sigil.example.com",
	})

	ctx := context.Background()
	status, err := client.Auth.AwaitResult(ctx, "challenge-id", &sigilauth.AwaitOptions{
		PollInterval: 1000,
		MaxAttempts:  30,
	})
	if err != nil {
		log.Fatal(err)
	}

	if status.Status == "verified" && status.Decision == "approved" {
		fmt.Println("Challenge approved!")
	}
}

func ExampleMPAService_Request() {
	os.Setenv("SIGIL_API_KEY", "sgk_test_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")

	client, _ := sigilauth.New(sigilauth.Config{
		ServiceURL: "https://sigil.example.com",
	})

	ctx := context.Background()
	result, err := client.MPA.Request(ctx, &sigilauth.MPARequest{
		RequestID: "mpa_xyz789",
		Action: sigilauth.Action{
			Type:        "engine:cold-boot",
			Description: "Cold boot engine ENG-001",
			Params: map[string]interface{}{
				"engine_id": "eng_001",
			},
		},
		Required: 2,
		Groups: []sigilauth.MPAGroup{
			{
				Members: []sigilauth.MPAGroupMember{
					{
						Fingerprint:     "a1b2c3d4",
						DevicePublicKey: "Ag8xYzI3ZWRkNDUz",
					},
				},
			},
			{
				Members: []sigilauth.MPAGroupMember{
					{
						Fingerprint:     "b2c3d4e5",
						DevicePublicKey: "AhJkbG1hb3B3",
					},
				},
			},
		},
	})
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("MPA request created: %s\n", result.RequestID)
	fmt.Printf("Requires %d approvals from %d groups\n", result.GroupsRequired, result.GroupsTotal)
}

func ExampleWebhookService_Verify() {
	webhooks := &sigilauth.WebhookService{}

	headers := map[string][]string{
		"X-Sigil-Signature": {"v1,abc123..."},
		"X-Sigil-Timestamp": {"1234567890"},
	}
	body := []byte(`{"event":"challenge.verified"}`)
	secret := "whsec_test123"

	err := webhooks.Verify(headers, body, secret)
	if err != nil {
		log.Printf("Webhook verification failed: %v", err)
		return
	}

	fmt.Println("Webhook verified successfully")
}
