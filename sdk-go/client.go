package sigilauth

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
)

type Client struct {
	config     Config
	httpClient *http.Client

	Auth     *AuthService
	MPA      *MPAService
	Webhooks *WebhookService
}

func New(config Config) (*Client, error) {
	if err := config.Validate(); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}

	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
	}

	if len(config.TLSCertPinning) > 0 {
		certPool := x509.NewCertPool()
		for _, cert := range config.TLSCertPinning {
			if !certPool.AppendCertsFromPEM([]byte(cert)) {
				return nil, fmt.Errorf("failed to add pinned certificate")
			}
		}
		tlsConfig.RootCAs = certPool
	}

	httpClient := &http.Client{
		Timeout: config.HTTPTimeout,
		Transport: &http.Transport{
			TLSClientConfig: tlsConfig,
		},
	}

	client := &Client{
		config:     config,
		httpClient: httpClient,
	}

	client.Auth = &AuthService{client: client}
	client.MPA = &MPAService{client: client}
	client.Webhooks = &WebhookService{client: client}

	return client, nil
}
