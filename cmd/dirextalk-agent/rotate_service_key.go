package main

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/auth"
	"github.com/YingSuiAI/dirextalk-agent/internal/config"
	"github.com/YingSuiAI/dirextalk-agent/internal/store/postgres"
)

var bootstrapServiceKeyIDPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{1,128}$`)

type bootstrapServiceKeyRotationInput struct {
	PreviousKeyID string
	KeyID         string
	ClientID      string
	Scopes        []string
	SecretDigest  []byte
}

func rotateBootstrapServiceKey() error {
	common, err := config.LoadCommon()
	if err != nil {
		return err
	}
	input, err := bootstrapServiceKeyRotationInputFromEnvironment()
	if err != nil {
		return err
	}
	defer clear(input.SecretDigest)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	pool, err := postgres.Open(ctx, common.DatabaseURL)
	if err != nil {
		return err
	}
	defer pool.Close()
	if err := postgres.VerifySchema(ctx, pool, common.InstanceID); err != nil {
		return err
	}
	store, err := postgres.New(pool, common.InstanceID)
	if err != nil {
		return err
	}
	replacement, revoked, err := store.RotateBootstrapCredential(ctx, input.PreviousKeyID, auth.BootstrapCredential{
		KeyID: input.KeyID, ClientID: input.ClientID, Scopes: input.Scopes, SecretDigest: input.SecretDigest,
	})
	if err != nil {
		return err
	}
	slog.Info(
		"bootstrap service credential rotated",
		"client_id", replacement.ClientID,
		"key_id", replacement.KeyID,
		"revoked_key_id", revoked.KeyID,
	)
	return nil
}

func bootstrapServiceKeyRotationInputFromEnvironment() (bootstrapServiceKeyRotationInput, error) {
	previousKeyID := strings.TrimSpace(os.Getenv("AGENT_PREVIOUS_BOOTSTRAP_SERVICE_KEY_ID"))
	pepperPath := strings.TrimSpace(os.Getenv("AGENT_SERVICE_KEY_PEPPER_FILE"))
	keyPath := strings.TrimSpace(os.Getenv("AGENT_BOOTSTRAP_SERVICE_KEY_FILE"))
	clientID := strings.TrimSpace(os.Getenv("AGENT_BOOTSTRAP_CLIENT_ID"))
	if !bootstrapServiceKeyIDPattern.MatchString(previousKeyID) || pepperPath == "" || keyPath == "" || clientID == "" {
		return bootstrapServiceKeyRotationInput{}, errors.New("valid AGENT_PREVIOUS_BOOTSTRAP_SERVICE_KEY_ID, AGENT_SERVICE_KEY_PEPPER_FILE, AGENT_BOOTSTRAP_SERVICE_KEY_FILE, and AGENT_BOOTSTRAP_CLIENT_ID are required")
	}
	scopes := splitScopes(os.Getenv("AGENT_BOOTSTRAP_SCOPES"))
	if len(scopes) == 0 {
		return bootstrapServiceKeyRotationInput{}, errors.New("AGENT_BOOTSTRAP_SCOPES must explicitly list replacement scopes")
	}
	pepper, err := config.ReadKeyMaterial(pepperPath)
	if err != nil {
		return bootstrapServiceKeyRotationInput{}, err
	}
	defer clear(pepper)
	if err := config.ValidateMountedSecretFile(keyPath); err != nil {
		return bootstrapServiceKeyRotationInput{}, err
	}
	raw, err := os.ReadFile(keyPath)
	if err != nil {
		return bootstrapServiceKeyRotationInput{}, errors.New("could not read mounted replacement service key")
	}
	defer clear(raw)
	keyID, secret, err := auth.ReadSecretFileValue(raw)
	if err != nil {
		return bootstrapServiceKeyRotationInput{}, err
	}
	defer clear(secret)
	if keyID == previousKeyID {
		return bootstrapServiceKeyRotationInput{}, errors.New("replacement service key must use a new key id")
	}
	return bootstrapServiceKeyRotationInput{
		PreviousKeyID: previousKeyID,
		KeyID:         keyID,
		ClientID:      clientID,
		Scopes:        scopes,
		SecretDigest:  auth.Digest(pepper, secret),
	}, nil
}
