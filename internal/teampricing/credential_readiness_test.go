package teampricing

import (
	"context"
	"errors"
	"testing"

	modelapi "github.com/YingSuiAI/dirextalk-agent/internal/model"
)

func TestCatalogCredentialReadinessResolvesOnlyMappedSourceAndClearsIt(
	t *testing.T,
) {
	t.Parallel()
	catalog, err := NewModelOfferCatalog(
		validCatalogDocument(),
		profileCatalog(t),
	)
	if err != nil {
		t.Fatal(err)
	}
	resolver := &credentialReadinessResolver{
		secret: []byte("synthetic-provider-token"),
	}
	readiness, err := NewCatalogCredentialReadiness(catalog, resolver)
	if err != nil {
		t.Fatal(err)
	}
	ready, err := readiness.Ready(
		context.Background(),
		"secret_ref:model/openai-codex",
	)
	if err != nil || !ready ||
		resolver.reference != "mounted:openai-codex" {
		t.Fatalf(
			"Ready() ready=%v reference=%q error=%v",
			ready,
			resolver.reference,
			err,
		)
	}
	for index, value := range resolver.secret {
		if value != 0 {
			t.Fatalf("secret byte %d was not cleared", index)
		}
	}
	resolver.calls = 0
	ready, err = readiness.Ready(
		context.Background(),
		"secret_ref:model/not-configured",
	)
	if err != nil || ready || resolver.calls != 0 {
		t.Fatalf(
			"unknown Ready() ready=%v calls=%d error=%v",
			ready,
			resolver.calls,
			err,
		)
	}
}

func TestCatalogCredentialReadinessTreatsMissingMountedSecretAsNotReady(
	t *testing.T,
) {
	t.Parallel()
	catalog, err := NewModelOfferCatalog(
		validCatalogDocument(),
		profileCatalog(t),
	)
	if err != nil {
		t.Fatal(err)
	}
	readiness, err := NewCatalogCredentialReadiness(
		catalog,
		&credentialReadinessResolver{
			err: modelapi.ErrSecretUnavailable,
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	ready, err := readiness.Ready(
		context.Background(),
		"secret_ref:model/openai-codex",
	)
	if err != nil || ready {
		t.Fatalf("Ready() ready=%v error=%v", ready, err)
	}
}

func TestCatalogCredentialReadinessPropagatesCancellation(t *testing.T) {
	t.Parallel()
	catalog, err := NewModelOfferCatalog(
		validCatalogDocument(),
		profileCatalog(t),
	)
	if err != nil {
		t.Fatal(err)
	}
	readiness, err := NewCatalogCredentialReadiness(
		catalog,
		&credentialReadinessResolver{},
	)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := readiness.Ready(
		ctx,
		"secret_ref:model/openai-codex",
	); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled Ready() error=%v", err)
	}
}

func TestCatalogCredentialMaterializationRequiresExactApprovedSelection(
	t *testing.T,
) {
	t.Parallel()
	catalog, err := NewModelOfferCatalog(
		validCatalogDocument(),
		profileCatalog(t),
	)
	if err != nil {
		t.Fatal(err)
	}
	resolver := &credentialReadinessResolver{
		secret: []byte("synthetic-provider-token"),
	}
	readiness, err := NewCatalogCredentialReadiness(catalog, resolver)
	if err != nil {
		t.Fatal(err)
	}
	request := CredentialMaterializationRequest{
		ProfileID:           "openai-codex",
		Provider:            "openai",
		Model:               "gpt-codex",
		ModelInterface:      "openai_responses",
		WorkerCredentialRef: "secret_ref:model/openai-codex",
	}
	var observed []byte
	if err := readiness.Materialize(
		context.Background(),
		request,
		func(secret []byte) error {
			observed = append([]byte(nil), secret...)
			return nil
		},
	); err != nil {
		t.Fatal(err)
	}
	if string(observed) != "synthetic-provider-token" ||
		resolver.reference != "mounted:openai-codex" {
		t.Fatalf(
			"materialized=%q source=%q",
			observed,
			resolver.reference,
		)
	}
	for index, value := range resolver.secret {
		if value != 0 {
			t.Fatalf("secret byte %d was not cleared", index)
		}
	}

	resolver.calls = 0
	resolver.secret = []byte("must-not-be-read")
	request.Model = "substituted-model"
	if err := readiness.Materialize(
		context.Background(),
		request,
		func([]byte) error {
			t.Fatal("mismatched selection reached secret callback")
			return nil
		},
	); !errors.Is(err, ErrCredentialReadinessUnavailable) {
		t.Fatalf("mismatched selection error=%v", err)
	}
	if resolver.calls != 0 {
		t.Fatalf("mismatched selection resolved %d secrets", resolver.calls)
	}
}

type credentialReadinessResolver struct {
	secret    []byte
	err       error
	calls     int
	reference string
}

func (resolver *credentialReadinessResolver) ResolveSecret(
	_ context.Context,
	reference string,
) ([]byte, error) {
	resolver.calls++
	resolver.reference = reference
	return resolver.secret, resolver.err
}

var _ modelapi.SecretResolver = (*credentialReadinessResolver)(nil)
