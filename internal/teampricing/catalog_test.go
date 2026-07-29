package teampricing

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	modelapi "github.com/YingSuiAI/dirextalk-agent/internal/model"
	"github.com/YingSuiAI/dirextalk-agent/internal/recipe"
	"github.com/YingSuiAI/dirextalk-agent/internal/teamplan"
)

func TestModelOfferCatalogResolvesServerOwnedProfiles(t *testing.T) {
	t.Parallel()
	catalog, err := NewModelOfferCatalog(validCatalogDocument(), profileCatalog(t))
	if err != nil {
		t.Fatal(err)
	}
	if catalog.Currency() != "USD" {
		t.Fatalf("Currency() = %q", catalog.Currency())
	}
	offers := catalog.catalogOffers()
	if len(offers) != 2 {
		t.Fatalf("offers = %d", len(offers))
	}
	got := offers[1].offer
	if got.ProfileID != "openai-codex" ||
		got.Provider != string(modelapi.ProviderOpenAICompatible) ||
		got.Model != "gpt-codex" ||
		got.ContextTokens != 256_000 ||
		got.CredentialRef != "secret_ref:model/openai-codex" {
		t.Fatalf("resolved offer = %#v", got)
	}
}

func TestModelOfferCatalogRejectsUntrustedMetadata(t *testing.T) {
	t.Parallel()
	tests := map[string]func(*ModelOfferCatalogDocument){
		"unknown profile": func(value *ModelOfferCatalogDocument) {
			value.Offers[0].ProfileID = "unknown"
		},
		"duplicate profile": func(value *ModelOfferCatalogDocument) {
			value.Offers[1].ProfileID = value.Offers[0].ProfileID
		},
		"raw credential": func(value *ModelOfferCatalogDocument) {
			value.Offers[0].WorkerCredentialRef =
				"sk-abcdefghijklmnopqrstuvwxyz012345"
		},
		"provider interface mismatch": func(value *ModelOfferCatalogDocument) {
			value.Offers[0].Interface = teamplan.ModelOpenAIResponses
		},
		"unknown pricing source": func(value *ModelOfferCatalogDocument) {
			value.Offers[0].SourceID = "missing-source"
		},
		"unused pricing source": func(value *ModelOfferCatalogDocument) {
			value.Sources = append(value.Sources, ModelPriceSource{
				SourceID:   "unused-source",
				Digest:     "sha256:" + strings.Repeat("a", 64),
				CapturedAt: value.Sources[0].CapturedAt,
			})
		},
		"noncanonical timestamp": func(value *ModelOfferCatalogDocument) {
			value.Sources[0].CapturedAt =
				value.Sources[0].CapturedAt.Add(time.Nanosecond)
		},
	}
	for name, mutate := range tests {
		name, mutate := name, mutate
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			document := validCatalogDocument()
			mutate(&document)
			if _, err := NewModelOfferCatalog(
				document,
				profileCatalog(t),
			); !errors.Is(err, ErrInvalidModelCatalog) {
				t.Fatalf("error = %v, want ErrInvalidModelCatalog", err)
			}
		})
	}
}

func TestLoadModelOfferCatalogIsStrictAndProtected(t *testing.T) {
	t.Parallel()
	directory := t.TempDir()
	document := validCatalogDocument()
	raw, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "catalog.json")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadModelOfferCatalog(path, profileCatalog(t)); err != nil {
		t.Fatalf("LoadModelOfferCatalog() error = %v", err)
	}

	unknown := filepath.Join(directory, "unknown.json")
	unknownRaw := append(raw[:len(raw)-1], []byte(`,"unexpected":true}`)...)
	if err := os.WriteFile(unknown, unknownRaw, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadModelOfferCatalog(
		unknown,
		profileCatalog(t),
	); !errors.Is(err, ErrInvalidModelCatalog) {
		t.Fatalf("unknown field error = %v", err)
	}

	loose := filepath.Join(directory, "loose.json")
	if err := os.WriteFile(loose, raw, 0o666); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(loose, 0o666); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadModelOfferCatalog(
		loose,
		profileCatalog(t),
	); !errors.Is(err, ErrInvalidModelCatalog) {
		t.Fatalf("loose permission error = %v", err)
	}

	linked := filepath.Join(directory, "linked.json")
	if err := os.Symlink(path, linked); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadModelOfferCatalog(
		linked,
		profileCatalog(t),
	); !errors.Is(err, ErrInvalidModelCatalog) {
		t.Fatalf("symlink error = %v", err)
	}
}

func validCatalogDocument() ModelOfferCatalogDocument {
	capturedAt := time.Date(2026, 7, 29, 8, 0, 0, 0, time.UTC)
	return ModelOfferCatalogDocument{
		SchemaVersion: ModelOfferCatalogSchemaV1,
		Currency:      "USD",
		Sources: []ModelPriceSource{
			{
				SourceID:   "anthropic-pricing-2026-07",
				Digest:     "sha256:" + strings.Repeat("1", 64),
				CapturedAt: capturedAt,
			},
			{
				SourceID:   "openai-pricing-2026-07",
				Digest:     "sha256:" + strings.Repeat("2", 64),
				CapturedAt: capturedAt,
			},
		},
		Offers: []ModelOfferEntry{
			{
				ProfileID:              "anthropic-review",
				Interface:              teamplan.ModelAnthropicAPI,
				Quality:                teamplan.QualityPremium,
				InputMicrosPerMillion:  5_000_000,
				OutputMicrosPerMillion: 25_000_000,
				WorkerCredentialRef:    "secret_ref:model/anthropic-review",
				Enabled:                false,
				SourceID:               "anthropic-pricing-2026-07",
			},
			{
				ProfileID:              "openai-codex",
				Interface:              teamplan.ModelOpenAIResponses,
				Quality:                teamplan.QualityBalanced,
				InputMicrosPerMillion:  2_000_000,
				OutputMicrosPerMillion: 8_000_000,
				WorkerCredentialRef:    "secret_ref:model/openai-codex",
				Enabled:                true,
				SourceID:               "openai-pricing-2026-07",
			},
		},
	}
}

func profileCatalog(t *testing.T) *modelapi.ProfileCatalog {
	t.Helper()
	catalog, err := modelapi.NewProfileCatalog([]modelapi.Profile{
		{
			ProfileID:       "anthropic-review",
			Provider:        modelapi.ProviderAnthropic,
			Model:           "claude-review",
			BaseURL:         "https://api.anthropic.example/v1",
			SecretRef:       "mounted:anthropic-review",
			ContextWindow:   200_000,
			MaxOutputTokens: 32_000,
		},
		{
			ProfileID:       "openai-codex",
			Provider:        modelapi.ProviderOpenAICompatible,
			Model:           "gpt-codex",
			BaseURL:         "https://api.openai.example/v1",
			SecretRef:       "mounted:openai-codex",
			ContextWindow:   256_000,
			MaxOutputTokens: 64_000,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return catalog
}

type fakeCredentialReadiness struct {
	ready map[string]bool
	calls []string
	err   error
}

func (fake *fakeCredentialReadiness) Ready(
	_ context.Context,
	reference string,
) (bool, error) {
	fake.calls = append(fake.calls, reference)
	return fake.ready[reference], fake.err
}

type fakeComputePort struct {
	evidence ComputeEvidence
	err      error
	calls    []string
}

func (fake *fakeComputePort) ReadComputeOffers(
	_ context.Context,
	region string,
) (ComputeEvidence, error) {
	fake.calls = append(fake.calls, region)
	return fake.evidence, fake.err
}

func validComputeEvidence(now time.Time) ComputeEvidence {
	return ComputeEvidence{
		Currency: "USD",
		Sources: []teamplan.OfferSourceReceipt{
			{
				Kind:       teamplan.OfferSourceComputePricing,
				SourceID:   "aws-price-list-us-east-1",
				Digest:     "sha256:" + strings.Repeat("3", 64),
				CapturedAt: now.Add(-5 * time.Minute),
			},
			{
				Kind:       teamplan.OfferSourceComputeCapacity,
				SourceID:   "aws-capacity-us-east-1",
				Digest:     "sha256:" + strings.Repeat("4", 64),
				CapturedAt: now.Add(-2 * time.Minute),
			},
		},
		Offers: []teamplan.ComputeOffer{
			{
				OfferID:        "10000000-0000-4000-8000-000000000001",
				Region:         "us-east-1",
				InstanceType:   "m7i.large",
				Architecture:   recipe.ArchitectureAMD64,
				VCPU:           2,
				MemoryMiB:      8192,
				DiskGiB:        40,
				HourlyMicros:   120_000,
				PurchaseOption: "on_demand",
				CapacityPool:   "aws:ec2:standard",
				CapacityUnits:  2,
				AvailableUnits: 64,
				Available:      true,
			},
		},
	}
}
