package coreconfirmation

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestPersistentServicePublicQuoteContainsOnlyHourlyPrice(t *testing.T) {
	now := time.Date(2026, 8, 16, 8, 0, 0, 0, time.UTC)
	binding := Binding{
		OperationDomain: "cloud_worker.execute",
		TargetKind:      TargetKindPersistentService,
		Quote: &LiveQuote{
			AmountMicros: 120_000, ComputeMicrosPerHour: 25_000, Currency: "USD",
			SourceTime: now, ExpiresAt: now.Add(5 * time.Minute), MaximumAuthorizedCostMicros: 150_000,
		},
	}
	encoded, err := json.Marshal(binding.Public())
	if err != nil {
		t.Fatal(err)
	}
	text := string(encoded)
	if !strings.Contains(text, `"compute_micros_per_hour":25000`) || !strings.Contains(text, `"currency":"USD"`) {
		t.Fatalf("hourly quote missing: %s", text)
	}
	if !strings.Contains(text, `"target_kind":"persistent_service"`) {
		t.Fatalf("target kind missing: %s", text)
	}
	if strings.Contains(text, "amount_micros") || strings.Contains(text, "maximum_authorized_cost_micros") {
		t.Fatalf("persistent service exposed bounded-job pricing: %s", text)
	}

	binding.TargetKind = "persistent_ssh_worker"
	encoded, err = json.Marshal(binding.Public())
	if err != nil {
		t.Fatal(err)
	}
	text = string(encoded)
	if !strings.Contains(text, `"amount_micros":120000`) || !strings.Contains(text, `"maximum_authorized_cost_micros":150000`) {
		t.Fatalf("bounded job pricing missing: %s", text)
	}
	if !strings.Contains(text, `"target_kind":"persistent_ssh_worker"`) {
		t.Fatalf("bounded target kind missing: %s", text)
	}
}
