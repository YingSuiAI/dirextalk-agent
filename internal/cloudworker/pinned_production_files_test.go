package cloudworker

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func writePinnedJSON(t *testing.T, name string, value any) (string, string) {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, raw, 0o400); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(raw)
	return path, hex.EncodeToString(digest[:])
}

func TestPinnedPricingCatalogBindsFileAndExactRequest(t *testing.T) {
	now := time.Date(2026, 8, 7, 10, 0, 0, 0, time.UTC)
	document := pricingCatalogDocument{
		Schema: PricingCatalogFileSchema, AccountID: "123456789012", Region: "us-east-1",
		InstanceType: "c7i.large", Architecture: "x86_64", VolumeType: "gp3",
		SourceTime: now, ExpiresAt: now.Add(10 * time.Minute),
		Rates: PricingCatalogRates{
			ComputeMicrosPerHour: 100_000, EBSStorageMicrosPerGiBMonth: 80_000,
			PublicIPv4MicrosPerHour: 5_000, ModelMicrosPerThousandTokens: 10_000,
		},
	}
	path, digest := writePinnedJSON(t, "pricing.json", document)
	catalog, err := NewPinnedPricingCatalog(path, digest)
	if err != nil {
		t.Fatal(err)
	}
	request := PricingCatalogRequest{
		AccountID: document.AccountID, AccountGeneration: 7, Region: document.Region,
		InstanceType: document.InstanceType, Architecture: document.Architecture,
		VolumeGiB: 32, VolumeType: document.VolumeType, VolumeIOPS: 3000,
		VolumeThroughput: 125, MaxRuntimeSeconds: 3600, MaxTokens: 2000,
		BasisDigest: digestValue("basis"), WorkspaceMode: WorkspaceNone,
	}
	snapshot, err := catalog.Snapshot(context.Background(), request)
	if err != nil || snapshot.RequestDigest != request.digest() || snapshot.RevisionDigest == "" {
		t.Fatalf("snapshot=%+v err=%v", snapshot, err)
	}
	request.Region = "us-west-2"
	if _, err := catalog.Snapshot(context.Background(), request); err == nil {
		t.Fatal("catalog accepted a different Region")
	}
	if _, err := NewPinnedPricingCatalog(path, digestValue("different")); err == nil {
		t.Fatal("catalog accepted a mismatched file pin")
	}
}

func TestPinnedRuntimeQualificationRequiresAuthorizedRelease(t *testing.T) {
	now := time.Date(2026, 8, 7, 10, 0, 0, 0, time.UTC)
	plan, _, _, _ := stagingFixture(t, now)
	document := runtimeQualificationDocument{
		Schema: RuntimeQualificationFileSchema, AMIID: plan.Compute.AMIID,
		AMIDigest: plan.Compute.AMIDigest, WorkerReleaseDigest: plan.Compute.WorkerReleaseDigest,
		PiRuntimeDigest: plan.Compute.PiRuntimeDigest, Architecture: plan.Compute.Architecture,
		PiVersion: "0.44.0", PiExecutableSHA256: digestValue("pi-executable"),
		ResultExtensionSHA256:   digestValue("result-extension"),
		HostNetworkPolicySHA256: plan.Compute.HostNetworkPolicySHA256,
	}
	path, digest := writePinnedJSON(t, "qualification.json", document)
	resolver, err := NewPinnedRuntimeQualification(path, digest)
	if err != nil {
		t.Fatal(err)
	}
	qualification, err := resolver.ResolveRuntimeQualification(context.Background(), plan)
	if err != nil || qualification.PiRuntimeDigest != plan.Compute.PiRuntimeDigest || qualification.PiExecutableSHA256 != document.PiExecutableSHA256 {
		t.Fatalf("qualification=%+v err=%v", qualification, err)
	}
	plan.Compute.WorkerReleaseDigest = digestValue("drift")
	if _, err := resolver.ResolveRuntimeQualification(context.Background(), plan); err == nil {
		t.Fatal("qualification accepted a drifted Worker release")
	}
}
