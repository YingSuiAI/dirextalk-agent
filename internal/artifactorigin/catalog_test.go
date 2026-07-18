package artifactorigin

import (
	"testing"

	assets "github.com/YingSuiAI/dirextalk-agent/deploy/awsartifactorigin"
	"github.com/YingSuiAI/dirextalk-agent/internal/knowledgeprofile"
)

func TestPinnedKnowledgeCatalog(t *testing.T) {
	catalog, err := ParseCatalog(assets.KnowledgeCatalog())
	if err != nil {
		t.Fatalf("ParseCatalog() error = %v", err)
	}
	want := map[string]struct {
		sha  string
		size int64
	}{
		"qdrant-linux-amd64":                     {"b4faedcdf8c9577bf1c8f2ab9b454636b87e056c116c99d49bd4f9fb2e634285", 30745357},
		"multilingual-e5-small-onnx":             {"ca456c06b3a9505ddfd9131408916dd79290368331e7d76bb621f1cba6bc8665", 470268510},
		"multilingual-e5-small-tokenizer":        {"0b44a9d7b51c3c62626640cda0e2c2f70fdacdc25bbbd68038369d14ebdf4c39", 17082730},
		"multilingual-e5-small-config":           {"69137736cab8b8903a07fe8afaafdda25aac55415a12a55d1bffa9f581abf959", 655},
		"multilingual-e5-small-tokenizer-config": {"a1d6bc8734a6f635dc158508bef000f8e2e5a759c7d92f984b2c86e5ff53425b", 443},
		"multilingual-e5-small-special-tokens":   {"d05497f1da52c5e09554c0cd874037a083e1dc1b9cfd48034d1c717f1afc07a7", 167},
		"knowledge-installer-linux-amd64":        {"ddfd0578bec82f1051ded9c49f90ce552b6284b4b0a30f09c12a663d79feae86", 7376597},
		"multilingual-e5-small-bundle":           {"ccf5b7e718151700b91a8fc632628a75a5756ddc18452e888e6f8950c0a5d198", 299428899},
		"knowledge-adapter-bundle":               {"61ef32ad69a4fed9fbf7444d34358f433dae9cbbb8ff47bc34b6871bad03eeb5", 43111084},
		"knowledge-provenance-v1":                {"58e3b6217b30cecb46908ccf87900fbbed331acb825d8380ad0fab43a32072c2", 1090},
		"knowledge-release-manifest-v1":          {"78a75a2974a6282f90cb749b373c4c48959ec9c348d2e2f4f15ea0a6abf5e4e3", 2429},
	}
	if len(catalog.Artifacts) != len(want) {
		t.Fatalf("catalog has %d artifacts, want %d", len(catalog.Artifacts), len(want))
	}
	for id, expected := range want {
		artifact, ok := catalog.Lookup(id)
		if !ok || artifact.SHA256 != expected.sha || artifact.SizeBytes != expected.size {
			t.Fatalf("catalog[%q] = %#v, want digest %s size %d", id, artifact, expected.sha, expected.size)
		}
	}
}

func TestPinnedCatalogPublishesEveryRetainedKnowledgeRecipeArtifact(t *testing.T) {
	t.Parallel()
	catalog, err := ParseCatalog(assets.KnowledgeCatalog())
	if err != nil {
		t.Fatal(err)
	}
	release, ok := knowledgeprofile.ReleaseManifest()
	if !ok {
		t.Fatal("retained Knowledge release manifest is invalid")
	}
	for _, item := range release.Artifacts {
		artifact, found := catalog.Lookup(item.ID)
		if !found || artifact.Name != item.Name || artifact.SHA256 != item.SHA256 || artifact.SizeBytes != item.SizeBytes ||
			item.URL != "https://"+DomainName+"/"+artifact.ObjectKey() {
			t.Fatalf("catalog does not publish retained artifact %q: %#v", item.ID, artifact)
		}
	}
	manifest, found := catalog.Lookup("knowledge-release-manifest-v1")
	if !found || manifest.Name != knowledgeprofile.ManifestName || manifest.SHA256 != knowledgeprofile.ManifestSHA256 || manifest.SizeBytes != 2429 ||
		knowledgeprofile.ManifestURL() != "https://"+DomainName+"/"+manifest.ObjectKey() {
		t.Fatalf("catalog does not publish the research manifest: %#v", manifest)
	}
}

func TestParseCatalogRejectsDuplicateAndMutableSource(t *testing.T) {
	for _, raw := range []string{
		`{"schema_version":"dirextalk.artifact-origin.catalog/v1","artifacts":[{"id":"a","name":"a.bin","sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","size_bytes":1,"media_type":"application/octet-stream","source_url":"https://example.com/a","source_revision":"v1","license":"MIT"},{"id":"a","name":"b.bin","sha256":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","size_bytes":1,"media_type":"application/octet-stream","source_url":"https://example.com/b","source_revision":"v1","license":"MIT"}]}`,
		`{"schema_version":"dirextalk.artifact-origin.catalog/v1","artifacts":[{"id":"a","name":"a.bin","sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","size_bytes":1,"media_type":"application/octet-stream","source_url":"http://example.com/a","source_revision":"latest","license":"MIT"}]}`,
		`{"schema_version":"dirextalk.artifact-origin.catalog/v1","artifacts":[{"id":"a","name":"a.bin","sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","size_bytes":1,"media_type":"application/octet-stream","source_url":"https://example.com/a?X-Amz-Signature=secret","source_revision":"v1","license":"MIT"}]}`,
	} {
		if _, err := ParseCatalog([]byte(raw)); err == nil {
			t.Fatal("ParseCatalog accepted an ambiguous or mutable catalog")
		}
	}
}
