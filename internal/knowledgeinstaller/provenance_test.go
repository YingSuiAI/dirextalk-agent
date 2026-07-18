package installer

import (
	"reflect"
	"testing"
)

func TestPinnedProvenanceAcceptsOnlyExactModelAndQdrant(t *testing.T) {
	t.Parallel()
	files := make([]ModelFileEvidence, 0, len(expectedModelFiles))
	for _, name := range []string{"onnx/model.onnx", "tokenizer.json", "config.json", "tokenizer_config.json", "special_tokens_map.json"} {
		files = append(files, expectedModelFiles[name])
	}
	value := Provenance{
		SchemaVersion: 1,
		Qdrant: ArtifactEvidence{
			Name: "qdrant-x86_64-unknown-linux-musl.tar.gz", Version: QdrantVersion, Size: QdrantSize, SHA256: QdrantSHA256,
		},
		Model:         ModelEvidence{Repository: "intfloat/multilingual-e5-small", Revision: ModelRevision, Files: files},
		AdapterBundle: ArtifactEvidence{Name: "dirextalk-knowledge-adapter.tar.gz", Version: "v1", Size: 1, SHA256: "1111111111111111111111111111111111111111111111111111111111111111"},
	}
	if err := value.Validate(); err != nil {
		t.Fatal(err)
	}
	value.Model.Files[0].Size++
	if err := value.Validate(); err == nil {
		t.Fatal("expected model mismatch")
	}
}

func TestMultilingualE5ProvenanceBindsRepositoryRevisionAndEveryFile(t *testing.T) {
	t.Parallel()
	want := map[string]ModelFileEvidence{
		"onnx/model.onnx":         {Path: "onnx/model.onnx", Size: 470_268_510, SHA256: "ca456c06b3a9505ddfd9131408916dd79290368331e7d76bb621f1cba6bc8665"},
		"tokenizer.json":          {Path: "tokenizer.json", Size: 17_082_730, SHA256: "0b44a9d7b51c3c62626640cda0e2c2f70fdacdc25bbbd68038369d14ebdf4c39"},
		"config.json":             {Path: "config.json", Size: 655, SHA256: "69137736cab8b8903a07fe8afaafdda25aac55415a12a55d1bffa9f581abf959"},
		"tokenizer_config.json":   {Path: "tokenizer_config.json", Size: 443, SHA256: "a1d6bc8734a6f635dc158508bef000f8e2e5a759c7d92f984b2c86e5ff53425b"},
		"special_tokens_map.json": {Path: "special_tokens_map.json", Size: 167, SHA256: "d05497f1da52c5e09554c0cd874037a083e1dc1b9cfd48034d1c717f1afc07a7"},
	}
	if ModelRevision != "0e60b8d9d2166d80387f86e3b48ec9ced55f4d15" {
		t.Fatalf("model revision = %q", ModelRevision)
	}
	if !reflect.DeepEqual(expectedModelFiles, want) {
		t.Fatalf("multilingual-e5-small file evidence changed: %#v", expectedModelFiles)
	}
	provenance := Provenance{
		SchemaVersion: 1,
		Qdrant:        ArtifactEvidence{Name: "qdrant-x86_64-unknown-linux-musl.tar.gz", Version: QdrantVersion, Size: QdrantSize, SHA256: QdrantSHA256},
		Model: ModelEvidence{
			Repository: "intfloat/multilingual-e5-small",
			Revision:   ModelRevision,
			Files: []ModelFileEvidence{
				want["onnx/model.onnx"], want["tokenizer.json"], want["config.json"], want["tokenizer_config.json"], want["special_tokens_map.json"],
			},
		},
		AdapterBundle: ArtifactEvidence{Name: "dirextalk-knowledge-adapter.tar.gz", Version: "v1", Size: 1, SHA256: "1111111111111111111111111111111111111111111111111111111111111111"},
	}
	if err := provenance.Validate(); err != nil {
		t.Fatal(err)
	}
	provenance.Model.Repository = "intfloat/e5-small-v2"
	if err := provenance.Validate(); err == nil {
		t.Fatal("mislabeled e5-small-v2 provenance was accepted")
	}
}
