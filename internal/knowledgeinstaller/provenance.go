package installer

import (
	"encoding/json"
	"fmt"
	"io"
)

const (
	QdrantVersion = "1.18.3"
	QdrantSize    = int64(30_745_357)
	QdrantSHA256  = "b4faedcdf8c9577bf1c8f2ab9b454636b87e056c116c99d49bd4f9fb2e634285"
	ModelRevision = "0e60b8d9d2166d80387f86e3b48ec9ced55f4d15"
)

type ArtifactEvidence struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Size    int64  `json:"size"`
	SHA256  string `json:"sha256"`
}

type ModelFileEvidence struct {
	Path   string `json:"path"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}

type ModelEvidence struct {
	Repository string              `json:"repository"`
	Revision   string              `json:"revision"`
	Files      []ModelFileEvidence `json:"files"`
}

type Provenance struct {
	SchemaVersion int              `json:"schema_version"`
	Qdrant        ArtifactEvidence `json:"qdrant"`
	Model         ModelEvidence    `json:"model"`
	AdapterBundle ArtifactEvidence `json:"adapter_bundle"`
}

var expectedModelFiles = map[string]ModelFileEvidence{
	"onnx/model.onnx": {
		Path: "onnx/model.onnx", Size: 470_268_510,
		SHA256: "ca456c06b3a9505ddfd9131408916dd79290368331e7d76bb621f1cba6bc8665",
	},
	"tokenizer.json": {
		Path: "tokenizer.json", Size: 17_082_730,
		SHA256: "0b44a9d7b51c3c62626640cda0e2c2f70fdacdc25bbbd68038369d14ebdf4c39",
	},
	"config.json": {
		Path: "config.json", Size: 655,
		SHA256: "69137736cab8b8903a07fe8afaafdda25aac55415a12a55d1bffa9f581abf959",
	},
	"tokenizer_config.json": {
		Path: "tokenizer_config.json", Size: 443,
		SHA256: "a1d6bc8734a6f635dc158508bef000f8e2e5a759c7d92f984b2c86e5ff53425b",
	},
	"special_tokens_map.json": {
		Path: "special_tokens_map.json", Size: 167,
		SHA256: "d05497f1da52c5e09554c0cd874037a083e1dc1b9cfd48034d1c717f1afc07a7",
	},
}

func LoadProvenance(path string) (Provenance, error) {
	file, err := openRegularNoFollow(path)
	if err != nil {
		return Provenance{}, fmt.Errorf("open provenance: %w", err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || info.Size() <= 0 || info.Size() > 64*1024 {
		return Provenance{}, fmt.Errorf("provenance size is invalid")
	}
	decoder := json.NewDecoder(file)
	decoder.DisallowUnknownFields()
	var value Provenance
	if err := decoder.Decode(&value); err != nil {
		return Provenance{}, fmt.Errorf("decode provenance: %w", err)
	}
	if err := requireJSONEOF(decoder); err != nil {
		return Provenance{}, err
	}
	if err := value.Validate(); err != nil {
		return Provenance{}, err
	}
	return value, nil
}

func (p Provenance) Validate() error {
	if p.SchemaVersion != 1 {
		return fmt.Errorf("unsupported provenance schema")
	}
	if p.Qdrant != (ArtifactEvidence{
		Name:    "qdrant-x86_64-unknown-linux-musl.tar.gz",
		Version: QdrantVersion,
		Size:    QdrantSize,
		SHA256:  QdrantSHA256,
	}) {
		return fmt.Errorf("qdrant provenance mismatch")
	}
	if p.Model.Repository != "intfloat/multilingual-e5-small" || p.Model.Revision != ModelRevision || len(p.Model.Files) != len(expectedModelFiles) {
		return fmt.Errorf("model provenance mismatch")
	}
	seen := make(map[string]bool, len(p.Model.Files))
	for _, file := range p.Model.Files {
		expected, ok := expectedModelFiles[file.Path]
		if !ok || seen[file.Path] || file != expected {
			return fmt.Errorf("model file provenance mismatch")
		}
		seen[file.Path] = true
	}
	if p.AdapterBundle.Name != "dirextalk-knowledge-adapter.tar.gz" || p.AdapterBundle.Size <= 0 || !isSHA256(p.AdapterBundle.SHA256) || p.AdapterBundle.SHA256 == zeroSHA256 {
		return fmt.Errorf("adapter provenance mismatch")
	}
	if p.AdapterBundle.Version == "" || len(p.AdapterBundle.Version) > 64 {
		return fmt.Errorf("adapter version mismatch")
	}
	return nil
}

func requireJSONEOF(decoder *json.Decoder) error {
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return fmt.Errorf("provenance contains trailing data")
	}
	return nil
}

const zeroSHA256 = "0000000000000000000000000000000000000000000000000000000000000000"

func isSHA256(value string) bool {
	if len(value) != 64 {
		return false
	}
	for _, character := range value {
		if !(character >= '0' && character <= '9') && !(character >= 'a' && character <= 'f') {
			return false
		}
	}
	return true
}
