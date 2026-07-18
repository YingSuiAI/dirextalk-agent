package artifactorigin

import (
	"bytes"
	"encoding/json"
	"io"
	"net/url"
	"strings"

	assets "github.com/YingSuiAI/dirextalk-agent/deploy/awsartifactorigin"
)

const maxCatalogBytes = 128 << 10

func ParseCatalog(raw []byte) (Catalog, error) {
	if len(raw) == 0 || len(raw) > maxCatalogBytes {
		return Catalog{}, ErrInvalid
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var catalog Catalog
	if err := decoder.Decode(&catalog); err != nil {
		return Catalog{}, ErrInvalid
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return Catalog{}, ErrInvalid
	}
	if catalog.SchemaVersion != CatalogSchemaV1 || len(catalog.Artifacts) == 0 || len(catalog.Artifacts) > 64 {
		return Catalog{}, ErrInvalid
	}
	ids := make(map[string]struct{}, len(catalog.Artifacts))
	keys := make(map[string]struct{}, len(catalog.Artifacts))
	for _, artifact := range catalog.Artifacts {
		if err := artifact.Validate(); err != nil {
			return Catalog{}, err
		}
		key := artifact.ObjectKey()
		if _, duplicate := ids[artifact.ID]; duplicate {
			return Catalog{}, ErrInvalid
		}
		if _, duplicate := keys[key]; duplicate {
			return Catalog{}, ErrInvalid
		}
		ids[artifact.ID], keys[key] = struct{}{}, struct{}{}
	}
	return catalog, nil
}

func PinnedKnowledgeArtifact(id string) (Artifact, error) {
	catalog, err := ParseCatalog(assets.KnowledgeCatalog())
	if err != nil {
		return Artifact{}, err
	}
	artifact, ok := catalog.Lookup(id)
	if !ok {
		return Artifact{}, ErrInvalid
	}
	return artifact, nil
}

func (catalog Catalog) Lookup(id string) (Artifact, bool) {
	for _, artifact := range catalog.Artifacts {
		if artifact.ID == id {
			return artifact, true
		}
	}
	return Artifact{}, false
}

func (artifact Artifact) Validate() error {
	parsed, err := url.Parse(artifact.SourceURL)
	if !artifactIDPattern.MatchString(artifact.ID) || !artifactNamePattern.MatchString(artifact.Name) ||
		!sha256Pattern.MatchString(artifact.SHA256) || artifact.SizeBytes <= 0 || artifact.SizeBytes > 1<<40 ||
		!mediaTypePattern.MatchString(artifact.MediaType) || !licensePattern.MatchString(artifact.License) ||
		err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || len(artifact.SourceURL) > 1024 ||
		strings.TrimSpace(artifact.SourceRevision) != artifact.SourceRevision || artifact.SourceRevision == "" || len(artifact.SourceRevision) > 128 ||
		strings.EqualFold(artifact.SourceRevision, "latest") || strings.ContainsAny(artifact.SourceRevision, "\r\n\x00") {
		return ErrInvalid
	}
	return nil
}

func (artifact Artifact) ObjectKey() string {
	return "sha256/" + artifact.SHA256 + "/" + artifact.Name
}
