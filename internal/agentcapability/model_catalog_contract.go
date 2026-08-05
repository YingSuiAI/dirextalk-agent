package agentcapability

import (
	"encoding/json"
	"sort"
	"strings"
)

var modelCatalogOutputModalityValues = []string{"audio", "embedding", "image", "text", "video"}

// ModelCatalogOutputModalitiesJSON is derived from the canonical enum source
// and shared by provider projection tests and the Capability result schema.
var ModelCatalogOutputModalitiesJSON = func() string {
	encoded, _ := json.Marshal(modelCatalogOutputModalityValues)
	return string(encoded)
}()

var modelCatalogOutputModalitySet = func() map[string]struct{} {
	result := make(map[string]struct{}, len(modelCatalogOutputModalityValues))
	for _, value := range modelCatalogOutputModalityValues {
		result[value] = struct{}{}
	}
	return result
}()

// CanonicalModelCatalogOutputModalities keeps only the closed, non-sensitive
// output modality enum.  Unknown provider values are intentionally omitted so
// secret-like canaries cannot be reflected into the public model projection.
func CanonicalModelCatalogOutputModalities(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	result := make([]string, 0, len(values))
	for _, value := range values {
		value = normalizeModelCatalogOutputModality(value)
		if _, ok := modelCatalogOutputModalitySet[value]; !ok {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}

func normalizeModelCatalogOutputModality(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	if value == "embeddings" {
		return "embedding"
	}
	return value
}
