package knowledge

import "sort"

const LocalMultilingualE5SmallProfileID = "local-multilingual-e5-small-v1"

type Catalog struct {
	profiles map[string]struct{}
}

func DefaultCatalog() Catalog {
	return Catalog{profiles: map[string]struct{}{LocalMultilingualE5SmallProfileID: {}}}
}

func (catalog Catalog) Contains(profileID string) bool {
	_, ok := catalog.profiles[profileID]
	return ok
}

func (catalog Catalog) IDs() []string {
	result := make([]string, 0, len(catalog.profiles))
	for profileID := range catalog.profiles {
		result = append(result, profileID)
	}
	sort.Strings(result)
	return result
}
