package workerimage

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"io"
	"strings"
)

// Public release entries are added only after publisher-owned live image
// qualification. An Agent release pins its catalog; customer accounts never
// need a publisher SSM share or access to the publisher's private AMI tags.
//
//go:embed public-releases.json
var publishedCatalog []byte

func PublishedReference(region string, flavor Flavor) (Reference, error) {
	return catalogReference(publishedCatalog, region, flavor)
}

func catalogReference(data []byte, region string, flavor Flavor) (Reference, error) {
	var catalog struct {
		Schema             string                          `json:"schema"`
		PublisherAccountID string                          `json:"publisher_account_id"`
		Regions            map[string]map[Flavor]Reference `json:"regions"`
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&catalog) != nil || decoder.Decode(new(any)) != io.EOF ||
		catalog.Schema != "dirextalk.worker-image-catalog/v1" || catalog.PublisherAccountID != PublisherAccountID ||
		!ValidFlavor(flavor) || strings.TrimSpace(region) == "" || strings.TrimSpace(region) != region {
		return Reference{}, ContractError{Kind: FailureIncompatible, Flavor: flavor}
	}
	reference, ok := catalog.Regions[region][flavor]
	if !ok {
		return Reference{}, ContractError{Kind: FailureMissing, Flavor: flavor}
	}
	reference.Flavor, reference.OwnerID = flavor, catalog.PublisherAccountID
	if err := ValidateReference(reference); err != nil {
		return Reference{}, err
	}
	return reference, nil
}
