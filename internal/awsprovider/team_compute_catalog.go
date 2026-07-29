package awsprovider

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"slices"
	"strings"
	"syscall"

	"github.com/YingSuiAI/dirextalk-agent/internal/security"
)

const (
	TeamComputeCatalogSchemaV1 = "dirextalk.agent.aws-team-compute-catalog/v1"
	maximumTeamComputeCatalog  = int64(1 << 20)
	maximumTeamComputeRegions  = 32
)

type TeamComputeRegion struct {
	Region            string             `json:"region"`
	AvailabilityZones []string           `json:"availability_zones"`
	Shapes            []TeamComputeShape `json:"shapes"`
}

type TeamComputeCatalogDocument struct {
	SchemaVersion string              `json:"schema_version"`
	Regions       []TeamComputeRegion `json:"regions"`
}

// TeamComputeCatalog is immutable operator-owned metadata. It is an allowlist,
// not pricing evidence; fresh AWS reads still determine price and capacity.
type TeamComputeCatalog struct {
	regions map[string]TeamComputeRegion
}

func LoadTeamComputeCatalog(path string) (*TeamComputeCatalog, error) {
	raw, err := readProtectedTeamComputeCatalog(path)
	if err != nil {
		return nil, err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var document TeamComputeCatalogDocument
	if err := decoder.Decode(&document); err != nil {
		return nil, ErrInvalidTeamComputePricing
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return nil, ErrInvalidTeamComputePricing
	}
	return NewTeamComputeCatalog(document)
}

func NewTeamComputeCatalog(
	document TeamComputeCatalogDocument,
) (*TeamComputeCatalog, error) {
	if document.SchemaVersion != TeamComputeCatalogSchemaV1 ||
		len(document.Regions) == 0 ||
		len(document.Regions) > maximumTeamComputeRegions {
		return nil, ErrInvalidTeamComputePricing
	}
	result := &TeamComputeCatalog{
		regions: make(map[string]TeamComputeRegion, len(document.Regions)),
	}
	for _, configured := range document.Regions {
		region, zones, shapes, err := normalizeTeamComputeRegion(
			configured.Region,
			configured.AvailabilityZones,
			configured.Shapes,
		)
		if err != nil {
			return nil, err
		}
		if _, duplicate := result.regions[region]; duplicate {
			return nil, ErrInvalidTeamComputePricing
		}
		for _, value := range append(
			append([]string{region}, zones...),
			teamComputeShapeStrings(shapes)...,
		) {
			if security.ContainsLikelySecret(value) {
				return nil, ErrInvalidTeamComputePricing
			}
		}
		result.regions[region] = TeamComputeRegion{
			Region:            region,
			AvailabilityZones: zones,
			Shapes:            shapes,
		}
	}
	return result, nil
}

func (catalog *TeamComputeCatalog) Resolve(
	region string,
) ([]string, []TeamComputeShape, error) {
	if catalog == nil || strings.TrimSpace(region) != region {
		return nil, nil, ErrInvalidTeamComputePricing
	}
	configured, ok := catalog.regions[region]
	if !ok {
		return nil, nil, ErrInvalidTeamComputePricing
	}
	return append([]string(nil), configured.AvailabilityZones...),
		append([]TeamComputeShape(nil), configured.Shapes...),
		nil
}

func (catalog *TeamComputeCatalog) Regions() []string {
	if catalog == nil {
		return nil
	}
	result := make([]string, 0, len(catalog.regions))
	for region := range catalog.regions {
		result = append(result, region)
	}
	slices.Sort(result)
	return result
}

func (catalog *TeamComputeCatalog) ConfigurationBinding(
	region string,
) (string, string, error) {
	zones, shapes, err := catalog.Resolve(region)
	if err != nil {
		return "", "", err
	}
	binding, err := newTeamComputeConfigurationBinding(
		region,
		zones,
		shapes,
	)
	if err != nil {
		return "", "", err
	}
	return binding.SourceID, binding.Digest, nil
}

func teamComputeShapeStrings(shapes []TeamComputeShape) []string {
	result := make([]string, 0, len(shapes)*2)
	for _, shape := range shapes {
		result = append(
			result,
			shape.InstanceType,
			string(shape.Architecture),
		)
	}
	return result
}

func readProtectedTeamComputeCatalog(path string) ([]byte, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil, ErrInvalidTeamComputePricing
	}
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, ErrInvalidTeamComputePricing
	}
	defer file.Close()

	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() ||
		info.Mode().Perm()&0o022 != 0 ||
		info.Size() <= 0 ||
		info.Size() > maximumTeamComputeCatalog {
		return nil, ErrInvalidTeamComputePricing
	}
	raw, err := io.ReadAll(
		io.LimitReader(file, maximumTeamComputeCatalog+1),
	)
	if err != nil || int64(len(raw)) != info.Size() {
		return nil, ErrInvalidTeamComputePricing
	}
	return raw, nil
}
