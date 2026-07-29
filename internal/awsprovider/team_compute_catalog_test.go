package awsprovider

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/YingSuiAI/dirextalk-agent/internal/recipe"
)

func TestTeamComputeCatalogNormalizesAndCopiesConfiguration(t *testing.T) {
	t.Parallel()
	document := validTeamComputeCatalogDocument()
	document.Regions[0].AvailabilityZones = []string{
		"us-east-1c",
		"us-east-1a",
	}
	document.Regions[0].Shapes = []TeamComputeShape{
		{
			InstanceType: "m7i.large",
			Architecture: recipe.ArchitectureAMD64,
			DiskGiB:      40,
		},
		{
			InstanceType: "c7g.large",
			Architecture: recipe.ArchitectureARM64,
			DiskGiB:      32,
		},
	}
	catalog, err := NewTeamComputeCatalog(document)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(catalog.Regions(), []string{"us-east-1"}) {
		t.Fatalf("Regions() = %#v", catalog.Regions())
	}
	zones, shapes, err := catalog.Resolve("us-east-1")
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(zones, []string{"us-east-1a", "us-east-1c"}) ||
		len(shapes) != 2 ||
		shapes[0].InstanceType != "c7g.large" ||
		shapes[1].InstanceType != "m7i.large" {
		t.Fatalf("resolved zones=%#v shapes=%#v", zones, shapes)
	}
	zones[0] = "changed"
	shapes[0].InstanceType = "changed"
	freshZones, freshShapes, err := catalog.Resolve("us-east-1")
	if err != nil ||
		freshZones[0] != "us-east-1a" ||
		freshShapes[0].InstanceType != "c7g.large" {
		t.Fatalf(
			"catalog aliases caller memory zones=%#v shapes=%#v error=%v",
			freshZones,
			freshShapes,
			err,
		)
	}
}

func TestTeamComputeCatalogConfigurationBindingTracksMeaningfulDrift(
	t *testing.T,
) {
	t.Parallel()
	leftDocument := validTeamComputeCatalogDocument()
	leftDocument.Regions[0].AvailabilityZones = []string{
		"us-east-1b",
		"us-east-1a",
	}
	leftDocument.Regions[0].Shapes = append(
		leftDocument.Regions[0].Shapes,
		TeamComputeShape{
			InstanceType: "c7g.large",
			Architecture: recipe.ArchitectureARM64,
			DiskGiB:      32,
		},
	)
	rightDocument := validTeamComputeCatalogDocument()
	rightDocument.Regions[0].Shapes = []TeamComputeShape{
		leftDocument.Regions[0].Shapes[1],
		leftDocument.Regions[0].Shapes[0],
	}
	left, err := NewTeamComputeCatalog(leftDocument)
	if err != nil {
		t.Fatal(err)
	}
	right, err := NewTeamComputeCatalog(rightDocument)
	if err != nil {
		t.Fatal(err)
	}
	leftSourceID, leftDigest, err := left.ConfigurationBinding("us-east-1")
	if err != nil {
		t.Fatal(err)
	}
	rightSourceID, rightDigest, err := right.ConfigurationBinding("us-east-1")
	if err != nil {
		t.Fatal(err)
	}
	if leftSourceID != rightSourceID || leftDigest != rightDigest {
		t.Fatalf(
			"equivalent configuration binding differs: %q/%q %q/%q",
			leftSourceID,
			leftDigest,
			rightSourceID,
			rightDigest,
		)
	}

	changedDocument := rightDocument
	changedDocument.Regions[0].AvailabilityZones = append(
		changedDocument.Regions[0].AvailabilityZones,
		"us-east-1c",
	)
	changed, err := NewTeamComputeCatalog(changedDocument)
	if err != nil {
		t.Fatal(err)
	}
	changedSourceID, changedDigest, err :=
		changed.ConfigurationBinding("us-east-1")
	if err != nil {
		t.Fatal(err)
	}
	if changedSourceID != leftSourceID || changedDigest == leftDigest {
		t.Fatalf(
			"meaningful drift binding = %q/%q, want source %q and new digest",
			changedSourceID,
			changedDigest,
			leftSourceID,
		)
	}
}

func TestTeamComputeCatalogRejectsUntrustedConfiguration(t *testing.T) {
	t.Parallel()
	tests := map[string]func(*TeamComputeCatalogDocument){
		"schema": func(value *TeamComputeCatalogDocument) {
			value.SchemaVersion = "other"
		},
		"duplicate region": func(value *TeamComputeCatalogDocument) {
			value.Regions = append(value.Regions, value.Regions[0])
		},
		"zone outside region": func(value *TeamComputeCatalogDocument) {
			value.Regions[0].AvailabilityZones[0] = "us-west-2a"
		},
		"duplicate zone": func(value *TeamComputeCatalogDocument) {
			value.Regions[0].AvailabilityZones = []string{
				"us-east-1a",
				"us-east-1a",
			}
		},
		"duplicate shape": func(value *TeamComputeCatalogDocument) {
			value.Regions[0].Shapes = append(
				value.Regions[0].Shapes,
				value.Regions[0].Shapes[0],
			)
		},
		"floating injection": func(value *TeamComputeCatalogDocument) {
			value.Regions[0].Shapes[0].InstanceType =
				"m7i.large;RunInstances"
		},
		"invalid disk": func(value *TeamComputeCatalogDocument) {
			value.Regions[0].Shapes[0].DiskGiB = 0
		},
	}
	for name, mutate := range tests {
		name, mutate := name, mutate
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			document := validTeamComputeCatalogDocument()
			mutate(&document)
			if _, err := NewTeamComputeCatalog(
				document,
			); !errors.Is(err, ErrInvalidTeamComputePricing) {
				t.Fatalf(
					"NewTeamComputeCatalog() error=%v, want invalid",
					err,
				)
			}
		})
	}
}

func TestLoadTeamComputeCatalogIsStrictAndProtected(t *testing.T) {
	t.Parallel()
	directory := t.TempDir()
	raw, err := json.Marshal(validTeamComputeCatalogDocument())
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "catalog.json")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadTeamComputeCatalog(path); err != nil {
		t.Fatalf("LoadTeamComputeCatalog() error=%v", err)
	}

	unknown := filepath.Join(directory, "unknown.json")
	unknownRaw := append(
		append([]byte(nil), raw[:len(raw)-1]...),
		[]byte(`,"unexpected":true}`)...,
	)
	if err := os.WriteFile(unknown, unknownRaw, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadTeamComputeCatalog(
		unknown,
	); !errors.Is(err, ErrInvalidTeamComputePricing) {
		t.Fatalf("unknown field error=%v", err)
	}

	loose := filepath.Join(directory, "loose.json")
	if err := os.WriteFile(loose, raw, 0o666); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(loose, 0o666); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadTeamComputeCatalog(
		loose,
	); !errors.Is(err, ErrInvalidTeamComputePricing) {
		t.Fatalf("loose permission error=%v", err)
	}

	linked := filepath.Join(directory, "linked.json")
	if err := os.Symlink(path, linked); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadTeamComputeCatalog(
		linked,
	); !errors.Is(err, ErrInvalidTeamComputePricing) {
		t.Fatalf("symlink error=%v", err)
	}
}

func validTeamComputeCatalogDocument() TeamComputeCatalogDocument {
	return TeamComputeCatalogDocument{
		SchemaVersion: TeamComputeCatalogSchemaV1,
		Regions: []TeamComputeRegion{{
			Region: "us-east-1",
			AvailabilityZones: []string{
				"us-east-1a",
				"us-east-1b",
			},
			Shapes: []TeamComputeShape{{
				InstanceType: "m7i.large",
				Architecture: recipe.ArchitectureAMD64,
				DiskGiB:      40,
			}},
		}},
	}
}
