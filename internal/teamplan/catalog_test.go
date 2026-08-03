package teamplan

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestParseRuntimeCatalogJSONVerifiesSignedQualificationEvidence(t *testing.T) {
	t.Parallel()
	publicKey, privateKey := runtimeCatalogTestKey()
	payload := validRuntimeCatalogPayload(publicKey)
	raw := signRuntimeCatalog(t, payload, privateKey)

	catalog, err := ParseRuntimeCatalogJSON(raw, publicKey)
	if err != nil {
		t.Fatalf("ParseRuntimeCatalogJSON() error = %v", err)
	}
	if catalog.SignerKeyID() != RuntimeCatalogSignerKeyID(publicKey) ||
		!strings.HasPrefix(catalog.Revision(), "sha256:") ||
		catalog.GeneratedAt() != payload.GeneratedAt ||
		len(catalog.QualifiedReleases()) != len(payload.Releases) {
		t.Fatalf("catalog metadata = %#v", catalog)
	}
	releases := catalog.Releases()
	if len(releases) != len(payload.Releases) ||
		!slicesAreSortedReleases(releases) {
		t.Fatalf("catalog releases = %+v", releases)
	}
	evidence, found := catalog.Evidence(releases[0].ReleaseID)
	if !found || evidence.SBOMDigest == "" || evidence.ContractTestDigest == "" {
		t.Fatalf("qualification evidence = %+v, %v", evidence, found)
	}
	releases[0].Capabilities[0] = CapabilityBrowser
	if catalog.Releases()[0].Capabilities[0] == CapabilityBrowser {
		t.Fatal("catalog Releases() exposed mutable internal slices")
	}

	request := validCompileRequest()
	request.RuntimeReleases = catalog.QualifiedReleases()
	request.CatalogRevision = catalog.Revision()
	if _, err := Compile(request); err != nil {
		t.Fatalf("Compile(signed catalog) error = %v", err)
	}
	if _, found := catalog.LaunchEvidence(releases[0].ReleaseID); found {
		t.Fatal("V1 catalog exposed unsigned runtime launch evidence")
	}
}

func TestRuntimeCatalogV2BindsWorkerInstallationAndExecutable(t *testing.T) {
	t.Parallel()
	publicKey, privateKey := runtimeCatalogTestKey()
	payload := validRuntimeCatalogV2Payload(publicKey)
	catalog, err := ParseRuntimeCatalogJSON(
		signRuntimeCatalog(t, payload, privateKey),
		publicKey,
	)
	if err != nil {
		t.Fatalf("ParseRuntimeCatalogJSON(V2) error = %v", err)
	}
	release := catalog.QualifiedReleases()[0]
	evidence, found := catalog.LaunchEvidence(release.ReleaseID)
	if !found ||
		evidence.InstallationManifestDigest !=
			payload.Releases[0].Launch.InstallationManifestDigest ||
		evidence.ExecutableDigest !=
			payload.Releases[0].Launch.ExecutableDigest ||
		catalog.SchemaVersion() != RuntimeCatalogSchemaV2 {
		t.Fatalf("V2 launch evidence = %+v, %v", evidence, found)
	}
	compiler, err := NewCatalogCompiler(catalog)
	if err != nil {
		t.Fatal(err)
	}
	resolved, err := compiler.ResolveRuntimeLaunchEvidence(
		release.ReleaseID,
	)
	if err != nil || resolved != evidence {
		t.Fatalf("compiler launch evidence = %+v, %v", resolved, err)
	}

	missing := validRuntimeCatalogV2Payload(publicKey)
	missing.Releases[0].Launch = nil
	if _, err := ParseRuntimeCatalogJSON(
		marshalRuntimeCatalogWithDummySignature(t, missing),
		publicKey,
	); !errors.Is(err, ErrInvalid) {
		t.Fatalf("missing V2 launch evidence error = %v", err)
	}

	legacy := validRuntimeCatalogPayload(publicKey)
	legacy.Releases[0].Launch = payload.Releases[0].Launch
	if _, err := ParseRuntimeCatalogJSON(
		marshalRuntimeCatalogWithDummySignature(t, legacy),
		publicKey,
	); !errors.Is(err, ErrInvalid) {
		t.Fatalf("V1 launch extension error = %v", err)
	}
}

func TestSignRuntimeCatalogV2ProducesSelfVerifyingCanonicalDocument(
	t *testing.T,
) {
	t.Parallel()
	publicKey, privateKey := runtimeCatalogTestKey()
	payload := validRuntimeCatalogV2Payload(publicKey)
	_, releases, err := normalizeRuntimeCatalogPayload(payload)
	if err != nil {
		t.Fatal(err)
	}
	specifications := make(
		[]RuntimeCatalogReleaseSpec,
		0,
		len(releases),
	)
	for _, release := range releases {
		specifications = append(
			specifications,
			RuntimeCatalogReleaseSpec{
				Runtime:       release.Runtime,
				Qualification: release.Qualification,
				Launch:        release.Launch,
			},
		)
	}
	raw, encodedPublicKey, err := SignRuntimeCatalogV2(
		payload.GeneratedAt,
		specifications,
		privateKey,
	)
	if err != nil {
		t.Fatalf("SignRuntimeCatalogV2() error = %v", err)
	}
	if string(encodedPublicKey) !=
		base64.RawURLEncoding.EncodeToString(publicKey) {
		t.Fatal("SignRuntimeCatalogV2() returned a different public key")
	}
	catalog, err := ParseRuntimeCatalogJSON(raw, publicKey)
	if err != nil {
		t.Fatalf("signed catalog parse error = %v", err)
	}
	if catalog.SchemaVersion() != RuntimeCatalogSchemaV2 ||
		catalog.SignerKeyID() != RuntimeCatalogSignerKeyID(publicKey) ||
		len(catalog.QualifiedReleases()) != len(specifications) {
		t.Fatalf("signed catalog = %#v", catalog)
	}

	malformed := append(ed25519.PrivateKey(nil), privateKey...)
	malformed[len(malformed)-1] ^= 0xff
	if _, _, err := SignRuntimeCatalogV2(
		payload.GeneratedAt,
		specifications,
		malformed,
	); !errors.Is(err, ErrInvalid) {
		t.Fatalf("malformed private key error = %v", err)
	}
	clear(malformed)
}

func TestParseRuntimeCatalogJSONRejectsTamperUnknownFieldsAndWrongKey(t *testing.T) {
	t.Parallel()
	publicKey, privateKey := runtimeCatalogTestKey()
	raw := signRuntimeCatalog(t, validRuntimeCatalogPayload(publicKey), privateKey)

	var document signedRuntimeCatalogDocument
	if err := json.Unmarshal(raw, &document); err != nil {
		t.Fatal(err)
	}
	document.Payload.Releases[0].ImageDigest = "sha256:" + strings.Repeat("f", 64)
	tampered, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseRuntimeCatalogJSON(tampered, publicKey); !errors.Is(err, ErrInvalid) {
		t.Fatalf("tampered catalog error = %v, want ErrInvalid", err)
	}

	var generic map[string]any
	if err := json.Unmarshal(raw, &generic); err != nil {
		t.Fatal(err)
	}
	generic["unreviewed"] = true
	unknown, err := json.Marshal(generic)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseRuntimeCatalogJSON(unknown, publicKey); !errors.Is(err, ErrInvalid) {
		t.Fatalf("unknown-field catalog error = %v, want ErrInvalid", err)
	}

	wrongSeed := sha256.Sum256([]byte("different runtime catalog test key"))
	wrongPrivate := ed25519.NewKeyFromSeed(wrongSeed[:])
	wrongPublic := wrongPrivate.Public().(ed25519.PublicKey)
	if _, err := ParseRuntimeCatalogJSON(raw, wrongPublic); !errors.Is(err, ErrInvalid) {
		t.Fatalf("wrong-key catalog error = %v, want ErrInvalid", err)
	}
}

func TestRuntimeCatalogQualificationAndActiveReleaseRules(t *testing.T) {
	t.Parallel()
	publicKey, privateKey := runtimeCatalogTestKey()

	t.Run("qualified requires evidence", func(t *testing.T) {
		payload := validRuntimeCatalogPayload(publicKey)
		payload.Releases[0].Qualification = nil
		raw := marshalRuntimeCatalogWithDummySignature(t, payload)
		if _, err := ParseRuntimeCatalogJSON(raw, publicKey); !errors.Is(err, ErrInvalid) {
			t.Fatalf("missing evidence error = %v, want ErrInvalid", err)
		}
	})

	t.Run("one qualified release per family and architecture", func(t *testing.T) {
		payload := validRuntimeCatalogPayload(publicKey)
		duplicate := payload.Releases[0]
		duplicate.ReleaseID = "40000000-0000-4000-8000-000000000099"
		duplicate.Version = "0.2.0"
		duplicate.ImageDigest = "sha256:" + strings.Repeat("9", 64)
		duplicate.Qualification = validQualification(
			"50000000-0000-4000-8000-000000000099",
		)
		payload.Releases = append(payload.Releases, duplicate)
		raw := marshalRuntimeCatalogWithDummySignature(t, payload)
		if _, err := ParseRuntimeCatalogJSON(raw, publicKey); !errors.Is(err, ErrInvalid) {
			t.Fatalf("duplicate active release error = %v, want ErrInvalid", err)
		}
	})

	t.Run("candidate may be retained but is not selectable", func(t *testing.T) {
		payload := validRuntimeCatalogPayload(publicKey)
		payload.Releases[0].Trust = RuntimeTrustCandidate
		payload.Releases[0].Qualification = nil
		raw := signRuntimeCatalog(t, payload, privateKey)
		catalog, err := ParseRuntimeCatalogJSON(raw, publicKey)
		if err != nil {
			t.Fatalf("candidate catalog error = %v", err)
		}
		if len(catalog.Releases()) != len(payload.Releases) ||
			len(catalog.QualifiedReleases()) != len(payload.Releases)-1 {
			t.Fatalf(
				"catalog release counts = %d/%d, want %d/%d",
				len(catalog.Releases()),
				len(catalog.QualifiedReleases()),
				len(payload.Releases),
				len(payload.Releases)-1,
			)
		}
	})

	t.Run("floating versions remain forbidden", func(t *testing.T) {
		payload := validRuntimeCatalogPayload(publicKey)
		payload.Releases[0].Version = "latest"
		raw := marshalRuntimeCatalogWithDummySignature(t, payload)
		if _, err := ParseRuntimeCatalogJSON(raw, publicKey); !errors.Is(err, ErrInvalid) {
			t.Fatalf("floating release error = %v, want ErrInvalid", err)
		}
	})
}

func TestLoadRuntimeCatalogRequiresProtectedRegularFiles(t *testing.T) {
	t.Parallel()
	publicKey, privateKey := runtimeCatalogTestKey()
	raw := signRuntimeCatalog(t, validRuntimeCatalogPayload(publicKey), privateKey)
	directory := t.TempDir()
	catalogPath := filepath.Join(directory, "runtime-catalog.json")
	keyPath := filepath.Join(directory, "runtime-catalog-public-key")
	if err := os.WriteFile(catalogPath, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(
		keyPath,
		[]byte(base64.RawURLEncoding.EncodeToString(publicKey)),
		0o600,
	); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadRuntimeCatalog(catalogPath, keyPath); err != nil {
		t.Fatalf("LoadRuntimeCatalog() error = %v", err)
	}

	symlink := filepath.Join(directory, "catalog-link")
	if err := os.Symlink(catalogPath, symlink); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadRuntimeCatalog(symlink, keyPath); !errors.Is(err, ErrInvalid) {
		t.Fatalf("symlink catalog error = %v, want ErrInvalid", err)
	}
	if err := os.Chmod(catalogPath, 0o666); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadRuntimeCatalog(catalogPath, keyPath); !errors.Is(err, ErrInvalid) {
		t.Fatalf("writable catalog error = %v, want ErrInvalid", err)
	}
}

func validRuntimeCatalogPayload(publicKey ed25519.PublicKey) runtimeCatalogPayload {
	qualifiedAt := time.Date(2026, 7, 29, 8, 0, 0, 0, time.UTC)
	releases := validRuntimeReleases(qualifiedAt)
	documents := make([]runtimeCatalogReleaseDocument, 0, len(releases))
	for index, release := range releases {
		documents = append(documents, runtimeCatalogReleaseDocument{
			ReleaseID:        release.ReleaseID,
			Family:           release.Family,
			Version:          release.Version,
			SourceURL:        release.SourceURL,
			SourceCommit:     release.SourceCommit,
			License:          release.License,
			ImageDigest:      release.ImageDigest,
			Adapter:          release.Adapter,
			Capabilities:     append([]Capability(nil), release.Capabilities...),
			ModelInterfaces:  append([]ModelInterface(nil), release.ModelInterfaces...),
			Suitability:      append([]Suitability(nil), release.Suitability...),
			Minimum:          release.Minimum,
			Recommended:      release.Recommended,
			ColdStartSeconds: uint64(release.ColdStart / time.Second),
			Trust:            release.Trust,
			QualifiedAt:      release.QualifiedAt,
			Qualification: validQualification(
				"50000000-0000-4000-8000-" +
					leftPadDecimal(index+1, 12),
			),
		})
	}
	return runtimeCatalogPayload{
		SchemaVersion: RuntimeCatalogSchemaV1,
		SignerKeyID:   RuntimeCatalogSignerKeyID(publicKey),
		GeneratedAt:   qualifiedAt.Add(time.Minute),
		Releases:      documents,
	}
}

func validRuntimeCatalogV2Payload(
	publicKey ed25519.PublicKey,
) runtimeCatalogPayload {
	payload := validRuntimeCatalogPayload(publicKey)
	payload.SchemaVersion = RuntimeCatalogSchemaV2
	for index := range payload.Releases {
		installationFill := "8"
		executableFill := "9"
		if index%2 == 1 {
			installationFill = "a"
			executableFill = "b"
		}
		payload.Releases[index].Launch = &RuntimeLaunchEvidence{
			InstallationManifestDigest: "sha256:" +
				strings.Repeat(installationFill, 64),
			ExecutableDigest: "sha256:" +
				strings.Repeat(executableFill, 64),
		}
	}
	return payload
}

func validQualification(id string) *QualificationEvidence {
	return &QualificationEvidence{
		QualificationID:         id,
		SBOMDigest:              "sha256:" + strings.Repeat("3", 64),
		ProvenanceDigest:        "sha256:" + strings.Repeat("4", 64),
		VulnerabilityScanDigest: "sha256:" + strings.Repeat("5", 64),
		ContractTestDigest:      "sha256:" + strings.Repeat("6", 64),
		LicenseDecisionDigest:   "sha256:" + strings.Repeat("7", 64),
	}
}

func runtimeCatalogTestKey() (ed25519.PublicKey, ed25519.PrivateKey) {
	seed := sha256.Sum256([]byte("dirextalk teamplan runtime catalog test key"))
	privateKey := ed25519.NewKeyFromSeed(seed[:])
	return privateKey.Public().(ed25519.PublicKey), privateKey
}

func signRuntimeCatalog(
	t *testing.T,
	payload runtimeCatalogPayload,
	privateKey ed25519.PrivateKey,
) []byte {
	t.Helper()
	canonical, err := canonicalRuntimeCatalogPayload(payload)
	if err != nil {
		t.Fatalf("canonicalRuntimeCatalogPayload() error = %v", err)
	}
	document := signedRuntimeCatalogDocument{
		Payload: payload,
		SignatureBase64URL: base64.RawURLEncoding.EncodeToString(
			ed25519.Sign(privateKey, canonical),
		),
	}
	raw, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func marshalRuntimeCatalogWithDummySignature(
	t *testing.T,
	payload runtimeCatalogPayload,
) []byte {
	t.Helper()
	document := signedRuntimeCatalogDocument{
		Payload: payload,
		SignatureBase64URL: base64.RawURLEncoding.EncodeToString(
			make([]byte, ed25519.SignatureSize),
		),
	}
	raw, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func leftPadDecimal(value, width int) string {
	text := strings.Repeat("0", width) + fmt.Sprint(value)
	return text[len(text)-width:]
}

func slicesAreSortedReleases(values []RuntimeRelease) bool {
	for index := 1; index < len(values); index++ {
		if values[index-1].ReleaseID > values[index].ReleaseID {
			return false
		}
	}
	return true
}
