package postgres

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"sort"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/coreconfirmation"
	"github.com/YingSuiAI/dirextalk-agent/internal/coreextension"
	"github.com/google/uuid"
)

// CoreExtensionStore persists the immutable extension projection and its
// confirmation-bound lifecycle. JSON is used for the closed protobuf/domain
// descriptors while identity, revision and fencing columns remain relational.
type CoreExtensionStore struct{ store *Store }

func NewCoreExtensionStore(s *Store) *CoreExtensionStore { return &CoreExtensionStore{store: s} }

func versionFromInspectionPG(in coreextension.Inspection, id uuid.UUID, now time.Time, m coreextension.Mutation) coreextension.VersionRecord {
	return coreextension.VersionRecord{VersionID: id.String(), Pin: in.Candidate.Pin, ContentDigest: in.ContentDigest, ManifestDigest: in.ManifestDigest, ExecutionDigest: in.ExecutionDigest, NetworkSchemaDigest: in.NetworkSchemaDigest, SecretSchemaDigest: in.SecretSchemaDigest, Execution: in.Execution, NetworkGrants: in.NetworkGrants, SecretGrants: configuredGrants(in.SecretGrants), ArtifactPath: m.ArtifactPath, ArtifactDigest: m.ArtifactDigest, CreatedAt: now}
}
func configuredGrants(g []coreextension.SecretGrantDescriptor) []coreextension.SecretGrantDescriptor {
	o := append([]coreextension.SecretGrantDescriptor(nil), g...)
	for i := range o {
		o[i].Configured = true
	}
	return o
}
func validateSecretInputsPG(m coreextension.Mutation) error {
	seen := map[string]bool{}
	for _, in := range m.SecretInputs {
		if in.Validate() != nil {
			return coreextension.ErrInvalid
		}
		seen[in.ReferenceID+":"+string(in.Purpose)] = true
	}
	for _, g := range m.Inspection.SecretGrants {
		key := g.ReferenceID + ":" + string(g.Purpose)
		if !seen[key] {
			return coreextension.ErrInvalid
		}
		matched := false
		for _, in := range m.SecretInputs {
			if in.ReferenceID == g.ReferenceID && in.Purpose == g.Purpose && g.BindingDigest == in.Fingerprint() {
				matched = true
			}
		}
		if !matched {
			return coreextension.ErrInvalid
		}
		delete(seen, key)
	}
	if len(seen) > 0 {
		return coreextension.ErrInvalid
	}
	return nil
}
func opForPG(s coreextension.State) string {
	if s == coreextension.StateUpdating {
		return coreextension.OperationUpdate
	}
	return coreextension.OperationUninstall
}
func bindingPG(i coreextension.Installation, m coreextension.Mutation) coreconfirmation.Binding {
	b := coreconfirmation.Binding{OperationDomain: "extension", TargetID: i.ID, TargetRevision: i.Revision, SourceVersion: i.Candidate.Pin.RegistryVersion, SourceCommit: i.Candidate.Pin.GitCommit, ContentDigest: coreconfirmation.Digest(m.Inspection.ContentDigest), ParameterDigest: coreconfirmation.Digest(digestPG(m, "params")), NetworkDigest: coreconfirmation.Digest(digestPG(m.Inspection.NetworkGrants, "network-schema")), SecretGrantDigest: coreconfirmation.Digest(digestPG(m.Inspection.SecretGrants, "secret-schema"))}
	for _, g := range m.Inspection.NetworkGrants {
		b.NetworkGrants = append(b.NetworkGrants, fmt.Sprintf("%s://%s:%d%s:%s", g.Scheme, g.Host, g.Port, g.PathPrefix, g.Digest))
	}
	for _, g := range m.Inspection.SecretGrants {
		b.SecretGrants = append(b.SecretGrants, coreconfirmation.SecretGrant{ReferenceID: g.ReferenceID, Purpose: coreconfirmation.SecretPurpose(g.Purpose), BindingDigest: coreconfirmation.Digest(g.BindingDigest)})
	}
	return b
}
func digestPG(v any, s string) string {
	b, _ := json.Marshal(v)
	return fmt.Sprintf("%x", sha256Bytes(append([]byte(s), b...)))
}
func sha256Bytes(b []byte) []byte { h := sha256.Sum256(b); return h[:] }

var _ coreextension.Repository = (*CoreExtensionStore)(nil)
var _ = sort.Strings
