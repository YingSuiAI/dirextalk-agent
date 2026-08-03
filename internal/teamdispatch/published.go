package teamdispatch

import (
	"crypto/sha256"
	"net/url"
	"path"
	"reflect"
	"strings"

	"github.com/YingSuiAI/dirextalk-agent/internal/cloud/canonical"
	"github.com/YingSuiAI/dirextalk-agent/internal/cloudexecution"
	installerbootstrap "github.com/YingSuiAI/dirextalk-agent/internal/installer/bootstrap"
	"github.com/YingSuiAI/dirextalk-agent/internal/security"
	"github.com/YingSuiAI/dirextalk-agent/internal/worker"
	"github.com/aws/aws-sdk-go-v2/aws/arn"
	"github.com/google/uuid"
)

const PublishedEvidenceSchemaV1 = "dirextalk.agent.team-published-evidence/v1"

// PublishedEvidenceV1 freezes only non-secret provider coordinates. Secret
// values remain inside the one-use publisher path; the stored SecretSource
// identifies an exact encrypted Secrets Manager version.
type PublishedEvidenceV1 struct {
	SchemaVersion      string                                `json:"schema_version"`
	ConnectionID       string                                `json:"connection_id"`
	Recipe             worker.BundleRef                      `json:"recipe"`
	Execution          worker.BundleRef                      `json:"execution"`
	Launch             cloudexecution.BootstrapArtifact      `json:"launch"`
	Access             worker.AccessScope                    `json:"access"`
	SecretBindings     map[string]string                     `json:"secret_bindings"`
	InstallerRootTrust *cloudexecution.InstallerRootTrustV1  `json:"installer_root_trust"`
	InstallerArtifacts []installerbootstrap.ArtifactSourceV1 `json:"installer_artifacts"`
	InstallerSecrets   []installerbootstrap.SecretSourceV1   `json:"installer_secrets"`
}

func NewPublishedEvidenceV1(
	intent IntentV1,
	connectionID string,
	published cloudexecution.PublishedBundles,
) (PublishedEvidenceV1, error) {
	evidence := PublishedEvidenceV1{
		SchemaVersion:  PublishedEvidenceSchemaV1,
		ConnectionID:   strings.TrimSpace(connectionID),
		Recipe:         published.Recipe,
		Execution:      published.Execution,
		Launch:         published.Launch,
		Access:         published.Access,
		SecretBindings: cloneStringMap(published.SecretBindings),
		InstallerRootTrust: cloneInstallerTrust(
			published.InstallerRootTrust,
		),
		InstallerArtifacts: append(
			[]installerbootstrap.ArtifactSourceV1{},
			published.InstallerArtifacts...,
		),
		InstallerSecrets: append(
			[]installerbootstrap.SecretSourceV1{},
			published.InstallerSecrets...,
		),
	}
	if evidence.ValidateAgainst(intent) != nil {
		return PublishedEvidenceV1{}, ErrFactMismatch
	}
	return evidence, nil
}

func (evidence PublishedEvidenceV1) PublishedBundles() (
	cloudexecution.PublishedBundles,
	error,
) {
	if evidence.Validate() != nil {
		return cloudexecution.PublishedBundles{}, ErrInvalid
	}
	return cloudexecution.PublishedBundles{
		Recipe:             evidence.Recipe,
		Execution:          evidence.Execution,
		Launch:             evidence.Launch,
		Access:             evidence.Access,
		SecretBindings:     cloneStringMap(evidence.SecretBindings),
		InstallerRootTrust: cloneInstallerTrust(evidence.InstallerRootTrust),
		InstallerArtifacts: append(
			[]installerbootstrap.ArtifactSourceV1{},
			evidence.InstallerArtifacts...,
		),
		InstallerSecrets: append(
			[]installerbootstrap.SecretSourceV1{},
			evidence.InstallerSecrets...,
		),
	}, nil
}

func (evidence PublishedEvidenceV1) Validate() error {
	connectionID, err := uuid.Parse(evidence.ConnectionID)
	if evidence.SchemaVersion != PublishedEvidenceSchemaV1 ||
		err != nil ||
		connectionID == uuid.Nil ||
		connectionID.String() != evidence.ConnectionID ||
		evidence.Recipe.Validate() != nil ||
		evidence.Execution.Validate() != nil ||
		evidence.Access.Validate() != nil ||
		!validLaunchArtifact(evidence.Launch) ||
		evidence.InstallerRootTrust == nil ||
		len(evidence.InstallerArtifacts) != 0 ||
		len(evidence.InstallerSecrets) != 1 ||
		len(evidence.SecretBindings) != 1 ||
		len(evidence.Access.SecretRefs) != 1 {
		return ErrInvalid
	}
	source := evidence.InstallerSecrets[0]
	key, err := arn.Parse(source.KMSKeyARN)
	if err != nil ||
		installerbootstrap.ValidateSecretSources(
			*evidence.InstallerRootTrust,
			evidence.InstallerSecrets,
			evidence.InstallerRootTrust.ArtifactManifest.
				Manifest.Binding.DeploymentID,
			installerbootstrap.InstanceIdentityV1{
				AccountID:  key.AccountID,
				Region:     key.Region,
				InstanceID: "i-00000000",
			},
		) != nil {
		return ErrInvalid
	}
	bound, found := evidence.SecretBindings[source.SecretRef]
	if !found ||
		bound != evidence.Access.SecretRefs[0] ||
		security.ContainsLikelySecret(bound) {
		return ErrInvalid
	}
	return nil
}

func (evidence PublishedEvidenceV1) ValidateAgainst(intent IntentV1) error {
	if intent.Validate() != nil || evidence.Validate() != nil {
		return ErrInvalid
	}
	binding := evidence.InstallerRootTrust.ArtifactManifest.Manifest.Binding
	source := evidence.InstallerSecrets[0]
	if binding.AgentInstanceID != intent.AgentInstanceID ||
		binding.DeploymentID != intent.DeploymentID ||
		binding.TaskID != intent.TaskID ||
		binding.PlanHash != intent.PlanDigest ||
		binding.ApprovalID != intent.ApprovalID ||
		source.SecretRef != intent.ModelCredentialRef ||
		evidence.SecretBindings[intent.ModelCredentialRef] !=
			evidence.Access.SecretRefs[0] {
		return ErrFactMismatch
	}
	base, err := exactDeploymentBase(
		evidence.Recipe.S3Ref,
		intent.DeploymentID,
		"bundles/recipe.cbor",
	)
	if err != nil ||
		!sameDeploymentObject(
			evidence.Execution.S3Ref,
			base,
			"bundles/execution.json",
		) ||
		!sameDeploymentObject(
			evidence.Launch.Reference,
			base,
			"launch/config.json",
		) ||
		evidence.Access.ArtifactPrefix != base+"artifacts/" ||
		evidence.Access.CheckpointPrefix != base+"checkpoints/" ||
		evidence.Access.EvidencePrefix != base+"evidence/" {
		return ErrFactMismatch
	}
	return nil
}

func (evidence PublishedEvidenceV1) Digest() (string, error) {
	if evidence.Validate() != nil {
		return "", ErrInvalid
	}
	return canonical.Digest(evidence)
}

func validLaunchArtifact(value cloudexecution.BootstrapArtifact) bool {
	parsed, err := url.Parse(strings.TrimSpace(value.Reference))
	var zero [sha256.Size]byte
	return err == nil &&
		parsed.Scheme == "s3" &&
		parsed.Host != "" &&
		parsed.Path != "" &&
		parsed.User == nil &&
		parsed.RawQuery == "" &&
		parsed.Fragment == "" &&
		value.SHA256 != zero &&
		!security.ContainsLikelySecret(value.Reference) &&
		(value.EnrollmentMaterialRef == "" ||
			value.EnrollmentMaterialRef ==
				"identity://aws-sts/"+
					evidenceDeploymentID(value.Reference))
}

func evidenceDeploymentID(reference string) string {
	parsed, err := url.Parse(reference)
	if err != nil {
		return ""
	}
	parts := strings.Split(strings.Trim(parsed.Path, "/"), "/")
	if len(parts) < 2 || parts[0] != "deployments" {
		return ""
	}
	return parts[1]
}

func exactDeploymentBase(
	reference,
	deploymentID,
	suffix string,
) (string, error) {
	parsed, err := url.Parse(reference)
	if err != nil ||
		parsed.Scheme != "s3" ||
		parsed.Host == "" ||
		parsed.Path != "/"+path.Join("deployments", deploymentID, suffix) {
		return "", ErrFactMismatch
	}
	return "s3://" + parsed.Host + "/deployments/" + deploymentID + "/", nil
}

func sameDeploymentObject(reference, base, suffix string) bool {
	return reference == base+suffix
}

func cloneStringMap(value map[string]string) map[string]string {
	if value == nil {
		return nil
	}
	cloned := make(map[string]string, len(value))
	for key, item := range value {
		cloned[key] = item
	}
	return cloned
}

func cloneInstallerTrust(
	value *cloudexecution.InstallerRootTrustV1,
) *cloudexecution.InstallerRootTrustV1 {
	if value == nil {
		return nil
	}
	cloned := *value
	cloned.PublicKey = append([]byte(nil), value.PublicKey...)
	cloned.ConfigCBOR = append([]byte(nil), value.ConfigCBOR...)
	cloned.ArtifactManifest.Manifest.Artifacts = append(
		cloned.ArtifactManifest.Manifest.Artifacts[:0:0],
		value.ArtifactManifest.Manifest.Artifacts...,
	)
	cloned.ArtifactManifest.Manifest.Secrets = append(
		cloned.ArtifactManifest.Manifest.Secrets[:0:0],
		value.ArtifactManifest.Manifest.Secrets...,
	)
	cloned.ArtifactManifest.Manifest.Volumes = append(
		cloned.ArtifactManifest.Manifest.Volumes[:0:0],
		value.ArtifactManifest.Manifest.Volumes...,
	)
	cloned.ArtifactManifest.Signature = append(
		[]byte(nil),
		value.ArtifactManifest.Signature...,
	)
	if reflect.DeepEqual(cloned, *value) {
		return &cloned
	}
	return nil
}
