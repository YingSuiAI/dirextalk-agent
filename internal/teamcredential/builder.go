// Package teamcredential binds one approved Team Worker role to a
// deployment-scoped model credential without putting plaintext in a task,
// database row, execution bundle, log, or EC2 user-data document.
package teamcredential

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/cloudexecution"
	"github.com/YingSuiAI/dirextalk-agent/internal/installer"
	installerbootstrap "github.com/YingSuiAI/dirextalk-agent/internal/installer/bootstrap"
	"github.com/YingSuiAI/dirextalk-agent/internal/security"
	"github.com/YingSuiAI/dirextalk-agent/internal/teamdispatch"
	"github.com/YingSuiAI/dirextalk-agent/internal/teaminput"
	"github.com/YingSuiAI/dirextalk-agent/internal/teampricing"
	"github.com/YingSuiAI/dirextalk-agent/internal/workerrunner"
	"github.com/google/uuid"
)

const (
	workerServiceUID      = uint32(65532)
	workerServiceGID      = uint32(65532)
	bootstrapExpiryGrace  = 30 * time.Minute
	maximumCapabilityLife = 7 * 24 * time.Hour
)

var (
	ErrInvalid     = errors.New("invalid Team Worker credential request")
	ErrUnavailable = errors.New("Team Worker credential is unavailable")
)

type BuildRequest struct {
	Intent   teamdispatch.IntentV1
	Prepared teaminput.PreparedInput
}

// RoleBundles is ready for the existing AWS artifact publisher. SecretRefs
// are passed separately because the Worker receives only the publisher's
// deployment-scoped opaque reference, never the catalog's mounted source.
type RoleBundles struct {
	Bundles    cloudexecution.CompiledBundles
	SecretRefs []string
}

func (bundles *RoleBundles) Destroy() {
	if bundles == nil {
		return
	}
	clear(bundles.Bundles.RecipeBytes)
	clear(bundles.Bundles.ExecutionBytes)
	if bundles.Bundles.InstallerDelivery != nil {
		clear(bundles.Bundles.InstallerDelivery.PublicKey)
		clear(bundles.Bundles.InstallerDelivery.SignedPlan.Signature)
		clear(bundles.Bundles.InstallerDelivery.ArtifactManifest.Signature)
	}
	*bundles = RoleBundles{}
}

type Builder struct {
	issuer      *installer.TrustIssuer
	credentials *teampricing.CatalogCredentialReadiness
	now         func() time.Time
}

func NewBuilder(
	issuer *installer.TrustIssuer,
	credentials *teampricing.CatalogCredentialReadiness,
	now func() time.Time,
) (*Builder, error) {
	if issuer == nil || credentials == nil || now == nil {
		return nil, ErrUnavailable
	}
	return &Builder{
		issuer:      issuer,
		credentials: credentials,
		now:         now,
	}, nil
}

func (builder *Builder) Build(
	request BuildRequest,
) (RoleBundles, error) {
	if builder == nil || builder.issuer == nil ||
		builder.credentials == nil || builder.now == nil ||
		request.Intent.Validate() != nil ||
		validatePrepared(request.Intent, request.Prepared) != nil {
		return RoleBundles{}, ErrInvalid
	}
	now := builder.now().UTC().Truncate(time.Microsecond)
	if now.IsZero() || !now.Before(request.Intent.LaunchNotAfter) {
		return RoleBundles{}, ErrUnavailable
	}
	materialization := request.Prepared.Fact.Materialization
	grant := materialization.CredentialGrant
	expiresAt := request.Intent.LaunchNotAfter.
		Add(bootstrapExpiryGrace).
		UTC().
		Truncate(time.Microsecond)
	maximum := now.Add(maximumCapabilityLife)
	if expiresAt.After(maximum) {
		expiresAt = maximum
	}
	if !expiresAt.After(now) {
		return RoleBundles{}, ErrUnavailable
	}
	versionID := uuid.NewSHA1(
		uuid.MustParse(request.Intent.DeploymentID),
		[]byte(
			"team-model-credential/v1\x00"+
				grant.CredentialSlot+"\x00"+
				materialization.CredentialGrantDigest,
		),
	).String()
	secretName := "dtx/" + request.Intent.AgentInstanceID +
		"/deployments/" + request.Intent.DeploymentID +
		"/" + grant.CredentialSlot
	declaration := installer.SecretV1{
		SlotID:     grant.CredentialSlot,
		SecretRef:  request.Intent.ModelCredentialRef,
		SecretName: secretName,
		VersionID:  versionID,
		TargetPath: materialization.CredentialTargetPath,
		FileMode:   0o400,
		OwnerUID:   workerServiceUID,
		OwnerGID:   workerServiceGID,
	}
	binding := installer.BindingV1{
		AgentInstanceID: request.Intent.AgentInstanceID,
		DeploymentID:    request.Intent.DeploymentID,
		TaskID:          request.Intent.TaskID,
		PlanHash:        request.Intent.PlanDigest,
		ApprovalID:      request.Intent.ApprovalID,
		RecipeDigest:    materialization.ManifestDigest,
	}
	plan := installer.InstallerPlanV1{
		SchemaVersion: installer.PlanSchemaV1,
		Binding:       binding,
		SecretRefs:    []string{declaration.SecretRef},
		Secrets:       []installer.SecretV1{declaration},
		Network:       installer.NetworkV1{},
		ExpiresAt:     expiresAt.Format(time.RFC3339Nano),
	}
	delivery, err := builder.issuer.Issue(
		plan,
		installer.DaemonConfigV1{
			SchemaVersion: installer.DaemonConfigSchema,
			Binding:       binding,
			TargetRoot:    installer.PreinstalledArtifactRoot,
		},
		now,
	)
	if err != nil {
		return RoleBundles{}, ErrUnavailable
	}
	root, err := delivery.RootTrustMaterial(now)
	if err != nil {
		return RoleBundles{}, ErrUnavailable
	}
	trust, err := installerbootstrap.NewRootTrustMaterial(root)
	if err != nil {
		return RoleBundles{}, ErrUnavailable
	}
	selection := teampricing.CredentialMaterializationRequest{
		ProfileID:           grant.ModelProfileID,
		Provider:            grant.ModelProvider,
		Model:               grant.Model,
		ModelInterface:      string(grant.ModelInterface),
		WorkerCredentialRef: request.Intent.ModelCredentialRef,
	}
	if builder.credentials.ValidateMaterializationRequest(selection) != nil {
		return RoleBundles{}, ErrInvalid
	}
	content := &catalogSecretContent{
		credentials: builder.credentials,
		selection:   selection,
	}
	return RoleBundles{
		Bundles: cloudexecution.CompiledBundles{
			RecipeBytes:        bytes.Clone(request.Prepared.Compiled.ManifestBytes),
			ExecutionBytes:     bytes.Clone(request.Prepared.Compiled.ExecutionBytes),
			InstallerDelivery:  &delivery,
			InstallerRootTrust: &trust,
			InstallerArtifacts: []cloudexecution.InstallerArtifactStagingInput{},
			InstallerSecrets: []cloudexecution.InstallerSecretStagingInput{{
				SlotID:       declaration.SlotID,
				SecretRef:    declaration.SecretRef,
				SecretName:   declaration.SecretName,
				VersionID:    declaration.VersionID,
				TargetPath:   declaration.TargetPath,
				FileMode:     declaration.FileMode,
				OwnerUID:     declaration.OwnerUID,
				OwnerGID:     declaration.OwnerGID,
				RecipeDigest: binding.RecipeDigest,
				Content:      content,
			}},
		},
		SecretRefs: []string{declaration.SecretRef},
	}, nil
}

func validatePrepared(
	intent teamdispatch.IntentV1,
	prepared teaminput.PreparedInput,
) error {
	materialization := prepared.Fact.Materialization
	compiled := prepared.Compiled
	if materialization.Validate() != nil ||
		!validInputStatus(prepared.Fact.Status) ||
		prepared.Fact.RecordRevision == 0 ||
		prepared.Fact.CreatedAt.IsZero() ||
		prepared.Fact.UpdatedAt.IsZero() ||
		materialization.OwnerID != intent.OwnerID ||
		materialization.ExecutionID != intent.ExecutionID ||
		materialization.ExecutionDigest != intent.ExecutionDigest ||
		materialization.RoleID != intent.RoleID ||
		materialization.RoleDigest != intent.RoleDigest ||
		materialization.TaskID != intent.TaskID ||
		materialization.TaskStepID != intent.TaskStepID ||
		materialization.DeploymentID != intent.DeploymentID ||
		materialization.ExpectedWorkerID != intent.ExpectedWorkerID ||
		materialization.Manifest.PlanID != intent.PlanID ||
		materialization.Manifest.PlanDigest != intent.PlanDigest ||
		compiled.Manifest != materialization.Manifest ||
		compiled.ManifestDigest != materialization.ManifestDigest ||
		!reflect.DeepEqual(
			compiled.RuntimeTask,
			materialization.RuntimeTask,
		) ||
		compiled.ExecutionBundleDigest !=
			materialization.ExecutionBundleDigest ||
		compiled.CredentialGrant !=
			materialization.CredentialGrant ||
		compiled.CredentialGrantDigest !=
			materialization.CredentialGrantDigest ||
		compiled.ContextTargetPath !=
			materialization.ContextTargetPath ||
		compiled.WorkspaceTargetPath !=
			materialization.WorkspaceTargetPath ||
		compiled.CredentialTargetPath !=
			materialization.CredentialTargetPath {
		return ErrInvalid
	}
	manifestBytes, err := json.Marshal(compiled.Manifest)
	if err != nil ||
		!bytes.Equal(manifestBytes, compiled.ManifestBytes) ||
		digest(compiled.ManifestBytes) != compiled.ManifestDigest ||
		digest(compiled.ContextBytes) !=
			materialization.ContextDigest ||
		digest(compiled.ExecutionBytes) !=
			compiled.ExecutionBundleDigest ||
		security.ContainsLikelySecret(
			string(compiled.ManifestBytes),
		) ||
		security.ContainsLikelySecret(
			string(compiled.ContextBytes),
		) ||
		security.ContainsLikelySecret(
			string(compiled.ExecutionBytes),
		) {
		clear(manifestBytes)
		return ErrInvalid
	}
	clear(manifestBytes)
	recipeDigest, err := hex.DecodeString(strings.TrimPrefix(
		compiled.ManifestDigest,
		"sha256:",
	))
	if err != nil {
		clear(recipeDigest)
		return ErrInvalid
	}
	objects, err := workerrunner.PublishedInputObjects(
		compiled.ExecutionBytes,
		recipeDigest,
	)
	clear(recipeDigest)
	if err != nil || len(objects) != 2 ||
		objects[0] != compiled.ContextObject ||
		objects[1] != compiled.WorkspaceObject ||
		compiled.ContextObject.SHA256 !=
			materialization.ContextDigest ||
		compiled.ContextObject.SizeBytes !=
			int64(len(compiled.ContextBytes)) ||
		compiled.WorkspaceObject.SHA256 !=
			materialization.WorkspaceDigest {
		return ErrInvalid
	}
	return nil
}

func validInputStatus(value teaminput.Status) bool {
	switch value {
	case teaminput.StatusMaterialized,
		teaminput.StatusPublished,
		teaminput.StatusCredentialReady,
		teaminput.StatusLaunchReady:
		return true
	default:
		return false
	}
}

func digest(content []byte) string {
	value := sha256.Sum256(content)
	return "sha256:" + hex.EncodeToString(value[:])
}

type catalogSecretContent struct {
	credentials *teampricing.CatalogCredentialReadiness
	selection   teampricing.CredentialMaterializationRequest
}

func (content *catalogSecretContent) Materialize(
	ctx context.Context,
	write func([]byte) error,
) error {
	if content == nil || content.credentials == nil ||
		ctx == nil || write == nil {
		return ErrUnavailable
	}
	if err := content.credentials.Materialize(
		ctx,
		content.selection,
		write,
	); err != nil {
		return ErrUnavailable
	}
	return nil
}

func (*catalogSecretContent) Commit(
	ctx context.Context,
	verify func() error,
) error {
	if ctx == nil || verify == nil {
		return ErrUnavailable
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := verify(); err != nil {
		return ErrUnavailable
	}
	return nil
}

var _ cloudexecution.InstallerSecretContent = (*catalogSecretContent)(nil)
