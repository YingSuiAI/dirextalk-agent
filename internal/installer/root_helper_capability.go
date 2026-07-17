package installer

import (
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"strings"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/cloud/canonical"
	"github.com/YingSuiAI/dirextalk-agent/internal/helperkey"
	"github.com/google/uuid"
)

const (
	RootHelperBootstrapCapabilitySchemaV1 = "dirextalk.agent.root-helper-bootstrap-capability/v1"
	RootHelperRestartCapabilitySchemaV1   = "dirextalk.agent.root-helper-restart-capability/v1"
	RootHelperPairingCapabilitySchemaV1   = "dirextalk.agent.root-helper-pairing-capability/v1"
	maximumRootHelperCapabilityDuration   = 15 * time.Minute
)

type RootHelperOperationKind string

const (
	RootHelperOperationPairingBegin  RootHelperOperationKind = "pairing_begin"
	RootHelperOperationPairingResume RootHelperOperationKind = "pairing_resume"
)

// RootHelperBootstrapCapabilityV1 is the complete, non-secret authority for
// one privileged helper-key delivery. The root daemon accepts no caller
// supplied path, mode, principal, or Secrets coordinate outside this signed
// value.
type RootHelperBootstrapCapabilityV1 struct {
	SchemaVersion    string                  `json:"schema_version"`
	CapabilityID     string                  `json:"capability_id"`
	TrustID          string                  `json:"trust_id"`
	InstallerBinding BindingV1               `json:"installer_binding"`
	PlanDigest       string                  `json:"plan_digest"`
	ManifestDigest   string                  `json:"manifest_digest"`
	HelperBinding    helperkey.DeviceBinding `json:"helper_binding"`
	HelperPublicKey  []byte                  `json:"helper_public_key"`
	Nonce            []byte                  `json:"nonce"`
	DeliveryRevision int64                   `json:"delivery_revision"`
	IssuedAt         string                  `json:"issued_at"`
	ExpiresAt        string                  `json:"expires_at"`
}

type SignedRootHelperBootstrapCapabilityV1 struct {
	Capability  RootHelperBootstrapCapabilityV1 `json:"capability"`
	SignerKeyID string                          `json:"signer_key_id"`
	Signature   []byte                          `json:"signature"`
}

// RootHelperRestartCapabilityV1 selects only a command already declared by
// the original InstallerDelivery. It intentionally has no argv, environment,
// path, unit, shell fragment, or provider passthrough.
type RootHelperRestartCapabilityV1 struct {
	SchemaVersion                   string    `json:"schema_version"`
	CapabilityID                    string    `json:"capability_id"`
	TrustID                         string    `json:"trust_id"`
	InstallerBinding                BindingV1 `json:"installer_binding"`
	PlanDigest                      string    `json:"plan_digest"`
	OperationID                     string    `json:"operation_id"`
	DeploymentID                    string    `json:"deployment_id"`
	OwnerID                         string    `json:"owner_id"`
	LifecycleRestartRef             string    `json:"lifecycle_restart_ref"`
	ExecutionBundleDigest           string    `json:"execution_bundle_digest"`
	ExpectedInstalledManifestDigest string    `json:"expected_installed_manifest_digest"`
	HelperDeliveryID                string    `json:"helper_delivery_id"`
	HelperID                        string    `json:"helper_id"`
	HelperSignerKeyID               string    `json:"helper_signer_key_id"`
	HelperPublicKeyDigest           string    `json:"helper_public_key_digest"`
	InstanceID                      string    `json:"instance_id"`
	WorkerPrincipalID               string    `json:"worker_principal_id"`
	WorkerLeaseEpoch                int64     `json:"worker_lease_epoch"`
	IssuedAt                        string    `json:"issued_at"`
	ExpiresAt                       string    `json:"expires_at"`
}

type SignedRootHelperRestartCapabilityV1 struct {
	Capability  RootHelperRestartCapabilityV1 `json:"capability"`
	SignerKeyID string                        `json:"signer_key_id"`
	Signature   []byte                        `json:"signature"`
}

type RootHelperRestartGrantV1 struct {
	OperationID                     string
	DeploymentID                    string
	OwnerID                         string
	LifecycleRestartRef             string
	ExecutionBundleDigest           string
	ExpectedInstalledManifestDigest string
	WorkerLeaseEpoch                int64
	LeaseExpiresAt                  time.Time
}

// RootHelperPairingCapabilityV1 authorizes exactly one Recipe-declared command
// in one pairing phase. Its signing domain is the OperationKind, so neither a
// restart capability nor the opposite pairing phase can be substituted.
type RootHelperPairingCapabilityV1 struct {
	SchemaVersion        string                  `json:"schema_version"`
	CapabilityID         string                  `json:"capability_id"`
	OperationKind        RootHelperOperationKind `json:"operation_kind"`
	TrustID              string                  `json:"trust_id"`
	InstallerBinding     BindingV1               `json:"installer_binding"`
	PlanDigest           string                  `json:"plan_digest"`
	OperationID          string                  `json:"operation_id"`
	SessionID            string                  `json:"session_id"`
	TaskID               string                  `json:"task_id"`
	StepID               string                  `json:"step_id"`
	DeploymentID         string                  `json:"deployment_id"`
	OwnerID              string                  `json:"owner_id"`
	RecipeID             string                  `json:"recipe_id"`
	RecipeDigest         string                  `json:"recipe_digest"`
	RecipeRevision       int64                   `json:"recipe_revision"`
	PayloadScopeRevision int64                   `json:"payload_scope_revision"`
	// RecipientPublicKeyDigest is empty for resume. For begin it binds the
	// untrusted socket request's raw X25519 recipient key before any command
	// is eligible to run.
	RecipientPublicKeyDigest string `json:"recipient_public_key_digest"`
	// ExecutionEpoch is initialized exactly once when the durable operation is
	// first acquired. It is deliberately independent from the transport lease.
	ExecutionEpoch int64 `json:"execution_epoch"`
	// PairingExpiresAt is the immutable session deadline. ExpiresAt remains the
	// short-lived capability authorization deadline.
	PairingExpiresAt                string `json:"pairing_expires_at"`
	CommandID                       string `json:"command_id"`
	ExecutionBundleDigest           string `json:"execution_bundle_digest"`
	ExpectedInstalledManifestDigest string `json:"expected_installed_manifest_digest"`
	HelperDeliveryID                string `json:"helper_delivery_id"`
	HelperID                        string `json:"helper_id"`
	HelperSignerKeyID               string `json:"helper_signer_key_id"`
	HelperPublicKeyDigest           string `json:"helper_public_key_digest"`
	InstanceID                      string `json:"instance_id"`
	WorkerPrincipalID               string `json:"worker_principal_id"`
	WorkerLeaseEpoch                int64  `json:"worker_lease_epoch"`
	IssuedAt                        string `json:"issued_at"`
	ExpiresAt                       string `json:"expires_at"`
}

type SignedRootHelperPairingCapabilityV1 struct {
	Capability  RootHelperPairingCapabilityV1 `json:"capability"`
	SignerKeyID string                        `json:"signer_key_id"`
	Signature   []byte                        `json:"signature"`
}

type RootHelperPairingGrantV1 struct {
	OperationID                     string
	SessionID                       string
	TaskID                          string
	StepID                          string
	DeploymentID                    string
	OwnerID                         string
	RecipeID                        string
	RecipeDigest                    string
	RecipeRevision                  int64
	PayloadScopeRevision            int64
	RecipientPublicKeyDigest        string
	ExecutionEpoch                  int64
	PairingExpiresAt                time.Time
	CommandID                       string
	ExecutionBundleDigest           string
	ExpectedInstalledManifestDigest string
	WorkerLeaseEpoch                int64
	LeaseExpiresAt                  time.Time
}

func (issuer *TrustIssuer) IssueRootHelperBootstrapCapability(
	delivery DeliveryV1,
	binding helperkey.DeviceBinding,
	publicKey, nonce []byte,
	deliveryRevision int64,
	expiresAt, now time.Time,
) (SignedRootHelperBootstrapCapabilityV1, error) {
	if err := ValidateDeliveryTrust(delivery); err != nil || helperkey.ValidateBinding(binding, publicKey) != nil ||
		len(nonce) != 32 || digestBytes(nonce) != binding.NonceDigest || deliveryRevision < 1 {
		return SignedRootHelperBootstrapCapabilityV1{}, errorf(CodeInvalidRequest, "root helper bootstrap capability is invalid")
	}
	if binding.AgentInstanceID != delivery.Config.Binding.AgentInstanceID ||
		binding.DeploymentID != delivery.Config.Binding.DeploymentID {
		return SignedRootHelperBootstrapCapabilityV1{}, errorf(CodeInvalidRequest, "root helper bootstrap capability crosses installer binding")
	}
	issuedAt, expiry, err := validateRootHelperLease(now, expiresAt)
	if err != nil {
		return SignedRootHelperBootstrapCapabilityV1{}, err
	}
	planDigest, manifestDigest, err := rootHelperDeliveryDigests(delivery)
	if err != nil {
		return SignedRootHelperBootstrapCapabilityV1{}, err
	}
	capability := RootHelperBootstrapCapabilityV1{
		SchemaVersion: RootHelperBootstrapCapabilitySchemaV1,
		CapabilityID:  uuid.NewSHA1(uuid.NameSpaceOID, []byte(delivery.TrustID+"\x00bootstrap\x00"+binding.DeliveryID+"\x00"+expiry.Format(time.RFC3339Nano))).String(),
		TrustID:       delivery.TrustID, InstallerBinding: delivery.Config.Binding,
		PlanDigest: planDigest, ManifestDigest: manifestDigest, HelperBinding: binding,
		HelperPublicKey: append([]byte(nil), publicKey...), Nonce: append([]byte(nil), nonce...),
		DeliveryRevision: deliveryRevision, IssuedAt: issuedAt.Format(time.RFC3339Nano), ExpiresAt: expiry.Format(time.RFC3339Nano),
	}
	signature, err := issuer.signRootHelperCapability(delivery, "bootstrap", capability)
	if err != nil {
		return SignedRootHelperBootstrapCapabilityV1{}, err
	}
	return SignedRootHelperBootstrapCapabilityV1{
		Capability: capability, SignerKeyID: delivery.SignedPlan.SignerKeyID, Signature: signature,
	}, nil
}

func (issuer *TrustIssuer) IssueRootHelperRestartCapability(
	delivery DeliveryV1,
	helperBinding helperkey.DeviceBinding,
	grant RootHelperRestartGrantV1,
	now time.Time,
) (SignedRootHelperRestartCapabilityV1, error) {
	if err := ValidateDeliveryTrust(delivery); err != nil {
		return SignedRootHelperRestartCapabilityV1{}, err
	}
	if _, found := findCommand(delivery.SignedPlan.Plan.Commands, grant.LifecycleRestartRef); !found ||
		helperBinding.AgentInstanceID != delivery.Config.Binding.AgentInstanceID ||
		helperBinding.DeploymentID != delivery.Config.Binding.DeploymentID ||
		grant.DeploymentID != helperBinding.DeploymentID || !validRootHelperRestartIdentity(
		grant.OperationID, grant.OwnerID, helperBinding.DeliveryID, helperBinding.HelperID,
		helperBinding.SignerKeyID, helperBinding.InstanceID, helperBinding.WorkerPrincipalID,
	) || grant.WorkerLeaseEpoch < 1 ||
		!digestPattern.MatchString(helperBinding.PublicKeyDigest) ||
		!digestPattern.MatchString(grant.ExecutionBundleDigest) ||
		!digestPattern.MatchString(grant.ExpectedInstalledManifestDigest) {
		return SignedRootHelperRestartCapabilityV1{}, errorf(CodeInvalidRequest, "root helper restart capability is invalid")
	}
	issuedAt, expiry, err := validateRootHelperLease(now, grant.LeaseExpiresAt)
	if err != nil {
		return SignedRootHelperRestartCapabilityV1{}, err
	}
	planDigest, _, err := rootHelperDeliveryDigests(delivery)
	if err != nil {
		return SignedRootHelperRestartCapabilityV1{}, err
	}
	capability := RootHelperRestartCapabilityV1{
		SchemaVersion: RootHelperRestartCapabilitySchemaV1,
		CapabilityID:  uuid.NewSHA1(uuid.NameSpaceOID, []byte(delivery.TrustID+"\x00restart\x00"+grant.OperationID+"\x00"+expiry.Format(time.RFC3339Nano))).String(),
		TrustID:       delivery.TrustID, InstallerBinding: delivery.Config.Binding, PlanDigest: planDigest,
		OperationID: grant.OperationID, DeploymentID: grant.DeploymentID, OwnerID: grant.OwnerID,
		LifecycleRestartRef: grant.LifecycleRestartRef, ExecutionBundleDigest: grant.ExecutionBundleDigest,
		ExpectedInstalledManifestDigest: grant.ExpectedInstalledManifestDigest,
		HelperDeliveryID:                helperBinding.DeliveryID, HelperID: helperBinding.HelperID,
		HelperSignerKeyID: helperBinding.SignerKeyID, HelperPublicKeyDigest: helperBinding.PublicKeyDigest,
		InstanceID:        helperBinding.InstanceID,
		WorkerPrincipalID: helperBinding.WorkerPrincipalID, WorkerLeaseEpoch: grant.WorkerLeaseEpoch,
		IssuedAt: issuedAt.Format(time.RFC3339Nano), ExpiresAt: expiry.Format(time.RFC3339Nano),
	}
	signature, err := issuer.signRootHelperCapability(delivery, "restart", capability)
	if err != nil {
		return SignedRootHelperRestartCapabilityV1{}, err
	}
	return SignedRootHelperRestartCapabilityV1{
		Capability: capability, SignerKeyID: delivery.SignedPlan.SignerKeyID, Signature: signature,
	}, nil
}

func (issuer *TrustIssuer) IssueRootHelperPairingCapability(
	delivery DeliveryV1,
	helperBinding helperkey.DeviceBinding,
	kind RootHelperOperationKind,
	grant RootHelperPairingGrantV1,
	now time.Time,
) (SignedRootHelperPairingCapabilityV1, error) {
	if err := ValidateDeliveryTrust(delivery); err != nil {
		return SignedRootHelperPairingCapabilityV1{}, err
	}
	_, commandFound := findCommand(delivery.SignedPlan.Plan.Commands, grant.CommandID)
	if (kind != RootHelperOperationPairingBegin && kind != RootHelperOperationPairingResume) ||
		!commandFound ||
		helperBinding.AgentInstanceID != delivery.Config.Binding.AgentInstanceID ||
		helperBinding.DeploymentID != delivery.Config.Binding.DeploymentID ||
		grant.DeploymentID != helperBinding.DeploymentID || !validRootHelperRestartIdentity(
		grant.OperationID, grant.OwnerID, helperBinding.DeliveryID, helperBinding.HelperID,
		helperBinding.SignerKeyID, helperBinding.InstanceID, helperBinding.WorkerPrincipalID,
	) || !validPairingScope(grant.SessionID, grant.TaskID, grant.StepID, grant.RecipeID,
		grant.RecipeDigest, grant.RecipeRevision, grant.PayloadScopeRevision) ||
		!validPairingRecipientBinding(kind, grant.RecipientPublicKeyDigest) || grant.ExecutionEpoch < 1 ||
		grant.PairingExpiresAt.IsZero() || !now.UTC().Before(grant.PairingExpiresAt.UTC()) ||
		grant.WorkerLeaseEpoch < 1 || !digestPattern.MatchString(helperBinding.PublicKeyDigest) ||
		!digestPattern.MatchString(grant.ExecutionBundleDigest) ||
		!digestPattern.MatchString(grant.ExpectedInstalledManifestDigest) {
		return SignedRootHelperPairingCapabilityV1{}, errorf(CodeInvalidRequest, "root helper pairing capability is invalid")
	}
	issuedAt, expiry, err := validateRootHelperLease(now, grant.LeaseExpiresAt)
	if err != nil {
		return SignedRootHelperPairingCapabilityV1{}, err
	}
	pairingExpiry := grant.PairingExpiresAt.UTC()
	if expiry.After(pairingExpiry) {
		return SignedRootHelperPairingCapabilityV1{}, errorf(CodeLeaseRejected, "root helper pairing capability exceeds pairing lifetime")
	}
	planDigest, _, err := rootHelperDeliveryDigests(delivery)
	if err != nil {
		return SignedRootHelperPairingCapabilityV1{}, err
	}
	capability := RootHelperPairingCapabilityV1{
		SchemaVersion: RootHelperPairingCapabilitySchemaV1, OperationKind: kind,
		CapabilityID: uuid.NewSHA1(uuid.NameSpaceOID, []byte(delivery.TrustID+"\x00"+string(kind)+"\x00"+grant.OperationID+"\x00"+expiry.Format(time.RFC3339Nano))).String(),
		TrustID:      delivery.TrustID, InstallerBinding: delivery.Config.Binding, PlanDigest: planDigest,
		OperationID: grant.OperationID, SessionID: grant.SessionID, TaskID: grant.TaskID, StepID: grant.StepID,
		DeploymentID: grant.DeploymentID, OwnerID: grant.OwnerID,
		RecipeID: grant.RecipeID, RecipeDigest: grant.RecipeDigest, RecipeRevision: grant.RecipeRevision,
		PayloadScopeRevision: grant.PayloadScopeRevision, RecipientPublicKeyDigest: grant.RecipientPublicKeyDigest,
		ExecutionEpoch: grant.ExecutionEpoch, PairingExpiresAt: pairingExpiry.Format(time.RFC3339Nano),
		CommandID: grant.CommandID, ExecutionBundleDigest: grant.ExecutionBundleDigest,
		ExpectedInstalledManifestDigest: grant.ExpectedInstalledManifestDigest,
		HelperDeliveryID:                helperBinding.DeliveryID, HelperID: helperBinding.HelperID,
		HelperSignerKeyID: helperBinding.SignerKeyID, HelperPublicKeyDigest: helperBinding.PublicKeyDigest,
		InstanceID: helperBinding.InstanceID, WorkerPrincipalID: helperBinding.WorkerPrincipalID,
		WorkerLeaseEpoch: grant.WorkerLeaseEpoch,
		IssuedAt:         issuedAt.Format(time.RFC3339Nano), ExpiresAt: expiry.Format(time.RFC3339Nano),
	}
	signature, err := issuer.signRootHelperCapability(delivery, string(kind), capability)
	if err != nil {
		return SignedRootHelperPairingCapabilityV1{}, err
	}
	return SignedRootHelperPairingCapabilityV1{
		Capability: capability, SignerKeyID: delivery.SignedPlan.SignerKeyID, Signature: signature,
	}, nil
}

func ValidateRootHelperBootstrapCapabilityAt(delivery DeliveryV1, signed SignedRootHelperBootstrapCapabilityV1, now time.Time) error {
	value := signed.Capability
	if value.SchemaVersion != RootHelperBootstrapCapabilitySchemaV1 || value.TrustID != delivery.TrustID ||
		value.InstallerBinding != delivery.Config.Binding || value.DeliveryRevision < 1 ||
		helperkey.ValidateBinding(value.HelperBinding, value.HelperPublicKey) != nil ||
		len(value.Nonce) != 32 || digestBytes(value.Nonce) != value.HelperBinding.NonceDigest ||
		value.HelperBinding.AgentInstanceID != value.InstallerBinding.AgentInstanceID ||
		value.HelperBinding.DeploymentID != value.InstallerBinding.DeploymentID {
		return errorf(CodeInvalidRequest, "root helper bootstrap capability binding is invalid")
	}
	if err := validateSignedRootHelperCapability(delivery, "bootstrap", value, signed.SignerKeyID, signed.Signature, value.PlanDigest, value.ManifestDigest, now); err != nil {
		return err
	}
	return nil
}

func ValidateRootHelperRestartCapabilityAt(delivery DeliveryV1, signed SignedRootHelperRestartCapabilityV1, now time.Time) error {
	value := signed.Capability
	if value.SchemaVersion != RootHelperRestartCapabilitySchemaV1 || value.TrustID != delivery.TrustID ||
		value.InstallerBinding != delivery.Config.Binding || value.DeploymentID != value.InstallerBinding.DeploymentID ||
		value.WorkerLeaseEpoch < 1 || !digestPattern.MatchString(value.ExecutionBundleDigest) ||
		!digestPattern.MatchString(value.ExpectedInstalledManifestDigest) ||
		!digestPattern.MatchString(value.HelperPublicKeyDigest) ||
		!validRootHelperRestartIdentity(
			value.OperationID, value.OwnerID, value.HelperDeliveryID, value.HelperID,
			value.HelperSignerKeyID, value.InstanceID, value.WorkerPrincipalID,
		) {
		return errorf(CodeInvalidRequest, "root helper restart capability binding is invalid")
	}
	if _, found := findCommand(delivery.SignedPlan.Plan.Commands, value.LifecycleRestartRef); !found {
		return errorf(CodeCommandNotAllowed, "restart command is not declared by installer delivery")
	}
	return validateSignedRootHelperCapability(delivery, "restart", value, signed.SignerKeyID, signed.Signature, value.PlanDigest, "", now)
}

func validPairingScope(sessionID, taskID, stepID, recipeID, recipeDigest string, recipeRevision, payloadScopeRevision int64) bool {
	session, sessionErr := uuid.Parse(sessionID)
	task, taskErr := uuid.Parse(taskID)
	return sessionErr == nil && session != uuid.Nil && session.String() == sessionID &&
		taskErr == nil && task != uuid.Nil && task.String() == taskID &&
		validPairingScopeID(stepID) && validPairingScopeID(recipeID) &&
		digestPattern.MatchString(recipeDigest) && recipeRevision > 0 && payloadScopeRevision > 0
}

func validPairingScopeID(value string) bool {
	return value != "" && len(value) <= 128 && strings.TrimSpace(value) == value &&
		!strings.ContainsAny(value, "\x00\r\n")
}

func validPairingRecipientBinding(kind RootHelperOperationKind, digest string) bool {
	switch kind {
	case RootHelperOperationPairingBegin:
		return digestPattern.MatchString(digest)
	case RootHelperOperationPairingResume:
		return digest == ""
	default:
		return false
	}
}

func ValidateRootHelperPairingCapabilityAt(delivery DeliveryV1, signed SignedRootHelperPairingCapabilityV1, expectedKind RootHelperOperationKind, now time.Time) error {
	value := signed.Capability
	if (expectedKind != RootHelperOperationPairingBegin && expectedKind != RootHelperOperationPairingResume) ||
		value.SchemaVersion != RootHelperPairingCapabilitySchemaV1 || value.OperationKind != expectedKind ||
		value.TrustID != delivery.TrustID || value.InstallerBinding != delivery.Config.Binding ||
		value.DeploymentID != value.InstallerBinding.DeploymentID || value.WorkerLeaseEpoch < 1 ||
		!digestPattern.MatchString(value.ExecutionBundleDigest) ||
		!digestPattern.MatchString(value.ExpectedInstalledManifestDigest) ||
		!digestPattern.MatchString(value.HelperPublicKeyDigest) ||
		!validPairingScope(value.SessionID, value.TaskID, value.StepID, value.RecipeID,
			value.RecipeDigest, value.RecipeRevision, value.PayloadScopeRevision) ||
		!validPairingRecipientBinding(expectedKind, value.RecipientPublicKeyDigest) || value.ExecutionEpoch < 1 ||
		!validRootHelperRestartIdentity(
			value.OperationID, value.OwnerID, value.HelperDeliveryID, value.HelperID,
			value.HelperSignerKeyID, value.InstanceID, value.WorkerPrincipalID,
		) {
		return errorf(CodeInvalidRequest, "root helper pairing capability binding is invalid")
	}
	if _, found := findCommand(delivery.SignedPlan.Plan.Commands, value.CommandID); !found {
		return errorf(CodeCommandNotAllowed, "pairing command is not declared by installer delivery")
	}
	if err := validateSignedRootHelperCapability(delivery, string(expectedKind), value, signed.SignerKeyID, signed.Signature, value.PlanDigest, "", now); err != nil {
		return err
	}
	pairingExpiry, pairingErr := parseCanonicalUTC(value.PairingExpiresAt)
	capabilityExpiry, capabilityErr := parseCanonicalUTC(value.ExpiresAt)
	if pairingErr != nil || capabilityErr != nil || !now.UTC().Before(pairingExpiry) || capabilityExpiry.After(pairingExpiry) {
		return errorf(CodeLeaseRejected, "root helper pairing lifetime is invalid")
	}
	return nil
}

func (issuer *TrustIssuer) signRootHelperCapability(delivery DeliveryV1, domain string, value any) ([]byte, error) {
	if issuer == nil || len(issuer.key) != sha256.Size {
		return nil, errorf(CodeInvalidRequest, "installer issuer is unavailable")
	}
	privateKey, planBytes, err := issuer.derivePrivateKey(delivery.SignedPlan.Plan)
	if err != nil {
		return nil, err
	}
	defer clear(privateKey)
	defer clear(planBytes)
	if !hmac.Equal(privateKey.Public().(ed25519.PublicKey), delivery.PublicKey) {
		return nil, errorf(CodeInvalidSignature, "installer issuer does not own delivery trust")
	}
	payload, err := rootHelperCapabilitySigningBytes(domain, value)
	if err != nil {
		return nil, errorf(CodeInvalidRequest, "canonicalize root helper capability")
	}
	defer clear(payload)
	return ed25519.Sign(privateKey, payload), nil
}

func validateSignedRootHelperCapability(delivery DeliveryV1, domain string, value any, signer string, signature []byte, planDigest, manifestDigest string, now time.Time) error {
	if err := ValidateDeliveryTrust(delivery); err != nil {
		return err
	}
	expectedPlan, expectedManifest, err := rootHelperDeliveryDigests(delivery)
	if err != nil || planDigest != expectedPlan || (manifestDigest != "" && manifestDigest != expectedManifest) ||
		signer != delivery.SignedPlan.SignerKeyID || len(signature) != ed25519.SignatureSize {
		return errorf(CodeInvalidSignature, "root helper capability trust is invalid")
	}
	var issuedRaw, expiresRaw string
	switch typed := value.(type) {
	case RootHelperBootstrapCapabilityV1:
		issuedRaw, expiresRaw = typed.IssuedAt, typed.ExpiresAt
	case RootHelperRestartCapabilityV1:
		issuedRaw, expiresRaw = typed.IssuedAt, typed.ExpiresAt
	case RootHelperPairingCapabilityV1:
		issuedRaw, expiresRaw = typed.IssuedAt, typed.ExpiresAt
	default:
		return errorf(CodeInvalidRequest, "root helper capability type is invalid")
	}
	issuedAt, issuedErr := parseCanonicalUTC(issuedRaw)
	expiresAt, expiresErr := parseCanonicalUTC(expiresRaw)
	current := now.UTC()
	if issuedErr != nil || expiresErr != nil || !issuedAt.Before(expiresAt) ||
		expiresAt.Sub(issuedAt) > maximumRootHelperCapabilityDuration ||
		current.Before(issuedAt) || !current.Before(expiresAt) {
		return errorf(CodeLeaseRejected, "root helper capability lease is invalid")
	}
	payload, err := rootHelperCapabilitySigningBytes(domain, value)
	if err != nil || !ed25519.Verify(ed25519.PublicKey(delivery.PublicKey), payload, signature) {
		clear(payload)
		return errorf(CodeInvalidSignature, "root helper capability signature is invalid")
	}
	clear(payload)
	return nil
}

func rootHelperCapabilitySigningBytes(domain string, value any) ([]byte, error) {
	payload, err := canonical.Marshal(value)
	if err != nil {
		return nil, err
	}
	return append(append([]byte("dirextalk.root-helper."+domain+"\x00"), payload...), 0), nil
}

func rootHelperDeliveryDigests(delivery DeliveryV1) (string, string, error) {
	planDigest, err := canonical.Digest(delivery.SignedPlan.Plan)
	if err != nil {
		return "", "", errorf(CodeInvalidRequest, "digest installer plan")
	}
	manifestDigest, err := canonical.Digest(delivery.ArtifactManifest.Manifest)
	if err != nil {
		return "", "", errorf(CodeInvalidRequest, "digest installer manifest")
	}
	return planDigest, manifestDigest, nil
}

func validateRootHelperLease(now, expiresAt time.Time) (time.Time, time.Time, error) {
	issued := now.UTC()
	expiry := expiresAt.UTC()
	if now.IsZero() || expiresAt.IsZero() || !issued.Before(expiry) || expiry.Sub(issued) > maximumRootHelperCapabilityDuration {
		return time.Time{}, time.Time{}, errorf(CodeLeaseRejected, "root helper capability lease is invalid")
	}
	return issued, expiry, nil
}

func digestBytes(value []byte) string {
	sum := sha256.Sum256(value)
	return digestString(sum)
}

func validRootHelperRestartIdentity(operationID, ownerID, deliveryID, helperID, signerID, instanceID, principalID string) bool {
	operation, operationErr := uuid.Parse(operationID)
	delivery, deliveryErr := uuid.Parse(deliveryID)
	return operationErr == nil && operation != uuid.Nil && operation.String() == operationID &&
		deliveryErr == nil && delivery != uuid.Nil && delivery.String() == deliveryID &&
		strings.TrimSpace(ownerID) == ownerID && ownerID != "" && len(ownerID) <= 255 &&
		!strings.ContainsAny(ownerID, "\x00\r\n") &&
		namePattern.MatchString(helperID) && namePattern.MatchString(signerID) &&
		instanceID != "" && principalID != "" && strings.HasSuffix(principalID, ":"+instanceID) &&
		!strings.ContainsAny(instanceID+principalID, "\x00\r\n")
}
