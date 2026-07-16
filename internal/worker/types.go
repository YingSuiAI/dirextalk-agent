package worker

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/idempotency"
	"github.com/YingSuiAI/dirextalk-agent/internal/installer"
	"github.com/YingSuiAI/dirextalk-agent/internal/security"
	"github.com/google/uuid"
)

var (
	ErrInvalid                   = errors.New("invalid worker request")
	ErrNotFound                  = errors.New("worker deployment not found")
	ErrAlreadyExists             = errors.New("worker deployment already exists")
	ErrInvalidCredential         = errors.New("invalid worker credential")
	ErrEnrollmentConsumed        = errors.New("worker enrollment is already consumed")
	ErrEnrollmentExpired         = errors.New("worker enrollment is expired")
	ErrLeaseActive               = errors.New("worker lease is still active")
	ErrStaleLease                = errors.New("worker lease epoch is stale")
	ErrLeaseExpired              = errors.New("worker lease is expired")
	ErrCancellationRequested     = errors.New("worker cancellation is requested")
	ErrTerminal                  = errors.New("worker deployment is terminal")
	ErrRevisionConflict          = errors.New("worker deployment revision conflict")
	ErrIdentityChallengeExpired  = errors.New("worker identity challenge is expired")
	ErrIdentityChallengeConsumed = errors.New("worker identity challenge is consumed")
	ErrIdentityRejected          = errors.New("worker provider identity is rejected")
	ErrIdentityUnavailable       = errors.New("worker provider identity is not ready")
	ErrInstallerTrustUnavailable = errors.New("worker installer trust issuer is unavailable")
	ErrIdempotencyConflict       = idempotency.ErrConflict
)

type State string

const (
	StatePendingEnrollment State = "pending_enrollment"
	StateReady             State = "ready"
	StateLeased            State = "leased"
	StateCancelRequested   State = "cancel_requested"
	StateFinished          State = "finished"
)

type Outcome string

const (
	OutcomePending     Outcome = "pending"
	OutcomeSucceeded   Outcome = "succeeded"
	OutcomeFailed      Outcome = "failed"
	OutcomeCanceled    Outcome = "canceled"
	OutcomeTimedOut    Outcome = "timed_out"
	OutcomeInterrupted Outcome = "interrupted"
)

type EvidenceTrust string

const (
	// TrustWorkerClaim is deliberately explicit: a root-capable Worker can
	// forge its local files and logs, so these references are never readiness
	// evidence by themselves.
	TrustWorkerClaim EvidenceTrust = "untrusted_worker_claim"
)

type AccessScope struct {
	ArtifactPrefix   string
	CheckpointPrefix string
	EvidencePrefix   string
	LogPrefix        string
	SecretRefs       []string
}

func (scope AccessScope) Validate() error {
	for name, value := range map[string]string{
		"artifact_prefix": scope.ArtifactPrefix, "checkpoint_prefix": scope.CheckpointPrefix,
		"evidence_prefix": scope.EvidencePrefix,
	} {
		if err := validateS3Prefix(name, value); err != nil {
			return err
		}
	}
	if err := validateCloudWatchPrefix(scope.LogPrefix); err != nil {
		return err
	}
	if len(scope.SecretRefs) > 128 {
		return fmt.Errorf("%w: too many declared secret references", ErrInvalid)
	}
	seen := make(map[string]struct{}, len(scope.SecretRefs))
	for _, raw := range scope.SecretRefs {
		ref := strings.TrimSpace(raw)
		if ref == "" || len(ref) > 1024 || strings.ContainsAny(ref, "*?#") || security.ContainsLikelySecret(ref) {
			return fmt.Errorf("%w: invalid declared secret reference", ErrInvalid)
		}
		parsed, err := url.Parse(ref)
		if err != nil || parsed.Scheme != "secret" || parsed.Host == "" || parsed.Path == "" || parsed.User != nil {
			return fmt.Errorf("%w: secret references must use secret://<store>/<path>", ErrInvalid)
		}
		if _, duplicate := seen[ref]; duplicate {
			return fmt.Errorf("%w: duplicate declared secret reference", ErrInvalid)
		}
		seen[ref] = struct{}{}
	}
	return nil
}

func (scope AccessScope) permitsS3(ref, prefix string) bool {
	return hasScopedPrefix(ref, prefix, "s3")
}

func (scope AccessScope) permitsLog(ref string) bool {
	return strings.HasPrefix(ref, strings.TrimSuffix(scope.LogPrefix, "/")+"/") && !security.ContainsLikelySecret(ref)
}

type Enrollment struct {
	CredentialDigest [sha256.Size]byte
	ExpiresAt        time.Time
	ConsumedAt       time.Time
}

type Lease struct {
	Attempt         int32
	Epoch           int64
	ExpiresAt       time.Time
	LastHeartbeatAt time.Time
	CheckpointRef   string
}

type EvidenceRef struct {
	Kind         string
	Ref          string
	ObjectSHA256 string
	SizeBytes    int64
	MediaType    string
	Trust        EvidenceTrust
	Attempt      int32
	LeaseEpoch   int64
	RecordedAt   time.Time
}

const MaximumObjectClaimBytes int64 = 8 << 20

// ObjectClaim binds a deployment-scoped S3 reference to the exact bytes a
// Worker uploaded. The bytes themselves never enter gRPC, events, or the Agent
// database, and the claim remains untrusted Worker-local evidence.
type ObjectClaim struct {
	Ref       string
	SHA256    [sha256.Size]byte
	SizeBytes int64
	MediaType string
}

func (claim ObjectClaim) Validate() error {
	trimmedRef := strings.TrimSpace(claim.Ref)
	parsed, err := url.Parse(trimmedRef)
	if err != nil || parsed.Scheme != "s3" || parsed.Host == "" || parsed.Path == "" || strings.HasSuffix(parsed.Path, "/") ||
		parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || len(claim.Ref) > 2048 || strings.ContainsAny(claim.Ref, "*?#") ||
		claim.Ref != trimmedRef || security.ContainsLikelySecret(claim.Ref) {
		return fmt.Errorf("%w: Worker object reference is invalid", ErrInvalid)
	}
	var empty [sha256.Size]byte
	if claim.SHA256 == empty || claim.SizeBytes < 1 || claim.SizeBytes > MaximumObjectClaimBytes {
		return fmt.Errorf("%w: Worker object digest or size is invalid", ErrInvalid)
	}
	switch claim.MediaType {
	case "application/json", "application/cbor", "application/octet-stream", "text/plain; charset=utf-8":
	default:
		return fmt.Errorf("%w: Worker object media type is invalid", ErrInvalid)
	}
	if security.ContainsLikelySecret(claim.MediaType) {
		return fmt.Errorf("%w: Worker object media type contains forbidden data", ErrInvalid)
	}
	return nil
}

func (claim ObjectClaim) Digest() string {
	var empty [sha256.Size]byte
	if claim.SHA256 == empty {
		return ""
	}
	return "sha256:" + hex.EncodeToString(claim.SHA256[:])
}

type Deployment struct {
	DeploymentID         string
	OwnerID              string
	TaskID               string
	StepID               string
	ControlPlaneEndpoint string
	RecipeBundle         BundleRef
	ExecutionBundle      BundleRef
	ExecutionTimeout     time.Duration
	InstallerDelivery    *installer.DeliveryV1
	InstallerCommandIDs  []string
	WorkerID             string
	ProviderInstanceID   string
	State                State
	Outcome              Outcome
	Access               AccessScope
	Enrollment           Enrollment
	SessionDigest        [sha256.Size]byte
	Lease                Lease
	ResultRef            string
	Evidence             []EvidenceRef
	CancelReason         string
	Revision             int64
	CreatedAt            time.Time
	UpdatedAt            time.Time
}

func (deployment Deployment) clone() Deployment {
	deployment.Access.SecretRefs = slices.Clone(deployment.Access.SecretRefs)
	deployment.Evidence = slices.Clone(deployment.Evidence)
	deployment.InstallerDelivery = cloneInstallerDelivery(deployment.InstallerDelivery)
	deployment.InstallerCommandIDs = slices.Clone(deployment.InstallerCommandIDs)
	return deployment
}

type Assignment struct {
	DeploymentID          string
	OwnerID               string
	TaskID                string
	StepID                string
	ControlPlaneEndpoint  string
	RecipeBundle          BundleRef
	ExecutionBundle       BundleRef
	ExecutionTimeout      time.Duration
	InstallerLeaseGrants  []installer.SignedLeaseGrantV1
	WorkerID              string
	Attempt               int32
	LeaseEpoch            int64
	LeaseExpiresAt        time.Time
	CheckpointRef         string
	CheckpointAttempt     int32
	CheckpointLeaseEpoch  int64
	Access                AccessScope
	CancellationRequested bool
	Revision              int64
}

type Heartbeat struct {
	LeaseEpoch            int64
	LeaseExpiresAt        time.Time
	InstallerLeaseGrants  []installer.SignedLeaseGrantV1
	CancellationRequested bool
	CheckpointRef         string
	Revision              int64
}

// Credential deliberately does not implement a plaintext String method. The
// caller receives a copy only through Reveal and should call Destroy promptly.
// Its formatted representation is always redacted.
type Credential struct{ value []byte }

func newCredential(value []byte) Credential { return Credential{value: slices.Clone(value)} }

func (credential Credential) Reveal() []byte { return slices.Clone(credential.value) }

func (credential *Credential) Destroy() {
	if credential == nil {
		return
	}
	for index := range credential.value {
		credential.value[index] = 0
	}
	credential.value = nil
}

func (Credential) String() string   { return "[redacted-worker-credential]" }
func (Credential) GoString() string { return "worker.Credential{[redacted]}" }

type CreateDeploymentRequest struct {
	DeploymentID         string
	OwnerID              string
	TaskID               string
	StepID               string
	ControlPlaneEndpoint string
	RecipeBundle         BundleRef
	ExecutionBundle      BundleRef
	ExecutionTimeout     time.Duration
	InstallerDelivery    *installer.DeliveryV1
	InstallerCommandIDs  []string
	Access               AccessScope
	EnrollmentTTL        time.Duration
}

type CreateIdentityChallengeRequest struct {
	DeploymentID     string
	WorkerID         string
	IdempotencyKey   string
	ExpectedRevision int64
}

type IdentityChallenge struct {
	ChallengeID                string
	DeploymentID               string
	WorkerID                   string
	OwnerID                    string
	AccountID                  string
	Region                     string
	ExpectedProviderInstanceID string
	ExpectedRevision           int64
	RequestHash                [sha256.Size]byte
	ExpiresAt                  time.Time
	ConsumedAt                 time.Time
	Revision                   int64
	CreatedAt                  time.Time
}

// IdentityMaterialization contains the immutable inputs and write scopes
// copied by the control plane into the AWS principal-specific Worker prefix.
// The external copy may leave harmless orphan objects after a crash; binding
// these references to a deployment happens atomically with identity enrollment.
type IdentityMaterialization struct {
	RecipeBundle    BundleRef
	ExecutionBundle BundleRef
	Access          AccessScope
}

func (materialization IdentityMaterialization) Validate(principalID, deploymentID string) error {
	if err := validatePrincipalID(principalID, ""); err != nil {
		return err
	}
	if err := validateUUID("deployment_id", deploymentID); err != nil {
		return err
	}
	if err := materialization.RecipeBundle.Validate(); err != nil {
		return err
	}
	if err := materialization.ExecutionBundle.Validate(); err != nil {
		return err
	}
	if err := materialization.Access.Validate(); err != nil {
		return err
	}

	basePath := "/workers/" + principalID + "/" + strings.TrimSpace(deploymentID) + "/"
	bucket := ""
	for _, reference := range []string{
		materialization.RecipeBundle.S3Ref,
		materialization.ExecutionBundle.S3Ref,
		materialization.Access.ArtifactPrefix,
		materialization.Access.CheckpointPrefix,
		materialization.Access.EvidencePrefix,
	} {
		parsed, err := url.Parse(strings.TrimSpace(reference))
		if err != nil || parsed.Scheme != "s3" || parsed.Host == "" || !strings.HasPrefix(parsed.Path, basePath) {
			return fmt.Errorf("%w: identity material must use its verified Worker principal prefix", ErrInvalid)
		}
		if bucket == "" {
			bucket = parsed.Host
		} else if parsed.Host != bucket {
			return fmt.Errorf("%w: identity material must use one Worker artifact bucket", ErrInvalid)
		}
	}
	return nil
}

// BundleRef binds an S3 object to the exact bytes approved by the control
// plane. Workers must verify SHA256 before parsing either bundle.
type BundleRef struct {
	S3Ref  string
	SHA256 [sha256.Size]byte
}

func (reference BundleRef) Validate() error {
	parsed, err := url.Parse(strings.TrimSpace(reference.S3Ref))
	if err != nil || parsed.Scheme != "s3" || parsed.Host == "" || parsed.Path == "" || strings.HasSuffix(parsed.Path, "/") || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return fmt.Errorf("%w: bundle_ref must identify one s3 object", ErrInvalid)
	}
	if len(reference.S3Ref) > 2048 || strings.ContainsAny(reference.S3Ref, "*?#") || security.ContainsLikelySecret(reference.S3Ref) {
		return fmt.Errorf("%w: bundle_ref contains forbidden data", ErrInvalid)
	}
	var empty [sha256.Size]byte
	if reference.SHA256 == empty {
		return fmt.Errorf("%w: bundle sha256 is required", ErrInvalid)
	}
	return nil
}

type EnrollRequest struct {
	DeploymentID     string
	WorkerID         string
	IdempotencyKey   string
	ExpectedRevision int64
	Credential       []byte
}

type AuthenticatedRequest struct {
	DeploymentID     string
	WorkerID         string
	IdempotencyKey   string
	ExpectedRevision int64
	Credential       []byte
}

// SessionRequest is a read-only, session-authenticated lookup. It deliberately
// has no idempotency key or expected revision because it returns the current
// durable fence that a restarted Worker must use for its next Claim.
type SessionRequest struct {
	DeploymentID string
	WorkerID     string
	Credential   []byte
}

type LeasedRequest struct {
	AuthenticatedRequest
	LeaseEpoch int64
}

type CompleteRequest struct {
	LeasedRequest
	Outcome      Outcome
	ResultRef    string
	ResultObject *ObjectClaim
}

func validateCreate(request CreateDeploymentRequest) error {
	for name, value := range map[string]string{"deployment_id": request.DeploymentID, "task_id": request.TaskID, "step_id": request.StepID} {
		parsed, err := uuid.Parse(strings.TrimSpace(value))
		if err != nil || parsed == uuid.Nil {
			return fmt.Errorf("%w: %s must be a non-zero UUID", ErrInvalid, name)
		}
	}
	owner := strings.TrimSpace(request.OwnerID)
	if owner == "" || len(owner) > 255 || security.ContainsLikelySecret(owner) {
		return fmt.Errorf("%w: owner_id is invalid", ErrInvalid)
	}
	if request.EnrollmentTTL <= 0 || request.EnrollmentTTL > 30*time.Minute {
		return fmt.Errorf("%w: enrollment ttl must be within 30 minutes", ErrInvalid)
	}
	if err := request.RecipeBundle.Validate(); err != nil {
		return err
	}
	if err := request.ExecutionBundle.Validate(); err != nil {
		return err
	}
	if request.ExecutionTimeout < time.Second || request.ExecutionTimeout > 7*24*time.Hour || request.ExecutionTimeout%time.Second != 0 {
		return fmt.Errorf("%w: execution timeout must be between one second and seven days", ErrInvalid)
	}
	if err := ValidateInstallerCapability(request.DeploymentID, request.TaskID, request.RecipeBundle, request.InstallerDelivery, request.InstallerCommandIDs); err != nil {
		return err
	}
	endpoint, err := url.Parse(strings.TrimSpace(request.ControlPlaneEndpoint))
	if err != nil || endpoint.Scheme != "grpcs" || endpoint.Host == "" || endpoint.User != nil || endpoint.RawQuery != "" || endpoint.Fragment != "" || security.ContainsLikelySecret(request.ControlPlaneEndpoint) {
		return fmt.Errorf("%w: control_plane_endpoint must be credential-free outbound grpcs", ErrInvalid)
	}
	return request.Access.Validate()
}

func ValidateInstallerCapability(deploymentID, taskID string, recipeBundle BundleRef, delivery *installer.DeliveryV1, commandIDs []string) error {
	if delivery == nil {
		if len(commandIDs) != 0 {
			return fmt.Errorf("%w: installer command selectors require a stable delivery", ErrInvalid)
		}
		return nil
	}
	if len(commandIDs) == 0 || len(commandIDs) > 128 {
		return fmt.Errorf("%w: installer delivery requires command selectors", ErrInvalid)
	}
	expiresAt, err := time.Parse(time.RFC3339Nano, delivery.SignedPlan.Plan.ExpiresAt)
	if err != nil || installer.ValidateDeliveryAt(*delivery, expiresAt.Add(-time.Nanosecond)) != nil {
		return fmt.Errorf("%w: installer delivery is invalid", ErrInvalid)
	}
	binding := delivery.Config.Binding
	if binding.DeploymentID != strings.TrimSpace(deploymentID) || binding.TaskID != strings.TrimSpace(taskID) ||
		binding.RecipeDigest != "sha256:"+hex.EncodeToString(recipeBundle.SHA256[:]) {
		return fmt.Errorf("%w: installer delivery binding does not match deployment", ErrInvalid)
	}
	declared := make(map[string]struct{}, len(delivery.SignedPlan.Plan.Commands))
	for _, command := range delivery.SignedPlan.Plan.Commands {
		declared[command.CommandID] = struct{}{}
	}
	seen := make(map[string]struct{}, len(commandIDs))
	for _, commandID := range commandIDs {
		if _, ok := declared[commandID]; !ok {
			return fmt.Errorf("%w: installer command selector is undeclared", ErrInvalid)
		}
		if _, duplicate := seen[commandID]; duplicate {
			return fmt.Errorf("%w: installer command selector is duplicated", ErrInvalid)
		}
		seen[commandID] = struct{}{}
	}
	return nil
}

func cloneInstallerDelivery(value *installer.DeliveryV1) *installer.DeliveryV1 {
	if value == nil {
		return nil
	}
	encoded, err := json.Marshal(value)
	if err != nil {
		return nil
	}
	var cloned installer.DeliveryV1
	if json.Unmarshal(encoded, &cloned) != nil {
		return nil
	}
	return &cloned
}

func validateIdentity(deploymentID, workerID string, credential []byte) error {
	for name, value := range map[string]string{"deployment_id": deploymentID, "worker_id": workerID} {
		parsed, err := uuid.Parse(strings.TrimSpace(value))
		if err != nil || parsed == uuid.Nil {
			return fmt.Errorf("%w: %s must be a non-zero UUID", ErrInvalid, name)
		}
	}
	if len(credential) < 32 || len(credential) > 128 {
		return ErrInvalidCredential
	}
	return nil
}

func validateIdempotencyKey(value string) error {
	parsed, err := uuid.Parse(strings.TrimSpace(value))
	if err != nil || parsed == uuid.Nil {
		return fmt.Errorf("%w: idempotency_key must be a non-zero UUID", ErrInvalid)
	}
	return nil
}

func validateExpectedRevision(value int64) error {
	if value < 1 {
		return fmt.Errorf("%w: expected_revision must be positive", ErrInvalid)
	}
	return nil
}

func validateS3Prefix(name, value string) error {
	parsed, err := url.Parse(strings.TrimSpace(value))
	if err != nil || parsed.Scheme != "s3" || parsed.Host == "" || parsed.Path == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || !strings.HasSuffix(parsed.Path, "/") {
		return fmt.Errorf("%w: %s must be an s3 bucket prefix ending in /", ErrInvalid, name)
	}
	if strings.ContainsAny(value, "*?#") || security.ContainsLikelySecret(value) {
		return fmt.Errorf("%w: %s contains forbidden data", ErrInvalid, name)
	}
	return nil
}

func validateCloudWatchPrefix(value string) error {
	parsed, err := url.Parse(strings.TrimSpace(value))
	if err != nil || parsed.Scheme != "cloudwatch" || parsed.Host == "" || parsed.Path == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || strings.HasSuffix(parsed.Path, "/") {
		return fmt.Errorf("%w: log_prefix must be cloudwatch://<group>/<stream-prefix>", ErrInvalid)
	}
	if strings.Contains(value, "*") || security.ContainsLikelySecret(value) {
		return fmt.Errorf("%w: log_prefix contains forbidden data", ErrInvalid)
	}
	return nil
}

func hasScopedPrefix(ref, prefix, scheme string) bool {
	if security.ContainsLikelySecret(ref) || len(ref) > 2048 {
		return false
	}
	parsed, err := url.Parse(strings.TrimSpace(ref))
	if err != nil || parsed.Scheme != scheme || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return false
	}
	return strings.HasPrefix(ref, prefix) && len(ref) > len(prefix)
}

func validatePrincipalID(principalID, instanceID string) error {
	parts := strings.Split(strings.TrimSpace(principalID), ":")
	if len(parts) != 2 || len(parts[0]) < 16 || len(parts[0]) > 128 || parts[1] == "" ||
		(instanceID != "" && parts[1] != strings.TrimSpace(instanceID)) {
		return fmt.Errorf("%w: invalid verified Worker principal", ErrIdentityRejected)
	}
	for _, value := range parts[0] {
		if (value < 'A' || value > 'Z') && (value < '0' || value > '9') {
			return fmt.Errorf("%w: invalid verified Worker principal", ErrIdentityRejected)
		}
	}
	if len(parts[1]) < 10 || len(parts[1]) > 19 || !strings.HasPrefix(parts[1], "i-") {
		return fmt.Errorf("%w: invalid verified Worker principal", ErrIdentityRejected)
	}
	for _, value := range parts[1][2:] {
		if (value < '0' || value > '9') && (value < 'a' || value > 'f') {
			return fmt.Errorf("%w: invalid verified Worker principal", ErrIdentityRejected)
		}
	}
	return nil
}
