package installer

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"path"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/cloud/canonical"
	"github.com/google/uuid"
)

var (
	digestPattern    = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	namePattern      = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)
	hostPattern      = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?$`)
	secretRefPattern = regexp.MustCompile(`^secret_ref:[A-Za-z0-9][A-Za-z0-9._/-]{0,127}$`)
)

type ArtifactInspector interface {
	Verify(context.Context, ArtifactV1) error
}

type VerifierConfig struct {
	PublicKey             ed25519.PublicKey
	ExpectedBinding       BindingV1
	TargetRoot            string
	Now                   func() time.Time
	Inspector             ArtifactInspector
	MaxIdempotencyEntries int
}

type idempotencyEntry struct {
	requestDigest string
	response      ResponseV1
	sequence      uint64
}

type Verifier struct {
	publicKey       ed25519.PublicKey
	expectedBinding BindingV1
	targetRoot      string
	now             func() time.Time
	inspector       ArtifactInspector
	maxEntries      int

	mu       sync.Mutex
	sequence uint64
	entries  map[string]idempotencyEntry
}

func NewVerifier(config VerifierConfig) (*Verifier, error) {
	if len(config.PublicKey) != ed25519.PublicKeySize {
		return nil, errorf(CodeInvalidRequest, "approval public key must be Ed25519")
	}
	if err := validateBinding(config.ExpectedBinding); err != nil {
		return nil, err
	}
	root, err := validateTargetRoot(config.TargetRoot)
	if err != nil {
		return nil, err
	}
	if config.Inspector == nil {
		return nil, errorf(CodeInvalidRequest, "artifact inspector is required")
	}
	if config.Now == nil {
		config.Now = time.Now
	}
	if config.MaxIdempotencyEntries <= 0 {
		config.MaxIdempotencyEntries = 1024
	}
	return &Verifier{
		publicKey: append(ed25519.PublicKey(nil), config.PublicKey...), expectedBinding: config.ExpectedBinding,
		targetRoot: root, now: config.Now, inspector: config.Inspector, maxEntries: config.MaxIdempotencyEntries,
		entries: make(map[string]idempotencyEntry),
	}, nil
}

func (v *Verifier) Verify(ctx context.Context, request RequestV1) (ResponseV1, error) {
	if err := validateRequestEnvelope(request); err != nil {
		return ResponseV1{}, err
	}
	if request.Action != ActionVerify {
		return ResponseV1{}, errorf(CodeUnsupportedAction, "action is not permitted")
	}
	if request.Binding != v.expectedBinding {
		return ResponseV1{}, errorf(CodeBindingMismatch, "request does not match daemon binding")
	}
	if request.SignedPlan.SignerKeyID != SignerKeyID(v.publicKey) || len(request.SignedPlan.Signature) != ed25519.SignatureSize {
		return ResponseV1{}, errorf(CodeInvalidSignature, "installer plan signer is not trusted")
	}
	payload, err := PlanSigningBytes(request.SignedPlan.Plan)
	if err != nil || !ed25519.Verify(v.publicKey, payload, request.SignedPlan.Signature) {
		return ResponseV1{}, errorf(CodeInvalidSignature, "installer plan signature verification failed")
	}
	plan := request.SignedPlan.Plan
	if err := validatePlan(plan, v.targetRoot); err != nil {
		return ResponseV1{}, err
	}
	if plan.Binding != v.expectedBinding || plan.Binding != request.Binding {
		return ResponseV1{}, errorf(CodeBindingMismatch, "signed installer plan does not match daemon binding")
	}
	expiresAt, _ := time.Parse(time.RFC3339Nano, plan.ExpiresAt)
	if !v.now().UTC().Before(expiresAt) {
		return ResponseV1{}, errorf(CodePlanExpired, "installer plan has expired")
	}
	artifact, found := findArtifact(plan.Artifacts, request.ArtifactName)
	if !found {
		return ResponseV1{}, errorf(CodeArtifactNotAllowed, "artifact is not declared by the signed plan")
	}
	requestDigest, err := canonical.Digest(request)
	if err != nil {
		return ResponseV1{}, errorf(CodeInvalidRequest, "digest installer request: %v", err)
	}

	// Keep the read-only file verification under the idempotency lock. This
	// guarantees that concurrent replays do not hash the artifact twice.
	v.mu.Lock()
	defer v.mu.Unlock()
	if entry, exists := v.entries[request.IdempotencyKey]; exists {
		if entry.requestDigest != requestDigest {
			return ResponseV1{}, errorf(CodeIdempotencyConflict, "idempotency key is bound to another request")
		}
		response := entry.response
		response.Replayed = true
		return response, nil
	}
	if err := v.inspector.Verify(ctx, artifact); err != nil {
		return ResponseV1{}, &protocolError{code: CodeArtifactVerification, err: err}
	}
	response := ResponseV1{
		SchemaVersion: ResponseSchemaV1, RequestID: request.RequestID, Action: ActionVerify,
		Status: StatusVerified, ArtifactName: artifact.Name, SHA256: artifact.SHA256,
	}
	v.sequence++
	v.entries[request.IdempotencyKey] = idempotencyEntry{requestDigest: requestDigest, response: response, sequence: v.sequence}
	v.evictOldest()
	return response, nil
}

func (v *Verifier) evictOldest() {
	if len(v.entries) <= v.maxEntries {
		return
	}
	var oldestKey string
	oldestSequence := ^uint64(0)
	for key, entry := range v.entries {
		if entry.sequence < oldestSequence {
			oldestKey, oldestSequence = key, entry.sequence
		}
	}
	delete(v.entries, oldestKey)
}

func validateRequestEnvelope(request RequestV1) error {
	if request.SchemaVersion != RequestSchemaV1 {
		return errorf(CodeInvalidRequest, "unsupported installer request schema")
	}
	for name, value := range map[string]string{
		"request_id": request.RequestID, "idempotency_key": request.IdempotencyKey,
	} {
		parsed, err := uuid.Parse(value)
		if err != nil || parsed.String() != value {
			return errorf(CodeInvalidRequest, "%s must be a canonical UUID", name)
		}
	}
	if len(request.Action) == 0 || len(request.Action) > 64 || !namePattern.MatchString(request.ArtifactName) {
		return errorf(CodeInvalidRequest, "invalid action or artifact name")
	}
	if err := validateBinding(request.Binding); err != nil {
		return err
	}
	return nil
}

func validatePlan(plan InstallerPlanV1, targetRoot string) error {
	if plan.SchemaVersion != PlanSchemaV1 || len(plan.Artifacts) == 0 || len(plan.Artifacts) > 128 ||
		len(plan.SecretRefs) > 128 || len(plan.Ports) > 128 || len(plan.Volumes) > 128 {
		return errorf(CodeInvalidRequest, "invalid installer plan schema or declaration count")
	}
	if err := validateBinding(plan.Binding); err != nil {
		return err
	}
	expiresAt, err := time.Parse(time.RFC3339Nano, plan.ExpiresAt)
	if err != nil || expiresAt.Location() != time.UTC || expiresAt.Format(time.RFC3339Nano) != plan.ExpiresAt {
		return errorf(CodeInvalidRequest, "expires_at must be canonical UTC RFC3339Nano")
	}
	seenArtifacts := make(map[string]struct{}, len(plan.Artifacts))
	for _, artifact := range plan.Artifacts {
		if !namePattern.MatchString(artifact.Name) || !digestPattern.MatchString(artifact.SHA256) || artifact.SizeBytes < 0 {
			return errorf(CodeInvalidRequest, "invalid artifact declaration")
		}
		if _, exists := seenArtifacts[artifact.Name]; exists {
			return errorf(CodeInvalidRequest, "duplicate artifact name")
		}
		seenArtifacts[artifact.Name] = struct{}{}
		if err := validateArtifactPath(targetRoot, artifact.TargetPath); err != nil {
			return err
		}
	}
	if err := validateSecrets(plan.SecretRefs); err != nil {
		return err
	}
	if err := validateNetwork(plan.Network); err != nil {
		return err
	}
	if err := validatePorts(plan.Network, plan.Ports); err != nil {
		return err
	}
	if err := validateVolumes(plan.Volumes); err != nil {
		return err
	}
	return nil
}

func validateBinding(binding BindingV1) error {
	if !digestPattern.MatchString(binding.PlanHash) || !digestPattern.MatchString(binding.RecipeDigest) || binding.LeaseEpoch < 1 {
		return errorf(CodeInvalidRequest, "invalid installer binding")
	}
	for name, value := range map[string]string{
		"agent_instance_id": binding.AgentInstanceID, "deployment_id": binding.DeploymentID,
		"task_id": binding.TaskID, "approval_id": binding.ApprovalID,
	} {
		parsed, err := uuid.Parse(value)
		if err != nil || parsed.String() != value {
			return errorf(CodeInvalidRequest, "%s must be a canonical UUID", name)
		}
	}
	return nil
}

func validateTargetRoot(value string) (string, error) {
	if value == "" || !path.IsAbs(value) || path.Clean(value) != value || value == "/" {
		return "", errorf(CodeInvalidPath, "target root must be a clean absolute POSIX path")
	}
	return value, nil
}

func validateArtifactPath(root, target string) error {
	if target == "" || !path.IsAbs(target) || path.Clean(target) != target || target == root {
		return errorf(CodeInvalidPath, "artifact target must be a clean absolute POSIX file path")
	}
	prefix := strings.TrimSuffix(root, "/") + "/"
	if !strings.HasPrefix(target, prefix) {
		return errorf(CodeInvalidPath, "artifact target is outside the approved root")
	}
	return nil
}

func validateSecrets(values []string) error {
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		if !secretRefPattern.MatchString(value) {
			return errorf(CodeInvalidRequest, "invalid secret reference")
		}
		if _, exists := seen[value]; exists {
			return errorf(CodeInvalidRequest, "duplicate secret reference")
		}
		seen[value] = struct{}{}
	}
	return nil
}

func validateNetwork(network NetworkV1) error {
	if len(network.OutboundHTTPSHosts) > 128 {
		return errorf(CodeInvalidRequest, "too many outbound hosts")
	}
	if !slices.IsSorted(network.OutboundHTTPSHosts) {
		return errorf(CodeInvalidRequest, "outbound HTTPS hosts must be sorted")
	}
	previous := ""
	for _, host := range network.OutboundHTTPSHosts {
		if host != strings.ToLower(host) || !hostPattern.MatchString(host) || host == previous || strings.Contains(host, "..") {
			return errorf(CodeInvalidRequest, "invalid or duplicate outbound HTTPS host")
		}
		previous = host
	}
	return nil
}

func validatePorts(network NetworkV1, ports []PortV1) error {
	seen := make(map[string]struct{}, len(ports))
	for _, port := range ports {
		if !namePattern.MatchString(port.Name) || (port.Protocol != "tcp" && port.Protocol != "udp") ||
			(port.Direction != "loopback" && port.Direction != "inbound" && port.Direction != "outbound") || port.Port < 1 || port.Port > 65535 {
			return errorf(CodeInvalidRequest, "invalid port declaration")
		}
		if port.Direction == "inbound" && !network.PublicInbound {
			return errorf(CodeInvalidRequest, "public inbound port was not approved")
		}
		key := fmt.Sprintf("%s/%s/%d", port.Direction, port.Protocol, port.Port)
		if _, exists := seen[key]; exists {
			return errorf(CodeInvalidRequest, "duplicate port declaration")
		}
		seen[key] = struct{}{}
	}
	return nil
}

func validateVolumes(volumes []VolumeV1) error {
	seen := make(map[string]struct{}, len(volumes))
	for _, volume := range volumes {
		if !namePattern.MatchString(volume.Name) || volume.SizeGiB < 1 || !path.IsAbs(volume.MountPath) ||
			path.Clean(volume.MountPath) != volume.MountPath || volume.MountPath == "/" {
			return errorf(CodeInvalidRequest, "invalid volume declaration")
		}
		if _, exists := seen[volume.Name]; exists {
			return errorf(CodeInvalidRequest, "duplicate volume declaration")
		}
		seen[volume.Name] = struct{}{}
	}
	return nil
}

func findArtifact(artifacts []ArtifactV1, name string) (ArtifactV1, bool) {
	for _, artifact := range artifacts {
		if artifact.Name == name {
			return artifact, true
		}
	}
	return ArtifactV1{}, false
}

func parseDigest(value string) ([sha256.Size]byte, error) {
	var result [sha256.Size]byte
	if !digestPattern.MatchString(value) {
		return result, errorf(CodeArtifactVerification, "invalid SHA-256 digest")
	}
	decoded, err := hex.DecodeString(strings.TrimPrefix(value, "sha256:"))
	if err != nil || len(decoded) != sha256.Size {
		return result, errorf(CodeArtifactVerification, "invalid SHA-256 digest")
	}
	copy(result[:], decoded)
	return result, nil
}
