package installer

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"path"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/cloud/canonical"
	"github.com/YingSuiAI/dirextalk-agent/internal/security"
	"github.com/google/uuid"
)

var (
	digestPattern       = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	namePattern         = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)
	hostPattern         = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?$`)
	secretRefPattern    = regexp.MustCompile(`^secret_ref:[A-Za-z0-9][A-Za-z0-9._/-]{0,127}$`)
	executablePattern   = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+-]{0,127}$`)
	volumeDevicePattern = regexp.MustCompile(`^/dev/sd[f-p]$`)
	volumeMountPattern  = regexp.MustCompile(`^/[A-Za-z0-9._/-]+$`)
)

type ArtifactInspector interface {
	Verify(context.Context, ArtifactV1) error
}

type VerifierConfig struct {
	PublicKey             ed25519.PublicKey
	ExpectedTrustID       string
	ExpectedBinding       BindingV1
	TargetRoot            string
	Now                   func() time.Time
	Inspector             ArtifactInspector
	Runner                CommandRunner
	Journal               ExecutionJournal
	MaxIdempotencyEntries int
}

type idempotencyEntry struct {
	requestDigest string
	response      ResponseV1
	sequence      uint64
}

type Verifier struct {
	publicKey       ed25519.PublicKey
	expectedTrustID string
	expectedBinding BindingV1
	targetRoot      string
	now             func() time.Time
	inspector       ArtifactInspector
	runner          CommandRunner
	journal         ExecutionJournal
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
	if config.ExpectedTrustID != "" && !digestPattern.MatchString(config.ExpectedTrustID) {
		return nil, errorf(CodeInvalidRequest, "expected installer trust ID is invalid")
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
		publicKey: append(ed25519.PublicKey(nil), config.PublicKey...), expectedTrustID: config.ExpectedTrustID, expectedBinding: config.ExpectedBinding,
		targetRoot: root, now: config.Now, inspector: config.Inspector, maxEntries: config.MaxIdempotencyEntries,
		runner: config.Runner, journal: config.Journal,
		entries: make(map[string]idempotencyEntry),
	}, nil
}

func (v *Verifier) Verify(ctx context.Context, request RequestV1) (ResponseV1, error) {
	if err := validateRequestEnvelope(request); err != nil {
		return ResponseV1{}, err
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
	switch request.Action {
	case ActionVerify:
		requestDigest, err := canonical.Digest(request)
		if err != nil {
			return ResponseV1{}, errorf(CodeInvalidRequest, "digest installer request: %v", err)
		}
		return v.verifyArtifact(ctx, request, plan, requestDigest)
	case ActionExecute:
		leaseExpiresAt, leaseEpoch, err := v.validateExecutionLease(request)
		if err != nil {
			return ResponseV1{}, err
		}
		operationDigest, err := executionOperationDigest(request)
		if err != nil {
			return ResponseV1{}, err
		}
		return v.executeCommand(ctx, request, plan, operationDigest, leaseEpoch, leaseExpiresAt)
	default:
		return ResponseV1{}, errorf(CodeUnsupportedAction, "action is not permitted")
	}
}

func (v *Verifier) verifyArtifact(ctx context.Context, request RequestV1, plan InstallerPlanV1, requestDigest string) (ResponseV1, error) {
	expiresAt, _ := time.Parse(time.RFC3339Nano, plan.ExpiresAt)
	if !v.now().UTC().Before(expiresAt) {
		return ResponseV1{}, errorf(CodePlanExpired, "installer plan has expired")
	}
	artifact, found := findArtifact(plan.Artifacts, request.ArtifactName)
	if !found {
		return ResponseV1{}, errorf(CodeArtifactNotAllowed, "artifact is not declared by the signed plan")
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

func (v *Verifier) executeCommand(ctx context.Context, request RequestV1, plan InstallerPlanV1, requestDigest string, leaseEpoch int64, leaseExpiresAt time.Time) (ResponseV1, error) {
	if v.runner == nil || v.journal == nil {
		return ResponseV1{}, errorf(CodeUnsupportedAction, "privileged execution is disabled")
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	if err := v.journal.FenceLease(leaseEpoch); err != nil {
		return ResponseV1{}, err
	}
	if response, found, err := v.journal.Lookup(request.IdempotencyKey, requestDigest); err != nil {
		return ResponseV1{}, err
	} else if found {
		return response, nil
	}
	expiresAt, _ := time.Parse(time.RFC3339Nano, plan.ExpiresAt)
	if now := v.now().UTC(); !now.Before(expiresAt) || !now.Before(leaseExpiresAt) {
		return ResponseV1{}, errorf(CodePlanExpired, "installer plan has expired")
	}
	command, found := findCommand(plan.Commands, request.CommandID)
	if !found {
		return ResponseV1{}, errorf(CodeCommandNotAllowed, "command is not declared by the signed plan")
	}
	for _, artifactName := range command.ArtifactRefs {
		artifact, exists := findArtifact(plan.Artifacts, artifactName)
		if !exists {
			return ResponseV1{}, errorf(CodeArtifactNotAllowed, "command artifact is not declared by the signed plan")
		}
		if err := v.inspector.Verify(ctx, artifact); err != nil {
			return ResponseV1{}, &protocolError{code: CodeArtifactVerification, err: err}
		}
	}
	if now := v.now().UTC(); !now.Before(expiresAt) || !now.Before(leaseExpiresAt) {
		return ResponseV1{}, errorf(CodePlanExpired, "installer plan expired during artifact verification")
	}
	base := ResponseV1{
		SchemaVersion: ResponseSchemaV1, RequestID: request.RequestID,
		Action: ActionExecute, CommandID: command.CommandID,
	}
	if response, replayed, err := v.journal.Begin(request.IdempotencyKey, requestDigest, base); err != nil {
		return ResponseV1{}, err
	} else if replayed {
		return response, nil
	}
	timeout := time.Duration(command.TimeoutSeconds) * time.Second
	now := v.now().UTC()
	remaining := min(expiresAt.Sub(now), leaseExpiresAt.Sub(now))
	if remaining <= 0 {
		return ResponseV1{}, errorf(CodePlanExpired, "installer lease expired before execution")
	}
	runTimeout := min(timeout, remaining)
	runCtx, cancel := context.WithTimeout(ctx, runTimeout)
	execution := CommandExecution{
		Argv: append([]string(nil), command.Argv...), WorkingDirectory: command.WorkingDirectory,
		Environment: []string{SafePathEnvironment}, Timeout: runTimeout,
	}
	runErr := v.runner.Run(runCtx, execution)
	runState := runCtx.Err()
	cancel()
	response := base
	switch {
	case ctx.Err() != nil:
		response.Status = StatusInterrupted
		response.ErrorCode = CodeExecutionInterrupted
	case runState == context.DeadlineExceeded:
		response.Status = StatusFailed
		response.ErrorCode = CodeExecutionTimedOut
	case runErr == nil:
		response.Status = StatusExecuted
	default:
		response.Status = StatusFailed
		response.ErrorCode = CodeExecutionFailed
	}
	if err := v.journal.Complete(request.IdempotencyKey, requestDigest, response); err != nil {
		return ResponseV1{}, err
	}
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
	if len(request.Action) == 0 || len(request.Action) > 64 {
		return errorf(CodeInvalidRequest, "invalid action")
	}
	switch request.Action {
	case ActionVerify:
		if !namePattern.MatchString(request.ArtifactName) || request.CommandID != "" || request.OperationID != "" || request.LeaseGrant != nil {
			return errorf(CodeInvalidRequest, "verify requires only an artifact name")
		}
	case ActionExecute:
		operationID, err := uuid.Parse(request.OperationID)
		if request.ArtifactName != "" || !namePattern.MatchString(request.CommandID) || err != nil || operationID.String() != request.OperationID || request.LeaseGrant == nil {
			return errorf(CodeInvalidRequest, "execute requires a command operation and lease grant")
		}
	}
	if err := validateBinding(request.Binding); err != nil {
		return err
	}
	return nil
}

func validatePlan(plan InstallerPlanV1, targetRoot string) error {
	if plan.SchemaVersion != PlanSchemaV1 || len(plan.Artifacts) == 0 || len(plan.Artifacts) > 128 ||
		len(plan.SecretRefs) > 128 || len(plan.Secrets) > 32 || len(plan.Ports) > 128 || len(plan.Volumes) > 128 || len(plan.Commands) > 128 {
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
	if err := validateSecretDeclarations(plan); err != nil {
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
	if err := validateCommands(plan); err != nil {
		return err
	}
	return nil
}

func validateSecretDeclarations(plan InstallerPlanV1) error {
	if len(plan.Secrets) != len(plan.SecretRefs) {
		return errorf(CodeInvalidRequest, "installer secret declarations do not match references")
	}
	seenSlots := make(map[string]struct{}, len(plan.Secrets))
	seenRefs := make(map[string]struct{}, len(plan.Secrets))
	declaredRefs := make([]string, 0, len(plan.Secrets))
	for _, secret := range plan.Secrets {
		if err := validateSecretDeclaration(secret); err != nil {
			return err
		}
		if secret.SecretName != "dtx/"+plan.Binding.AgentInstanceID+"/deployments/"+plan.Binding.DeploymentID+"/"+secret.SlotID ||
			secret.TargetPath != PreinstalledSecretRoot+"/"+secret.SlotID {
			return errorf(CodeInvalidPath, "installer secret destination is outside its deployment binding")
		}
		if _, duplicate := seenSlots[secret.SlotID]; duplicate {
			return errorf(CodeInvalidRequest, "duplicate installer secret slot")
		}
		if _, duplicate := seenRefs[secret.SecretRef]; duplicate {
			return errorf(CodeInvalidRequest, "duplicate installer secret reference")
		}
		seenSlots[secret.SlotID] = struct{}{}
		seenRefs[secret.SecretRef] = struct{}{}
		declaredRefs = append(declaredRefs, secret.SecretRef)
	}
	slices.Sort(declaredRefs)
	if !slices.Equal(declaredRefs, plan.SecretRefs) {
		return errorf(CodeInvalidRequest, "installer secret references are not canonical")
	}
	return nil
}

func validateSecretDeclaration(secret SecretV1) error {
	version, versionErr := uuid.Parse(secret.VersionID)
	if !namePattern.MatchString(secret.SlotID) || !secretRefPattern.MatchString(secret.SecretRef) ||
		secret.SecretName == "" || len(secret.SecretName) > 512 || strings.ContainsAny(secret.SecretName, "*?\\\x00") ||
		versionErr != nil || version == uuid.Nil || version.String() != secret.VersionID ||
		!path.IsAbs(secret.TargetPath) || path.Clean(secret.TargetPath) != secret.TargetPath || !strings.HasPrefix(secret.TargetPath, PreinstalledSecretRoot+"/") ||
		(secret.FileMode != 0o400 && secret.FileMode != 0o440) || secret.OwnerUID > 65535 || secret.OwnerGID > 65535 {
		return errorf(CodeInvalidRequest, "invalid installer secret declaration")
	}
	return nil
}

func validateCommands(plan InstallerPlanV1) error {
	artifacts := make(map[string]struct{}, len(plan.Artifacts))
	for _, artifact := range plan.Artifacts {
		artifacts[artifact.Name] = struct{}{}
	}
	volumes := make(map[string]struct{}, len(plan.Volumes))
	for _, volume := range plan.Volumes {
		volumes[volume.Name] = struct{}{}
	}
	secrets := make(map[string]struct{}, len(plan.SecretRefs))
	for _, secret := range plan.SecretRefs {
		secrets[secret] = struct{}{}
	}
	seen := make(map[string]struct{}, len(plan.Commands))
	for _, command := range plan.Commands {
		if !namePattern.MatchString(command.CommandID) || len(command.Argv) < 1 || len(command.Argv) > 128 || len(command.ArtifactRefs) < 1 ||
			command.TimeoutSeconds < 1 || command.TimeoutSeconds > 24*60*60 {
			return errorf(CodeInvalidRequest, "invalid command ID, argv/artifact count, or timeout")
		}
		if strings.ContainsRune(command.WorkingDirectory, '\x00') || !path.IsAbs(command.WorkingDirectory) ||
			path.Clean(command.WorkingDirectory) != command.WorkingDirectory {
			return errorf(CodeInvalidPath, "invalid command working directory")
		}
		if _, exists := seen[command.CommandID]; exists {
			return errorf(CodeInvalidRequest, "duplicate command ID")
		}
		seen[command.CommandID] = struct{}{}
		switch strings.ToLower(path.Base(command.Argv[0])) {
		case "sh", "bash", "dash", "ash", "zsh", "ksh", "fish", "eval", "powershell", "pwsh", "cmd", "cmd.exe":
			return errorf(CodeCommandNotAllowed, "installer command cannot invoke a shell or evaluator")
		}
		totalArgvBytes := 0
		for index, argument := range command.Argv {
			totalArgvBytes += len(argument)
			if len(argument) > 16<<10 || strings.ContainsRune(argument, '\x00') || security.ContainsLikelySecret(argument) {
				return errorf(CodeInvalidRequest, "command argv contains an invalid value")
			}
			if index == 0 && ((strings.Contains(argument, "/") && (!path.IsAbs(argument) || path.Clean(argument) != argument)) ||
				(!strings.Contains(argument, "/") && !executablePattern.MatchString(argument))) {
				return errorf(CodeInvalidPath, "command executable is not absolute or safe-PATH-resolvable")
			}
		}
		if totalArgvBytes > 64<<10 {
			return errorf(CodeInvalidRequest, "command argv exceeds limit")
		}
		if err := validateCommandRefs(command.ArtifactRefs, artifacts, namePattern); err != nil {
			return errorf(CodeInvalidRequest, "invalid command artifact references")
		}
		if err := validateCommandRefs(command.VolumeRefs, volumes, namePattern); err != nil {
			return errorf(CodeInvalidRequest, "invalid command volume references")
		}
		if err := validateCommandRefs(command.SecretRefs, secrets, secretRefPattern); err != nil {
			return errorf(CodeInvalidRequest, "invalid command secret references")
		}
	}
	return nil
}

func validateCommandRefs(values []string, declared map[string]struct{}, pattern *regexp.Regexp) error {
	if !slices.IsSorted(values) {
		return errors.New("references are not sorted")
	}
	previous := ""
	for _, value := range values {
		if !pattern.MatchString(value) || value == previous {
			return errors.New("reference is invalid or duplicated")
		}
		if _, exists := declared[value]; !exists {
			return errors.New("reference is undeclared")
		}
		previous = value
	}
	return nil
}

func validateBinding(binding BindingV1) error {
	if !digestPattern.MatchString(binding.PlanHash) || !digestPattern.MatchString(binding.RecipeDigest) {
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

func (v *Verifier) validateExecutionLease(request RequestV1) (time.Time, int64, error) {
	if request.LeaseGrant == nil {
		return time.Time{}, 0, errorf(CodeLeaseRejected, "installer lease grant is required")
	}
	if v.expectedTrustID != "" && request.LeaseGrant.Grant.TrustID != v.expectedTrustID {
		return time.Time{}, 0, errorf(CodeLeaseRejected, "installer lease grant does not match root trust")
	}
	delivery := DeliveryV1{
		SchemaVersion: DeliverySchemaV1, TrustID: request.LeaseGrant.Grant.TrustID,
		PublicKey:  append([]byte(nil), v.publicKey...),
		Config:     DaemonConfigV1{SchemaVersion: DaemonConfigSchema, Binding: v.expectedBinding, TargetRoot: v.targetRoot},
		SignedPlan: request.SignedPlan,
	}
	if err := ValidateLeaseGrantAt(delivery, *request.LeaseGrant, request.CommandID, v.now().UTC()); err != nil {
		return time.Time{}, 0, err
	}
	operationID := installerOperationID(delivery.TrustID, request.CommandID)
	if request.OperationID != operationID || request.RequestID != installerRequestID(operationID) || request.IdempotencyKey != installerIdempotencyKey(operationID) {
		return time.Time{}, 0, errorf(CodeLeaseRejected, "installer operation identity is invalid")
	}
	expiresAt, _ := time.Parse(time.RFC3339Nano, request.LeaseGrant.Grant.ExpiresAt)
	return expiresAt, request.LeaseGrant.Grant.LeaseEpoch, nil
}

func executionOperationDigest(request RequestV1) (string, error) {
	digest, err := canonical.Digest(struct {
		SchemaVersion string                `json:"schema_version"`
		Action        string                `json:"action"`
		Binding       BindingV1             `json:"binding"`
		SignedPlan    SignedInstallerPlanV1 `json:"signed_plan"`
		OperationID   string                `json:"operation_id"`
		CommandID     string                `json:"command_id"`
	}{request.SchemaVersion, request.Action, request.Binding, request.SignedPlan, request.OperationID, request.CommandID})
	if err != nil {
		return "", errorf(CodeInvalidRequest, "digest installer operation")
	}
	return digest, nil
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
	if len(volumes) > 11 {
		return errorf(CodeInvalidRequest, "too many volume declarations")
	}
	seen := make(map[string]struct{}, len(volumes))
	devices := make(map[string]struct{}, len(volumes))
	mounts := make(map[string]struct{}, len(volumes))
	for _, volume := range volumes {
		if !namePattern.MatchString(volume.Name) || volume.SizeGiB < 1 || !volumeDevicePattern.MatchString(volume.DeviceName) ||
			!path.IsAbs(volume.MountPath) || !volumeMountPattern.MatchString(volume.MountPath) || path.Clean(volume.MountPath) != volume.MountPath || reservedInstallerVolumeMount(volume.MountPath) ||
			(volume.Disposition != "delete_with_deployment" && volume.Disposition != "retain_with_managed_service") {
			return errorf(CodeInvalidRequest, "invalid volume declaration")
		}
		if _, exists := seen[volume.Name]; exists {
			return errorf(CodeInvalidRequest, "duplicate volume declaration")
		}
		seen[volume.Name] = struct{}{}
		if _, exists := devices[volume.DeviceName]; exists {
			return errorf(CodeInvalidRequest, "duplicate volume device")
		}
		devices[volume.DeviceName] = struct{}{}
		if _, exists := mounts[volume.MountPath]; exists {
			return errorf(CodeInvalidRequest, "duplicate volume mount")
		}
		mounts[volume.MountPath] = struct{}{}
	}
	return nil
}

func reservedInstallerVolumeMount(value string) bool {
	for _, root := range []string{"/", "/boot", "/dev", "/efi", "/etc", "/home", "/proc", "/run", "/sys", "/tmp", "/usr"} {
		if value == root || strings.HasPrefix(value, root+"/") {
			return true
		}
	}
	return false
}

func findArtifact(artifacts []ArtifactV1, name string) (ArtifactV1, bool) {
	for _, artifact := range artifacts {
		if artifact.Name == name {
			return artifact, true
		}
	}
	return ArtifactV1{}, false
}

func findCommand(commands []CommandV1, commandID string) (CommandV1, bool) {
	for _, command := range commands {
		if command.CommandID == commandID {
			return command, true
		}
	}
	return CommandV1{}, false
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
