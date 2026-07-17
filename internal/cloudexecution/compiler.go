package cloudexecution

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
	"strings"
	"time"

	cloudapproval "github.com/YingSuiAI/dirextalk-agent/internal/cloud/approval"
	cloudquote "github.com/YingSuiAI/dirextalk-agent/internal/cloud/quote"
	"github.com/YingSuiAI/dirextalk-agent/internal/installer"
	installerbootstrap "github.com/YingSuiAI/dirextalk-agent/internal/installer/bootstrap"
	"github.com/YingSuiAI/dirextalk-agent/internal/recipe"
	"github.com/YingSuiAI/dirextalk-agent/internal/workerrunner"
	"github.com/google/uuid"
)

const (
	installerProvisioningGrace       = 30 * time.Minute
	installerCapabilityMaximumPeriod = 7 * 24 * time.Hour
)

// CompiledBundles is the only publication input. Lease grants are
// intentionally absent: they are issued by Agent only after a Worker claim.
type CompiledBundles struct {
	RecipeBytes         []byte
	ExecutionBytes      []byte
	InstallerDelivery   *installer.DeliveryV1
	InstallerCommandIDs []string
	InstallerRootTrust  *InstallerRootTrustV1
	InstallerArtifacts  []InstallerArtifactStagingInput
	InstallerSecrets    []InstallerSecretStagingInput
}

// InstallerRootTrustV1 is the single shared, public IMDS user-data contract.
// The stable full Delivery remains in the digest-bound execution bundle and
// PostgreSQL; lease grants are never part of this material.
type InstallerRootTrustV1 = installerbootstrap.RootTrustMaterialV1

func compileBundles(value recipe.RecipeV1, delivery *installer.DeliveryV1, now time.Time) (CompiledBundles, error) {
	if err := validateExecutionRecipe(value); err != nil {
		return CompiledBundles{}, err
	}
	recipeBytes, err := value.CanonicalCBOR()
	if err != nil {
		return CompiledBundles{}, ErrInvalid
	}
	recipeDigest := sha256.Sum256(recipeBytes)
	actions := make([]workerrunner.ActionV1, 0, len(value.Install.Steps))
	var commandIDs []string
	for _, step := range value.Install.Steps {
		switch strings.TrimSpace(step.Action) {
		case (workerrunner.NoopAction{}).Kind():
			actions = append(actions, workerrunner.ActionV1{ID: step.ID, Kind: step.Action, TimeoutSeconds: step.TimeoutSeconds, Noop: &workerrunner.NoopInputV1{}})
		case installer.ActionExecute:
			if delivery == nil {
				return CompiledBundles{}, ErrNotReady
			}
			commandID := step.Inputs[0].Ref
			command, found := installerCommand(delivery.SignedPlan.Plan.Commands, commandID)
			if !found || command.TimeoutSeconds != step.TimeoutSeconds {
				return CompiledBundles{}, ErrUnsupportedRecipe
			}
			actions = append(actions, workerrunner.ActionV1{
				ID: step.ID, Kind: installer.ActionExecute, TimeoutSeconds: step.TimeoutSeconds,
				Installer: &workerrunner.InstallerExecuteInputV1{CommandID: commandID, Delivery: *delivery},
			})
			commandIDs = append(commandIDs, commandID)
		default:
			return CompiledBundles{}, ErrUnsupportedRecipe
		}
	}
	encoded, err := json.Marshal(workerrunner.ExecutionBundleV1{SchemaVersion: 1, RecipeSHA256: hex.EncodeToString(recipeDigest[:]), Actions: actions})
	if err != nil {
		return CompiledBundles{}, ErrInvalid
	}
	result := CompiledBundles{RecipeBytes: recipeBytes, ExecutionBytes: encoded, InstallerCommandIDs: commandIDs}
	if delivery != nil {
		result.InstallerDelivery = cloneDelivery(delivery)
		material, materialErr := delivery.RootTrustMaterial(now)
		if materialErr != nil {
			return CompiledBundles{}, ErrNotReady
		}
		trust, materialErr := installerbootstrap.NewRootTrustMaterial(material)
		if materialErr != nil {
			return CompiledBundles{}, ErrNotReady
		}
		result.InstallerRootTrust = &trust
		result.InstallerArtifacts = make([]InstallerArtifactStagingInput, 0, len(delivery.SignedPlan.Plan.Artifacts))
		sourceIDs := make(map[string]string, len(value.Install.Installer.Artifacts))
		for _, declaration := range value.Install.Installer.Artifacts {
			sourceIDs[declaration.Name] = declaration.SourceID
		}
		for _, artifact := range delivery.SignedPlan.Plan.Artifacts {
			result.InstallerArtifacts = append(result.InstallerArtifacts, InstallerArtifactStagingInput{
				Name: artifact.Name, SourceID: sourceIDs[artifact.Name], SHA256: artifact.SHA256, SizeBytes: artifact.SizeBytes,
				TargetPath: artifact.TargetPath, RecipeDigest: delivery.Config.Binding.RecipeDigest,
			})
		}
		result.InstallerSecrets = make([]InstallerSecretStagingInput, 0, len(delivery.SignedPlan.Plan.Secrets))
		for _, secret := range delivery.SignedPlan.Plan.Secrets {
			result.InstallerSecrets = append(result.InstallerSecrets, InstallerSecretStagingInput{
				SlotID: secret.SlotID, SecretRef: secret.SecretRef, SecretName: secret.SecretName, VersionID: secret.VersionID,
				TargetPath: secret.TargetPath, FileMode: secret.FileMode, OwnerUID: secret.OwnerUID, OwnerGID: secret.OwnerGID,
				RecipeDigest: delivery.Config.Binding.RecipeDigest,
			})
		}
	}
	return result, nil
}

func validateExecutionRecipe(value recipe.RecipeV1) error {
	if err := value.Validate(); err != nil {
		return ErrInvalid
	}
	declared := make(map[string]recipe.InstallerCommandV1)
	if value.Install.Installer != nil {
		for _, command := range value.Install.Installer.Commands {
			declared[command.CommandID] = command
		}
	}
	selected := make(map[string]struct{})
	for _, step := range value.Install.Steps {
		switch strings.TrimSpace(step.Action) {
		case (workerrunner.NoopAction{}).Kind():
			if len(step.Inputs) != 0 {
				return ErrUnsupportedRecipe
			}
		case installer.ActionExecute:
			if value.Install.Installer == nil || len(step.Inputs) != 1 || step.Inputs[0].Name != "command_id" ||
				step.Inputs[0].Kind != recipe.ActionInputConfig {
				return ErrUnsupportedRecipe
			}
			command, ok := declared[step.Inputs[0].Ref]
			if !ok || command.TimeoutSeconds != step.TimeoutSeconds {
				return ErrUnsupportedRecipe
			}
			if _, duplicate := selected[command.CommandID]; duplicate {
				return ErrUnsupportedRecipe
			}
			selected[command.CommandID] = struct{}{}
		default:
			return ErrUnsupportedRecipe
		}
	}
	return nil
}

func issueInstallerDelivery(value recipe.RecipeV1, plan cloudapproval.PlanV1, approval cloudapproval.ApprovalV1, operation Operation, taskID string, issuer *installer.TrustIssuer, now time.Time) (*installer.DeliveryV1, error) {
	if value.Install.Installer == nil {
		return nil, nil
	}
	if issuer == nil || taskID == "" || plan.Recipe.Digest == "" || approval.PlanHash == "" {
		return nil, ErrNotReady
	}
	sources := make(map[string]recipe.SourceV1, len(value.Sources))
	for _, source := range value.Sources {
		sources[source.ID] = source
	}
	artifacts := make([]installer.ArtifactV1, 0, len(value.Install.Installer.Artifacts))
	for _, declaration := range value.Install.Installer.Artifacts {
		source, ok := sources[declaration.SourceID]
		if !ok {
			return nil, ErrUnsupportedRecipe
		}
		artifacts = append(artifacts, installer.ArtifactV1{Name: declaration.Name, SHA256: source.ArtifactDigest, SizeBytes: declaration.SizeBytes, TargetPath: declaration.TargetPath})
	}
	secretRefs, secretSlots, secrets, err := resolveInstallerSecrets(value, plan, operation.DeploymentID)
	if err != nil {
		return nil, err
	}
	volumes, volumeSlots, err := resolveInstallerVolumes(value, plan)
	if err != nil {
		return nil, err
	}
	commands := make([]installer.CommandV1, 0, len(value.Install.Installer.Commands))
	for _, declaration := range value.Install.Installer.Commands {
		resolvedVolumes := make([]string, 0, len(declaration.VolumeSlotRefs))
		for _, slot := range declaration.VolumeSlotRefs {
			name, ok := volumeSlots[slot]
			if !ok {
				return nil, ErrNotReady
			}
			resolvedVolumes = append(resolvedVolumes, name)
		}
		sort.Strings(resolvedVolumes)
		resolvedSecrets := make([]string, 0, len(declaration.SecretSlotRefs))
		for _, slot := range declaration.SecretSlotRefs {
			reference, ok := secretSlots[slot]
			if !ok {
				return nil, ErrNotReady
			}
			resolvedSecrets = append(resolvedSecrets, reference)
		}
		sort.Strings(resolvedSecrets)
		artifactRefs := append([]string(nil), declaration.ArtifactRefs...)
		sort.Strings(artifactRefs)
		commands = append(commands, installer.CommandV1{
			CommandID: declaration.CommandID, Argv: append([]string(nil), declaration.Argv...), WorkingDirectory: declaration.WorkingDirectory,
			TimeoutSeconds: declaration.TimeoutSeconds, ArtifactRefs: artifactRefs, VolumeRefs: resolvedVolumes, SecretRefs: resolvedSecrets,
		})
	}
	binding := installer.BindingV1{
		AgentInstanceID: plan.AgentInstanceID, DeploymentID: operation.DeploymentID, TaskID: taskID,
		PlanHash: approval.PlanHash, ApprovalID: approval.ApprovalID, RecipeDigest: plan.Recipe.Digest,
	}
	expiresAt, err := installerCapabilityExpiry(value, plan, operation, now)
	if err != nil {
		return nil, err
	}
	installerPlan := installer.InstallerPlanV1{
		SchemaVersion: installer.PlanSchemaV1, Binding: binding, Artifacts: artifacts, SecretRefs: secretRefs, Secrets: secrets,
		Network: installerNetwork(value, plan), Ports: installerPorts(value, plan), Volumes: volumes, Commands: commands,
		ExpiresAt: expiresAt.Format(time.RFC3339Nano),
	}
	delivery, err := issuer.Issue(installerPlan, installer.DaemonConfigV1{SchemaVersion: installer.DaemonConfigSchema, Binding: binding, TargetRoot: installer.PreinstalledArtifactRoot}, now)
	if err != nil {
		return nil, ErrUnsupportedRecipe
	}
	return &delivery, nil
}

func resolveInstallerVolumes(value recipe.RecipeV1, plan cloudapproval.PlanV1) ([]installer.VolumeV1, map[string]string, error) {
	if err := cloudquote.ValidateVolumeScopesForRecipe(plan.ResourceScope.VolumeScopes, value, cloudquote.RetentionScopeV1{
		Class: cloudquote.RetentionClass(plan.RetentionScope.Class), AutoDestroy: plan.RetentionScope.AutoDestroy,
		GracePeriodSeconds: plan.RetentionScope.GracePeriodSeconds, MaxLifetimeSeconds: plan.RetentionScope.MaxLifetimeSeconds,
	}); err != nil {
		return nil, nil, ErrNotReady
	}
	volumes := make([]installer.VolumeV1, 0, len(plan.ResourceScope.VolumeScopes))
	bySlot := make(map[string]string, len(plan.ResourceScope.VolumeScopes))
	for _, scope := range plan.ResourceScope.VolumeScopes {
		volumes = append(volumes, installer.VolumeV1{
			Name: scope.SlotID, DeviceName: scope.DeviceName, MountPath: scope.MountPath, ReadOnly: scope.ReadOnly,
			Persistent: scope.Persistent, Disposition: string(scope.Disposition), SizeGiB: scope.SizeGiB,
		})
		bySlot[scope.SlotID] = scope.SlotID
	}
	sort.Slice(volumes, func(i, j int) bool { return volumes[i].Name < volumes[j].Name })
	return volumes, bySlot, nil
}

func installerCapabilityExpiry(value recipe.RecipeV1, plan cloudapproval.PlanV1, operation Operation, issuedNow time.Time) (time.Time, error) {
	issuedNow = issuedNow.UTC()
	if issuedNow.IsZero() || value.Install.TimeoutSeconds == 0 {
		return time.Time{}, ErrInvalid
	}
	expiresAt := issuedNow.Add(time.Duration(value.Install.TimeoutSeconds)*time.Second + installerProvisioningGrace)
	maximum := issuedNow.Add(installerCapabilityMaximumPeriod)
	if expiresAt.After(maximum) {
		expiresAt = maximum
	}
	switch plan.RetentionScope.Class {
	case cloudapproval.RetentionEphemeral:
		if !plan.RetentionScope.AutoDestroy || plan.RetentionScope.MaxLifetimeSeconds == 0 || operation.RecordedAt.IsZero() {
			return time.Time{}, ErrInvalid
		}
		retentionExpiry := operation.RecordedAt.UTC().Add(time.Duration(plan.RetentionScope.MaxLifetimeSeconds) * time.Second)
		if retentionExpiry.Before(expiresAt) {
			expiresAt = retentionExpiry
		}
	case cloudapproval.RetentionManaged:
	default:
		return time.Time{}, ErrInvalid
	}
	if !expiresAt.After(issuedNow) {
		return time.Time{}, ErrNotReady
	}
	return expiresAt, nil
}

func resolveInstallerSecrets(value recipe.RecipeV1, plan cloudapproval.PlanV1, deploymentID string) ([]string, map[string]string, []installer.SecretV1, error) {
	resolved := make(map[string]string)
	declarations := make([]installer.SecretV1, 0, len(plan.SecretScope))
	matchedRefs := make(map[string]struct{}, len(plan.SecretScope))
	deployment, deploymentErr := uuid.Parse(deploymentID)
	if deploymentErr != nil || deployment == uuid.Nil {
		return nil, nil, nil, ErrInvalid
	}
	for _, slot := range value.SecretSlots {
		match := ""
		for _, scope := range plan.SecretScope {
			if scope.Purpose == slot.Purpose && scope.Delivery == slot.Delivery {
				if match != "" {
					return nil, nil, nil, ErrNotReady
				}
				match = scope.SecretRef
			}
		}
		if match != "" {
			if slot.Delivery != recipe.SecretDeliveryFile {
				return nil, nil, nil, ErrUnsupportedRecipe
			}
			if _, err := bootstrapSessionID(match); err != nil {
				return nil, nil, nil, ErrNotReady
			}
			resolved[slot.SlotID] = match
			matchedRefs[match] = struct{}{}
			version := uuid.NewSHA1(deployment, []byte("dirextalk-service-secret/v1\x00"+slot.SlotID+"\x00"+match)).String()
			declarations = append(declarations, installer.SecretV1{
				SlotID: slot.SlotID, SecretRef: match,
				SecretName: "dtx/" + plan.AgentInstanceID + "/deployments/" + deploymentID + "/" + slot.SlotID,
				VersionID:  version, TargetPath: slot.TargetPath, FileMode: slot.FileMode, OwnerUID: slot.OwnerUID, OwnerGID: slot.OwnerGID,
			})
		} else {
			return nil, nil, nil, ErrNotReady
		}
	}
	if len(matchedRefs) != len(plan.SecretScope) {
		return nil, nil, nil, ErrNotReady
	}
	sort.Slice(declarations, func(left, right int) bool { return declarations[left].SecretRef < declarations[right].SecretRef })
	all := make([]string, 0, len(declarations))
	for _, declaration := range declarations {
		all = append(all, declaration.SecretRef)
	}
	sort.Strings(all)
	return all, resolved, declarations, nil
}

func bootstrapSessionID(reference string) (string, error) {
	const prefix = "secret_ref:bootstrap/"
	sessionID := strings.TrimPrefix(reference, prefix)
	parsed, err := uuid.Parse(sessionID)
	if reference == sessionID || err != nil || parsed == uuid.Nil || parsed.String() != sessionID {
		return "", ErrNotReady
	}
	return sessionID, nil
}

func installerNetwork(value recipe.RecipeV1, plan cloudapproval.PlanV1) installer.NetworkV1 {
	result := installer.NetworkV1{PublicInbound: plan.NetworkScope.PublicExposure}
	if value.Network != nil {
		for _, rule := range value.Network.Outbound {
			if rule.Protocol == recipe.NetworkHTTPS {
				result.OutboundHTTPSHosts = append(result.OutboundHTTPSHosts, rule.Destination)
			}
		}
	}
	sort.Strings(result.OutboundHTTPSHosts)
	return result
}

func installerPorts(value recipe.RecipeV1, plan cloudapproval.PlanV1) []installer.PortV1 {
	if value.Network == nil {
		return nil
	}
	result := make([]installer.PortV1, 0, len(value.Network.Listeners))
	for _, listener := range value.Network.Listeners {
		direction := "loopback"
		if listener.BindScope == recipe.BindPrivate {
			direction = "outbound"
			if plan.NetworkScope.PublicExposure {
				direction = "inbound"
			}
		}
		result = append(result, installer.PortV1{Name: listener.ID, Protocol: "tcp", Direction: direction, Port: listener.Port})
	}
	return result
}

func installerCommand(commands []installer.CommandV1, commandID string) (installer.CommandV1, bool) {
	for _, command := range commands {
		if command.CommandID == commandID {
			return command, true
		}
	}
	return installer.CommandV1{}, false
}

func cloneDelivery(value *installer.DeliveryV1) *installer.DeliveryV1 {
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

func ValidateInstallerOperation(value Operation) error {
	if value.InstallerDelivery == nil {
		if len(value.InstallerCommandIDs) != 0 || value.InstallerRootTrust != nil {
			return ErrInvalid
		}
		return nil
	}
	if value.TaskID == "" || len(value.InstallerCommandIDs) == 0 || value.InstallerRootTrust == nil {
		return ErrInvalid
	}
	delivery := value.InstallerDelivery
	expiresAt, err := time.Parse(time.RFC3339Nano, delivery.SignedPlan.Plan.ExpiresAt)
	if err != nil || installer.ValidateDeliveryAt(*delivery, expiresAt.Add(-time.Nanosecond)) != nil {
		return ErrInvalid
	}
	binding := delivery.Config.Binding
	if binding.DeploymentID != value.DeploymentID || binding.TaskID != value.TaskID || binding.PlanHash != value.ApprovedPlanHash {
		return ErrInvalid
	}
	declared := make(map[string]struct{}, len(delivery.SignedPlan.Plan.Commands))
	for _, command := range delivery.SignedPlan.Plan.Commands {
		declared[command.CommandID] = struct{}{}
	}
	seen := make(map[string]struct{}, len(value.InstallerCommandIDs))
	for _, commandID := range value.InstallerCommandIDs {
		if _, ok := declared[commandID]; !ok {
			return ErrInvalid
		}
		if _, duplicate := seen[commandID]; duplicate {
			return ErrInvalid
		}
		seen[commandID] = struct{}{}
	}
	material, err := delivery.RootTrustMaterial(expiresAt.Add(-time.Nanosecond))
	if err != nil {
		return ErrInvalid
	}
	trust := value.InstallerRootTrust
	expectedTrust, err := installerbootstrap.NewRootTrustMaterial(material)
	if err != nil {
		return ErrInvalid
	}
	if _, err := installerbootstrap.ValidateTrustMaterial(*trust, binding.DeploymentID); err != nil ||
		trust.TrustID != material.TrustID ||
		!bytes.Equal(trust.PublicKey, material.PublicKey) || !bytes.Equal(trust.ConfigCBOR, material.ConfigCBOR) ||
		trust.ConfigDigest != expectedTrust.ConfigDigest {
		return ErrInvalid
	}
	return nil
}
