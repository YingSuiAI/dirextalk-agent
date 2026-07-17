package recipe

import (
	"fmt"
	"net"
	"net/url"
	"path"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"time"
)

var (
	identifierPattern          = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
	digestPattern              = regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)
	commitPattern              = regexp.MustCompile(`^[A-Fa-f0-9]{7,64}$`)
	repositoryNamespacePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._/-]{0,254}[A-Za-z0-9]$|^[A-Za-z0-9]$`)
	hostLabelPattern           = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)
	credentialPatterns         = []*regexp.Regexp{
		regexp.MustCompile(`(?:AKIA|ASIA)[A-Z0-9]{16}`),
		regexp.MustCompile(`(?i)aws[_ -]?(?:secret[_ -]?access[_ -]?key|session[_ -]?token)`),
		regexp.MustCompile(`-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----`),
		regexp.MustCompile(`(?i)(?:^|[^A-Za-z0-9])(?:gh[pousr]_[A-Za-z0-9]{20,}|hf_[A-Za-z0-9]{20,}|sk[-_][A-Za-z0-9_-]{20,}|xox[baprs]-[A-Za-z0-9-]{10,})`),
		regexp.MustCompile(`(?i)(?:authorization|password|secret|token)\s*[:=]\s*[^\s,;]+`),
	}
)

type recipeReferences struct {
	sources     map[string]struct{}
	volumes     map[string]struct{}
	data        map[string]struct{}
	secrets     map[string]struct{}
	checkpoints map[string]struct{}
	listeners   map[string]struct{}
}

func ValidMaturity(value Maturity) bool {
	return value == MaturityExperimental || value == MaturityManaged
}

func ValidArchitecture(value Architecture) bool {
	return value == ArchitectureAMD64 || value == ArchitectureARM64
}

func ValidSecretDelivery(value SecretDelivery) bool {
	return value == SecretDeliveryFile || value == SecretDeliveryEnvironment
}

func ValidateDigest(value string) error {
	if !digestPattern.MatchString(value) {
		return fmt.Errorf("must be a lowercase sha256 digest")
	}
	return nil
}

func (r RecipeV1) Validate() error {
	if r.SchemaVersion != SchemaV1 {
		return fmt.Errorf("schema_version must be %q", SchemaV1)
	}
	if err := validateIdentifier("recipe_id", r.RecipeID); err != nil {
		return err
	}
	if err := validateText("name", r.Name, 1, 160); err != nil {
		return err
	}
	if !ValidMaturity(r.Maturity) {
		return fmt.Errorf("maturity is invalid")
	}
	if err := rejectCredentialMaterial(reflect.ValueOf(r)); err != nil {
		return err
	}
	refs := recipeReferences{}
	if err := validateSources(r.Sources, &refs); err != nil {
		return err
	}
	if err := validateSlots(r.VolumeSlots, r.DataSlots, r.SecretSlots, &refs); err != nil {
		return err
	}
	if err := validateRequirements(r.Requirements, refs); err != nil {
		return err
	}
	if err := validateInstall(r.Install, &refs); err != nil {
		return err
	}
	if err := validateProbe("health.liveness", r.Health.Liveness); err != nil {
		return err
	}
	if err := validateProbe("health.readiness", r.Health.Readiness); err != nil {
		return err
	}
	if err := validateProbe("health.semantic", r.Health.Semantic); err != nil {
		return err
	}
	if err := validateLifecycle(r.Lifecycle); err != nil {
		return err
	}
	if err := validateNetwork(r.Network, &refs); err != nil {
		return err
	}
	if err := validateRestart(r.Restart, refs.checkpoints); err != nil {
		return err
	}
	if err := validatePairing(r.Pairing); err != nil {
		return err
	}
	if err := validateIntegrations(r.Integrations, refs); err != nil {
		return err
	}
	return validateMaturity(r, refs)
}

func validateSources(sources []SourceV1, refs *recipeReferences) error {
	if len(sources) == 0 || len(sources) > 16 {
		return fmt.Errorf("sources must contain between 1 and 16 entries")
	}
	refs.sources = make(map[string]struct{}, len(sources))
	seenURLs := make(map[string]struct{}, len(sources))
	for index, source := range sources {
		prefix := fmt.Sprintf("sources[%d]", index)
		if source.ID != "" {
			if err := validateIdentifier(prefix+".id", source.ID); err != nil {
				return err
			}
			if _, exists := refs.sources[source.ID]; exists {
				return fmt.Errorf("%s.id is duplicated", prefix)
			}
			refs.sources[source.ID] = struct{}{}
		}
		parsed, err := validateSourceURL(source.URL)
		if err != nil {
			return fmt.Errorf("%s.url %w", prefix, err)
		}
		if _, exists := seenURLs[source.URL]; exists {
			return fmt.Errorf("%s.url is duplicated", prefix)
		}
		seenURLs[source.URL] = struct{}{}
		if err := validateText(prefix+".version", source.Version, 1, 128); err != nil {
			return err
		}
		if !commitPattern.MatchString(source.Commit) {
			return fmt.Errorf("%s.commit must be a 7-64 character hexadecimal commit", prefix)
		}
		if err := ValidateDigest(source.ArtifactDigest); err != nil {
			return fmt.Errorf("%s.artifact_digest %w", prefix, err)
		}
		if err := ValidateDigest(source.ContentDigest); err != nil {
			return fmt.Errorf("%s.content_digest %w", prefix, err)
		}
		if err := validateText(prefix+".license", source.License, 1, 128); err != nil {
			return err
		}
		if source.RetrievedAt.IsZero() {
			return fmt.Errorf("%s.retrieved_at is required", prefix)
		}
		switch source.Kind {
		case "": // Legacy experimental drafts remain readable.
			if source.Repository != nil {
				return fmt.Errorf("%s.repository requires repository kind", prefix)
			}
		case SourceRepository:
			if source.Repository == nil {
				return fmt.Errorf("%s.repository is required for repository sources", prefix)
			}
			if err := validateRepository(prefix+".repository", *source.Repository, parsed.Hostname()); err != nil {
				return err
			}
		case SourceDocumentation, SourceRelease:
			if source.Repository != nil {
				return fmt.Errorf("%s.repository is only valid for repository sources", prefix)
			}
		default:
			return fmt.Errorf("%s.kind is invalid", prefix)
		}
	}
	return nil
}

func validateSourceURL(raw string) (*url.URL, error) {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || !parsed.IsAbs() || parsed.Opaque != "" {
		return nil, fmt.Errorf("must be an absolute HTTPS URL")
	}
	if parsed.User != nil {
		return nil, fmt.Errorf("must not contain user information")
	}
	if parsed.Fragment != "" {
		return nil, fmt.Errorf("must not contain a fragment")
	}
	if port := parsed.Port(); port != "" {
		value, err := strconv.ParseUint(port, 10, 16)
		if err != nil || value == 0 {
			return nil, fmt.Errorf("contains an invalid port")
		}
	}
	if err := validatePublicHost(parsed.Hostname(), true); err != nil {
		return nil, err
	}
	for key := range parsed.Query() {
		key = strings.ToLower(key)
		if strings.HasPrefix(key, "x-amz-") || credentialQueryKey(key) {
			return nil, fmt.Errorf("must not contain credential-bearing query parameters")
		}
	}
	return parsed, nil
}

func validateRepository(name string, repository RepositoryIdentityV1, sourceHost string) error {
	if err := validatePublicHost(repository.Host, false); err != nil {
		return fmt.Errorf("%s.host %w", name, err)
	}
	if !strings.EqualFold(repository.Host, sourceHost) {
		return fmt.Errorf("%s.host must match the repository source host", name)
	}
	if !repositoryNamespacePattern.MatchString(repository.Namespace) || strings.Contains(repository.Namespace, "..") || strings.Contains(repository.Namespace, "//") {
		return fmt.Errorf("%s.namespace is invalid", name)
	}
	return validateIdentifier(name+".name", repository.Name)
}

func credentialQueryKey(key string) bool {
	switch key {
	case "access_key", "accesskey", "api_key", "apikey", "auth", "authorization", "credential", "key", "password", "secret", "signature", "token":
		return true
	default:
		return strings.Contains(key, "credential") || strings.Contains(key, "signature") || strings.HasSuffix(key, "token")
	}
}

func validatePublicHost(host string, allowPublicIP bool) error {
	if host == "" || host != strings.ToLower(host) || strings.ContainsAny(host, "*/\\") {
		return fmt.Errorf("must be a lowercase, non-wildcard host")
	}
	if ip := net.ParseIP(host); ip != nil {
		if !allowPublicIP || !ip.IsGlobalUnicast() || ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
			return fmt.Errorf("must not be a private, local, or disallowed IP address")
		}
		return nil
	}
	if host == "localhost" || len(host) > 253 || strings.HasPrefix(host, ".") || strings.HasSuffix(host, ".") {
		return fmt.Errorf("is not a valid host")
	}
	for _, label := range strings.Split(host, ".") {
		if !hostLabelPattern.MatchString(label) {
			return fmt.Errorf("is not a valid host")
		}
	}
	return nil
}

func validateSlots(volumes []VolumeSlotRequirementV1, data []DataSlotRequirementV1, secrets []SecretSlotRequirementV1, refs *recipeReferences) error {
	if len(volumes) > 32 || len(data) > 32 || len(secrets) > 32 {
		return fmt.Errorf("each slot collection must contain at most 32 entries")
	}
	refs.volumes = make(map[string]struct{}, len(volumes))
	refs.data = make(map[string]struct{}, len(data))
	refs.secrets = make(map[string]struct{}, len(secrets))
	all := make(map[string]struct{}, len(volumes)+len(data)+len(secrets))
	check := func(name, id, purpose string, own map[string]struct{}) error {
		if err := validateIdentifier(name+".slot_id", id); err != nil {
			return err
		}
		if _, exists := all[id]; exists {
			return fmt.Errorf("%s.slot_id is duplicated across recipe slots", name)
		}
		all[id] = struct{}{}
		own[id] = struct{}{}
		return validateText(name+".purpose", purpose, 1, 256)
	}
	for index, slot := range volumes {
		name := fmt.Sprintf("volume_slots[%d]", index)
		if err := check(name, slot.SlotID, slot.Purpose, refs.volumes); err != nil {
			return err
		}
		if slot.MountPath != "" {
			if err := validateMountPath(name+".mount_path", slot.MountPath); err != nil {
				return err
			}
		}
		if slot.Persistent && !slot.EncryptionRequired {
			return fmt.Errorf("%s persistent volumes must require encryption", name)
		}
	}
	for index, slot := range data {
		if err := check(fmt.Sprintf("data_slots[%d]", index), slot.SlotID, slot.Purpose, refs.data); err != nil {
			return err
		}
	}
	for index, slot := range secrets {
		name := fmt.Sprintf("secret_slots[%d]", index)
		if err := check(name, slot.SlotID, slot.Purpose, refs.secrets); err != nil {
			return err
		}
		if !ValidSecretDelivery(slot.Delivery) {
			return fmt.Errorf("%s.delivery is invalid", name)
		}
		switch slot.Delivery {
		case SecretDeliveryFile:
			if !strings.HasPrefix(slot.TargetPath, "/etc/dirextalk-service-secrets/") || path.Clean(slot.TargetPath) != slot.TargetPath || strings.Contains(slot.TargetPath, "\\") ||
				(slot.FileMode != 0o400 && slot.FileMode != 0o440) || slot.OwnerUID > 65535 || slot.OwnerGID > 65535 {
				return fmt.Errorf("%s file delivery requires a read-only dedicated target and owner", name)
			}
		case SecretDeliveryEnvironment:
			if slot.TargetPath != "" || slot.FileMode != 0 || slot.OwnerUID != 0 || slot.OwnerGID != 0 {
				return fmt.Errorf("%s environment delivery cannot declare a file target", name)
			}
		}
	}
	return nil
}

func validateMountPath(name, value string) error {
	if !strings.HasPrefix(value, "/") || value == "/" || path.Clean(value) != value || strings.Contains(value, "\\") {
		return fmt.Errorf("%s must be a clean absolute Worker path", name)
	}
	for _, denied := range []string{"/dev", "/proc", "/sys", "/run/secrets"} {
		if value == denied || strings.HasPrefix(value, denied+"/") {
			return fmt.Errorf("%s targets a reserved Worker path", name)
		}
	}
	return nil
}

func validateRequirements(value ResourceRequirementsV1, refs recipeReferences) error {
	if value.MinVCPU == 0 || value.MinVCPU > 1024 {
		return fmt.Errorf("requirements.min_vcpu must be between 1 and 1024")
	}
	if value.MinMemoryMiB == 0 || value.MinMemoryMiB > 64*1024*1024 {
		return fmt.Errorf("requirements.min_memory_mib is out of range")
	}
	if value.MinDiskGiB == 0 || value.MinDiskGiB > 64*1024 {
		return fmt.Errorf("requirements.min_disk_gib is out of range")
	}
	if !ValidArchitecture(value.Architecture) {
		return fmt.Errorf("requirements.architecture is invalid")
	}
	if value.GPURequired {
		if value.MinGPUMemoryMiB == 0 || value.MinGPUMemoryMiB > 16*1024*1024 {
			return fmt.Errorf("requirements.min_gpu_memory_mib is required and must be in range for GPU recipes")
		}
		if err := validateText("requirements.gpu_family", value.GPUFamily, 1, 128); err != nil {
			return err
		}
	} else if value.MinGPUMemoryMiB != 0 || value.GPUFamily != "" {
		return fmt.Errorf("GPU requirements require gpu_required")
	}
	if len(value.DataLocations) > 32 {
		return fmt.Errorf("requirements.data_locations must contain at most 32 entries")
	}
	seen := make(map[string]struct{}, len(value.DataLocations))
	for index, location := range value.DataLocations {
		name := fmt.Sprintf("requirements.data_locations[%d]", index)
		if _, exists := refs.data[location.DataSlotID]; !exists {
			return fmt.Errorf("%s.data_slot_id does not reference a declared data slot", name)
		}
		if _, exists := seen[location.DataSlotID]; exists {
			return fmt.Errorf("%s.data_slot_id is duplicated", name)
		}
		seen[location.DataSlotID] = struct{}{}
		if err := validateUniqueTextSet(name+".residency", location.Residency, 0, 16, 128, true); err != nil {
			return err
		}
		switch location.Kind {
		case DataLocationWorkerVolume:
			if _, exists := refs.volumes[location.VolumeSlotID]; !exists {
				return fmt.Errorf("%s.volume_slot_id must reference a declared volume slot", name)
			}
		case DataLocationWorkerEphemeral, DataLocationObjectStore, DataLocationExternal:
			if location.VolumeSlotID != "" {
				return fmt.Errorf("%s.volume_slot_id is only valid for worker_volume", name)
			}
		default:
			return fmt.Errorf("%s.kind is invalid", name)
		}
	}
	return nil
}

func validateInstall(value InstallContractV1, refs *recipeReferences) error {
	if value.TimeoutSeconds == 0 || value.TimeoutSeconds > 24*60*60 {
		return fmt.Errorf("install.timeout_seconds must be between 1 and 86400")
	}
	if err := validateUniqueTextSet("install.checkpoint_names", value.CheckpointNames, 1, 32, 128, true); err != nil {
		return err
	}
	refs.checkpoints = make(map[string]struct{}, len(value.CheckpointNames))
	for _, checkpoint := range value.CheckpointNames {
		refs.checkpoints[checkpoint] = struct{}{}
	}
	if err := validateUniqueTextSet("install.allowed_adaptations", value.AllowedAdaptations, 0, 64, 256, false); err != nil {
		return err
	}
	if len(value.Adaptations) > 64 {
		return fmt.Errorf("install.adaptations must contain at most 64 entries")
	}
	seenAdaptations := make(map[string]struct{}, len(value.Adaptations))
	for index, adaptation := range value.Adaptations {
		name := fmt.Sprintf("install.adaptations[%d]", index)
		if err := validateIdentifier(name+".action", adaptation.Action); err != nil {
			return err
		}
		if _, exists := seenAdaptations[adaptation.Action]; exists {
			return fmt.Errorf("%s.action is duplicated", name)
		}
		seenAdaptations[adaptation.Action] = struct{}{}
		if err := validateText(name+".summary", adaptation.Summary, 1, 256); err != nil {
			return err
		}
		if adaptation.MaxAttempts == 0 || adaptation.MaxAttempts > 20 {
			return fmt.Errorf("%s.max_attempts must be between 1 and 20", name)
		}
	}
	if len(value.Steps) == 0 || len(value.Steps) > 64 {
		return fmt.Errorf("install.steps must contain between 1 and 64 entries")
	}
	if err := validateInstallerCapability(value.Installer, *refs); err != nil {
		return err
	}
	seenSteps := make(map[string]struct{}, len(value.Steps))
	var totalTimeout uint64
	for index, step := range value.Steps {
		prefix := fmt.Sprintf("install.steps[%d]", index)
		if err := validateIdentifier(prefix+".id", step.ID); err != nil {
			return err
		}
		if _, exists := seenSteps[step.ID]; exists {
			return fmt.Errorf("%s.id is duplicated", prefix)
		}
		seenSteps[step.ID] = struct{}{}
		if err := validateText(prefix+".summary", step.Summary, 1, 512); err != nil {
			return err
		}
		if step.TimeoutSeconds == 0 || step.TimeoutSeconds > value.TimeoutSeconds {
			return fmt.Errorf("%s.timeout_seconds must be positive and not exceed install timeout", prefix)
		}
		totalTimeout += uint64(step.TimeoutSeconds)
		if step.Action != "" {
			if err := validateIdentifier(prefix+".action", step.Action); err != nil {
				return err
			}
		} else if len(step.Inputs) != 0 {
			return fmt.Errorf("%s.inputs require a typed action", prefix)
		}
		if step.Checkpoint != "" {
			if _, exists := refs.checkpoints[step.Checkpoint]; !exists {
				return fmt.Errorf("%s.checkpoint does not reference a declared checkpoint", prefix)
			}
		}
		seenInputs := make(map[string]struct{}, len(step.Inputs))
		for inputIndex, input := range step.Inputs {
			name := fmt.Sprintf("%s.inputs[%d]", prefix, inputIndex)
			if err := validateIdentifier(name+".name", input.Name); err != nil {
				return err
			}
			if _, exists := seenInputs[input.Name]; exists {
				return fmt.Errorf("%s.name is duplicated", name)
			}
			seenInputs[input.Name] = struct{}{}
			if err := validateIdentifier(name+".ref", input.Ref); err != nil {
				return err
			}
			if err := validateActionInputReference(name, input, *refs); err != nil {
				return err
			}
		}
	}
	if totalTimeout > uint64(value.TimeoutSeconds) {
		return fmt.Errorf("install step timeouts exceed install.timeout_seconds")
	}
	return nil
}

func validateInstallerCapability(value *InstallerCapabilityV1, refs recipeReferences) error {
	if value == nil {
		return nil
	}
	if len(value.Artifacts) == 0 || len(value.Artifacts) > 128 || len(value.Commands) == 0 || len(value.Commands) > 128 {
		return fmt.Errorf("install.installer must declare between 1 and 128 artifacts and commands")
	}
	artifacts := make(map[string]InstallerArtifactV1, len(value.Artifacts))
	for index, artifact := range value.Artifacts {
		name := fmt.Sprintf("install.installer.artifacts[%d]", index)
		if err := validateIdentifier(name+".name", artifact.Name); err != nil {
			return err
		}
		if _, duplicate := artifacts[artifact.Name]; duplicate {
			return fmt.Errorf("%s.name is duplicated", name)
		}
		if _, exists := refs.sources[artifact.SourceID]; !exists {
			return fmt.Errorf("%s.source_id does not reference a declared source", name)
		}
		if artifact.SizeBytes < 1 || artifact.SizeBytes > 8<<30 {
			return fmt.Errorf("%s.size_bytes must be between 1 and 8 GiB", name)
		}
		root := "/usr/local/share/dirextalk-worker/artifacts/"
		if !strings.HasPrefix(artifact.TargetPath, root) || path.Clean(artifact.TargetPath) != artifact.TargetPath || artifact.TargetPath == strings.TrimSuffix(root, "/") || strings.Contains(artifact.TargetPath, "\\") {
			return fmt.Errorf("%s.target_path must be a clean preinstalled artifact path", name)
		}
		artifacts[artifact.Name] = artifact
	}
	commands := make(map[string]struct{}, len(value.Commands))
	for index, command := range value.Commands {
		name := fmt.Sprintf("install.installer.commands[%d]", index)
		if err := validateIdentifier(name+".command_id", command.CommandID); err != nil {
			return err
		}
		if _, duplicate := commands[command.CommandID]; duplicate {
			return fmt.Errorf("%s.command_id is duplicated", name)
		}
		commands[command.CommandID] = struct{}{}
		if len(command.Argv) == 0 || len(command.Argv) > 128 || command.TimeoutSeconds == 0 || command.TimeoutSeconds > 24*60*60 {
			return fmt.Errorf("%s argv or timeout is invalid", name)
		}
		if !path.IsAbs(command.WorkingDirectory) || path.Clean(command.WorkingDirectory) != command.WorkingDirectory || strings.Contains(command.WorkingDirectory, "\\") {
			return fmt.Errorf("%s.working_directory must be a clean absolute Worker path", name)
		}
		if err := validateInstallerCommandArgv(name, command.Argv); err != nil {
			return err
		}
		if err := validateInstallerRefs(name+".artifact_refs", command.ArtifactRefs, func(reference string) bool { _, ok := artifacts[reference]; return ok }); err != nil {
			return err
		}
		if len(command.ArtifactRefs) == 0 {
			return fmt.Errorf("%s.artifact_refs must lock the executable", name)
		}
		executableLocked := false
		for _, reference := range command.ArtifactRefs {
			if artifacts[reference].TargetPath == command.Argv[0] {
				executableLocked = true
				break
			}
		}
		if !executableLocked {
			return fmt.Errorf("%s argv executable is not a referenced digest-locked artifact", name)
		}
		if err := validateInstallerRefs(name+".volume_slot_refs", command.VolumeSlotRefs, func(reference string) bool { _, ok := refs.volumes[reference]; return ok }); err != nil {
			return err
		}
		if err := validateInstallerRefs(name+".secret_slot_refs", command.SecretSlotRefs, func(reference string) bool { _, ok := refs.secrets[reference]; return ok }); err != nil {
			return err
		}
	}
	return nil
}

func validateInstallerCommandArgv(name string, values []string) error {
	for index, value := range values {
		if value == "" || len(value) > 16<<10 || strings.ContainsAny(value, "\x00\r\n") {
			return fmt.Errorf("%s.argv[%d] is invalid", name, index)
		}
	}
	base := strings.ToLower(path.Base(values[0]))
	switch base {
	case "sh", "bash", "dash", "ash", "zsh", "ksh", "fish", "eval", "powershell", "pwsh", "cmd", "cmd.exe":
		return fmt.Errorf("%s.argv cannot invoke a shell or evaluator", name)
	}
	return nil
}

func validateInstallerRefs(name string, values []string, declared func(string) bool) error {
	seen := make(map[string]struct{}, len(values))
	for index, value := range values {
		if err := validateIdentifier(fmt.Sprintf("%s[%d]", name, index), value); err != nil {
			return err
		}
		if _, duplicate := seen[value]; duplicate || !declared(value) {
			return fmt.Errorf("%s contains a duplicate or undeclared reference", name)
		}
		seen[value] = struct{}{}
	}
	return nil
}

func validateActionInputReference(name string, input ActionInputV1, refs recipeReferences) error {
	var set map[string]struct{}
	switch input.Kind {
	case ActionInputConfig:
		return nil
	case ActionInputSource:
		set = refs.sources
	case ActionInputVolumeSlot:
		set = refs.volumes
	case ActionInputDataSlot:
		set = refs.data
	case ActionInputSecretSlot:
		set = refs.secrets
	default:
		return fmt.Errorf("%s.kind is invalid", name)
	}
	if _, exists := set[input.Ref]; !exists {
		return fmt.Errorf("%s.ref does not reference the declared %s", name, input.Kind)
	}
	return nil
}

func validateProbe(name string, value ProbeV1) error {
	if err := validateText(name+".target", value.Target, 1, 512); err != nil {
		return err
	}
	if value.TimeoutSeconds > 300 {
		return fmt.Errorf("%s.timeout_seconds must not exceed 300", name)
	}
	switch value.Kind {
	case ProbeHTTP:
		parsed, err := url.ParseRequestURI(value.Target)
		if err != nil || parsed.IsAbs() || parsed.Host != "" || parsed.RawQuery != "" || parsed.Fragment != "" || !strings.HasPrefix(parsed.Path, "/") || path.Clean(parsed.Path) != parsed.Path {
			return fmt.Errorf("%s.target must be a clean service-local path without query or fragment", name)
		}
	case ProbeTCP:
		host, port, err := net.SplitHostPort(value.Target)
		parsedPort, parseErr := strconv.ParseUint(port, 10, 16)
		if err != nil || parseErr != nil || parsedPort == 0 || host == "" || host == "0.0.0.0" || host == "::" || host == "*" {
			return fmt.Errorf("%s.target must be a non-wildcard host:port endpoint", name)
		}
	case ProbeAction:
		if err := validateIdentifier(name+".target", value.Target); err != nil {
			return err
		}
	default:
		return fmt.Errorf("%s.kind is invalid", name)
	}
	return nil
}

func validateLifecycle(value LifecycleContractV1) error {
	actions := []struct {
		name  string
		value string
	}{
		{"start", value.Start}, {"stop", value.Stop}, {"maintenance", value.Maintenance}, {"restart", value.Restart},
		{"upgrade", value.Upgrade}, {"rollback", value.Rollback}, {"backup", value.Backup},
		{"restore", value.Restore}, {"destroy", value.Destroy},
	}
	for _, action := range actions {
		if err := validateIdentifier("lifecycle."+action.name, action.value); err != nil {
			return err
		}
	}
	return nil
}

func validateNetwork(value *NetworkContractV1, refs *recipeReferences) error {
	refs.listeners = make(map[string]struct{})
	if value == nil {
		return nil
	}
	if !value.DefaultDeny {
		return fmt.Errorf("network.default_deny must be true")
	}
	if len(value.Outbound) > 64 || len(value.Listeners) > 32 {
		return fmt.Errorf("network declarations exceed their maximum size")
	}
	seenRules := make(map[string]struct{}, len(value.Outbound))
	for index, rule := range value.Outbound {
		name := fmt.Sprintf("network.outbound[%d]", index)
		if err := validateIdentifier(name+".id", rule.ID); err != nil {
			return err
		}
		if _, exists := seenRules[rule.ID]; exists {
			return fmt.Errorf("%s.id is duplicated", name)
		}
		seenRules[rule.ID] = struct{}{}
		switch rule.Protocol {
		case NetworkHTTPS:
			if rule.Port != 443 {
				return fmt.Errorf("%s HTTPS egress must use port 443", name)
			}
			if err := validatePublicHost(rule.Destination, false); err != nil {
				return fmt.Errorf("%s.destination %w", name, err)
			}
		case NetworkDNS:
			if rule.Destination != "system-resolver" || rule.Port != 53 {
				return fmt.Errorf("%s DNS egress must target system-resolver:53", name)
			}
		default:
			return fmt.Errorf("%s.protocol is invalid", name)
		}
	}
	seenSockets := make(map[string]struct{}, len(value.Listeners))
	for index, listener := range value.Listeners {
		name := fmt.Sprintf("network.listeners[%d]", index)
		if err := validateIdentifier(name+".id", listener.ID); err != nil {
			return err
		}
		if _, exists := refs.listeners[listener.ID]; exists {
			return fmt.Errorf("%s.id is duplicated", name)
		}
		refs.listeners[listener.ID] = struct{}{}
		switch listener.Protocol {
		case ListenerHTTP, ListenerHTTPS, ListenerTCP:
		default:
			return fmt.Errorf("%s.protocol is invalid", name)
		}
		if listener.BindScope != BindLoopback && listener.BindScope != BindPrivate {
			return fmt.Errorf("%s.bind_scope is invalid", name)
		}
		if listener.Port == 0 || listener.Port > 65535 {
			return fmt.Errorf("%s.port is out of range", name)
		}
		socket := fmt.Sprintf("%s:%d", listener.BindScope, listener.Port)
		if _, exists := seenSockets[socket]; exists {
			return fmt.Errorf("%s duplicates a declared bind scope and port", name)
		}
		seenSockets[socket] = struct{}{}
	}
	switch value.PublicIngress.Mode {
	case PublicIngressNone:
		if value.PublicIngress.ListenerID != "" || value.PublicIngress.TLSRequired || value.PublicIngress.AuthenticationRequired {
			return fmt.Errorf("network.public_ingress none must not declare ingress capabilities")
		}
	case PublicIngressManagedTLS:
		if _, exists := refs.listeners[value.PublicIngress.ListenerID]; !exists {
			return fmt.Errorf("network.public_ingress.listener_id must reference a listener")
		}
		if !value.PublicIngress.TLSRequired || !value.PublicIngress.AuthenticationRequired {
			return fmt.Errorf("managed public ingress must require TLS and authentication")
		}
	default:
		return fmt.Errorf("network.public_ingress.mode is invalid")
	}
	return nil
}

func validateRestart(value *RestartContractV1, checkpoints map[string]struct{}) error {
	if value == nil {
		return nil
	}
	if value.Mode != RestartAlways && value.Mode != RestartOnFailure && value.Mode != RestartManual {
		return fmt.Errorf("restart.mode is invalid")
	}
	if err := validateIdentifier("restart.action", value.Action); err != nil {
		return err
	}
	if value.Mode == RestartManual {
		if value.MaxAttempts > 100 {
			return fmt.Errorf("restart.max_attempts must not exceed 100")
		}
	} else if value.MaxAttempts == 0 || value.MaxAttempts > 100 {
		return fmt.Errorf("restart.max_attempts must be between 1 and 100")
	}
	if err := validateUniqueTextSet("restart.recovery_checkpoints", value.RecoveryCheckpoints, 1, 32, 128, true); err != nil {
		return err
	}
	for _, checkpoint := range value.RecoveryCheckpoints {
		if _, exists := checkpoints[checkpoint]; !exists {
			return fmt.Errorf("restart.recovery_checkpoints must reference install checkpoints")
		}
	}
	return nil
}

func validatePairing(value *PairingContractV1) error {
	if value == nil {
		return nil
	}
	if err := validateIdentifier("pairing.begin_action", value.BeginAction); err != nil {
		return err
	}
	if err := validateIdentifier("pairing.resume_action", value.ResumeAction); err != nil {
		return err
	}
	if value.PayloadDelivery != PairingPayloadOnDemandEncrypted {
		return fmt.Errorf("pairing.payload_delivery must be on_demand_encrypted")
	}
	if value.TimeoutSeconds == 0 || value.TimeoutSeconds > 30*24*60*60 {
		return fmt.Errorf("pairing.timeout_seconds must be between 1 and 2592000")
	}
	return nil
}

func validateIntegrations(values []IntegrationDeclarationV1, refs recipeReferences) error {
	if len(values) > 16 {
		return fmt.Errorf("integrations must contain at most 16 entries")
	}
	seen := make(map[string]struct{}, len(values))
	for index, integration := range values {
		name := fmt.Sprintf("integrations[%d]", index)
		if err := validateIdentifier(name+".id", integration.ID); err != nil {
			return err
		}
		if _, exists := seen[integration.ID]; exists {
			return fmt.Errorf("%s.id is duplicated", name)
		}
		seen[integration.ID] = struct{}{}
		if _, exists := refs.listeners[integration.ListenerID]; !exists {
			return fmt.Errorf("%s.listener_id must reference a declared listener", name)
		}
		if integration.SecretSlotID != "" {
			if _, exists := refs.secrets[integration.SecretSlotID]; !exists {
				return fmt.Errorf("%s.secret_slot_id must reference a declared secret slot", name)
			}
		}
		switch integration.Kind {
		case IntegrationMCP:
			if integration.Transport != TransportMCPStreamableHTTP || !integration.AuthenticationRequired {
				return fmt.Errorf("%s MCP must use authenticated Streamable HTTP", name)
			}
		case IntegrationACP:
			if integration.Transport != TransportACP || !integration.AuthenticationRequired {
				return fmt.Errorf("%s ACP must require its typed authenticated transport", name)
			}
		case IntegrationConnector:
			if integration.Transport != TransportConnector || !integration.AuthenticationRequired {
				return fmt.Errorf("%s Connector must require its typed authenticated transport", name)
			}
		case IntegrationWeb:
			if integration.Transport != TransportWebHTTP {
				return fmt.Errorf("%s Web integration transport is invalid", name)
			}
		default:
			return fmt.Errorf("%s.kind is invalid", name)
		}
	}
	return nil
}

func validateMaturity(r RecipeV1, refs recipeReferences) error {
	if r.Maturity == MaturityExperimental {
		if r.ManagedAcceptance != nil {
			return fmt.Errorf("experimental recipes must not contain managed acceptance")
		}
		return nil
	}
	if r.ManagedAcceptance == nil {
		return fmt.Errorf("managed recipes require acceptance")
	}
	if r.Network == nil {
		return fmt.Errorf("managed recipes require an explicit deny-by-default network contract")
	}
	if r.Restart == nil {
		return fmt.Errorf("managed recipes require restart recovery")
	}
	officialRepository := false
	latestRetrieval := time.Time{}
	for index, source := range r.Sources {
		if source.ID == "" || source.Kind == "" {
			return fmt.Errorf("managed sources[%d] require typed identity", index)
		}
		if source.Official && source.Kind == SourceRepository && source.Repository != nil {
			officialRepository = true
		}
		if source.RetrievedAt.After(latestRetrieval) {
			latestRetrieval = source.RetrievedAt
		}
	}
	if !officialRepository {
		return fmt.Errorf("managed recipes require an official repository identity")
	}
	for index, step := range r.Install.Steps {
		if step.Action == "" || step.Checkpoint == "" {
			return fmt.Errorf("managed install.steps[%d] require typed action and checkpoint", index)
		}
	}
	if len(r.Install.AllowedAdaptations) != 0 && len(r.Install.Adaptations) == 0 {
		return fmt.Errorf("managed allowed adaptations require typed action rules")
	}
	for index, volume := range r.VolumeSlots {
		if volume.MountPath == "" {
			return fmt.Errorf("managed volume_slots[%d] require a verified mount mapping", index)
		}
	}
	locations := make(map[string]struct{}, len(r.Requirements.DataLocations))
	for _, location := range r.Requirements.DataLocations {
		locations[location.DataSlotID] = struct{}{}
	}
	for dataSlot := range refs.data {
		if _, exists := locations[dataSlot]; !exists {
			return fmt.Errorf("managed data slots require declared data locations")
		}
	}
	acceptance := r.ManagedAcceptance
	if err := ValidateDigest(acceptance.ExperimentalDigest); err != nil {
		return fmt.Errorf("managed_acceptance.experimental_digest %w", err)
	}
	if err := validateIdentifier("managed_acceptance.acceptance_ref", acceptance.AcceptanceRef); err != nil {
		return err
	}
	if err := validateIdentifier("managed_acceptance.verification_ref", acceptance.VerificationRef); err != nil {
		return err
	}
	if acceptance.AcceptedAt.IsZero() || acceptance.AcceptedAt.Before(latestRetrieval) {
		return fmt.Errorf("managed_acceptance.accepted_at must follow source retrieval")
	}
	experimental := r
	experimental.Maturity = MaturityExperimental
	experimental.ManagedAcceptance = nil
	digest, err := experimental.Digest()
	if err != nil {
		return fmt.Errorf("managed source recipe is invalid")
	}
	if digest != acceptance.ExperimentalDigest {
		return fmt.Errorf("managed acceptance does not bind this experimental recipe")
	}
	return nil
}

func validateUniqueTextSet(name string, values []string, minimum, maximum, maxLength int, identifiers bool) error {
	if len(values) < minimum || len(values) > maximum {
		return fmt.Errorf("%s must contain between %d and %d entries", name, minimum, maximum)
	}
	seen := make(map[string]struct{}, len(values))
	for index, value := range values {
		var err error
		if identifiers {
			err = validateIdentifier(fmt.Sprintf("%s[%d]", name, index), value)
		} else {
			err = validateText(fmt.Sprintf("%s[%d]", name, index), value, 1, maxLength)
		}
		if err != nil {
			return err
		}
		if _, exists := seen[value]; exists {
			return fmt.Errorf("%s contains duplicate value", name)
		}
		seen[value] = struct{}{}
	}
	return nil
}

func validateIdentifier(name, value string) error {
	if !identifierPattern.MatchString(value) {
		return fmt.Errorf("%s is not a valid identifier", name)
	}
	return nil
}

func validateText(name, value string, minimum, maximum int) error {
	if value != strings.TrimSpace(value) || len(value) < minimum || len(value) > maximum {
		return fmt.Errorf("%s must contain %d-%d trimmed bytes", name, minimum, maximum)
	}
	return nil
}

func rejectCredentialMaterial(value reflect.Value) error {
	if !value.IsValid() {
		return nil
	}
	if value.Type() == reflect.TypeOf(time.Time{}) {
		return nil
	}
	for value.Kind() == reflect.Interface || value.Kind() == reflect.Pointer {
		if value.IsNil() {
			return nil
		}
		value = value.Elem()
	}
	switch value.Kind() {
	case reflect.String:
		text := value.String()
		for _, pattern := range credentialPatterns {
			if pattern.MatchString(text) {
				return fmt.Errorf("recipe contains credential-like material")
			}
		}
	case reflect.Struct:
		for index := 0; index < value.NumField(); index++ {
			field := value.Type().Field(index)
			if !field.IsExported() {
				continue
			}
			if err := rejectCredentialMaterial(value.Field(index)); err != nil {
				return err
			}
		}
	case reflect.Array, reflect.Slice:
		for index := 0; index < value.Len(); index++ {
			if err := rejectCredentialMaterial(value.Index(index)); err != nil {
				return err
			}
		}
	case reflect.Map:
		iterator := value.MapRange()
		for iterator.Next() {
			if err := rejectCredentialMaterial(iterator.Key()); err != nil {
				return err
			}
			if err := rejectCredentialMaterial(iterator.Value()); err != nil {
				return err
			}
		}
	}
	return nil
}
