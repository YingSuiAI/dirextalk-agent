package coreexecutionv2

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"time"
)

var (
	sha256RE       = regexp.MustCompile(`^[0-9a-f]{64}$`)
	commitRE       = regexp.MustCompile(`^[0-9a-f]{40}(?:[0-9a-f]{24})?$`)
	nameRE         = regexp.MustCompile(`^[a-z0-9]+(?:[._-][a-z0-9]+)*$`)
	instanceRE     = regexp.MustCompile(`^i-[0-9a-f]{8,32}$`)
	instanceTypeRE = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,31}\.[a-z0-9][a-z0-9-]{0,31}$`)
)

var allowedFields = map[string]map[string]struct{}{
	"projects.analyze": {"project_id": {}, "source": {}, "idempotency_key": {}},
	"analyses.get":     {"analysis_id": {}}, "targets.list": {"page_size": {}, "page_token": {}}, "targets.get": {"target_id": {}, "revision": {}},
	"targets.import": {"credential_id": {}, "credential_revision": {}, "instance_id": {}, "idempotency_key": {}}, "targets.reserve": {"credential_id": {}, "credential_revision": {}, "instance_type": {}, "volume_gib": {}, "idempotency_key": {}}, "targets.observe": {"target_id": {}, "target_revision": {}, "idempotency_key": {}},
	"plans.create": {"project_id": {}, "analysis_id": {}, "intent": {}, "recipe_id": {}, "target_id": {}, "target_revision": {}, "purpose": {}, "ai_configuration": {}, "idempotency_key": {}},
	"plans.revise": {"plan_id": {}, "intent": {}, "recipe_id": {}, "target_id": {}, "target_revision": {}, "purpose": {}, "ai_configuration": {}, "idempotency_key": {}, "expected_revision": {}}, "plans.get": {"record_kind": {}, "plan_id": {}, "revision": {}}, "plans.list": {"record_kind": {}, "page_size": {}, "page_token": {}},
	"deployments.list": {"project_id": {}, "page_size": {}, "page_token": {}}, "deployments.get": {"deployment_id": {}}, "deployments.events": {"deployment_id": {}, "after_sequence": {}, "limit": {}},
	"runs.create": {"record_kind": {}, "plan_id": {}, "plan_revision": {}, "operation": {}, "trigger_kind": {}, "rollback_of_run_id": {}, "idempotency_key": {}}, "runs.get": {"record_kind": {}, "run_id": {}}, "runs.list": {"record_kind": {}, "project_id": {}, "deployment_id": {}, "page_size": {}, "page_token": {}}, "runs.cancel": {"record_kind": {}, "run_id": {}, "idempotency_key": {}, "expected_revision": {}}, "runs.retry": {"record_kind": {}, "run_id": {}, "idempotency_key": {}, "expected_revision": {}}, "runs.events": {"record_kind": {}, "run_id": {}, "after_sequence": {}, "limit": {}},
	"artifacts.get": {"record_kind": {}, "artifact_id": {}}, "artifacts.download": {"record_kind": {}, "artifact_id": {}, "offset_bytes": {}, "max_chunk_bytes": {}}, "service_bindings.list": {"project_id": {}, "page_size": {}, "page_token": {}}, "service_bindings.get": {"binding_id": {}}, "service_bindings.invoke": {"binding_id": {}, "operation": {}, "idempotency_key": {}, "expected_revision": {}, "input": {}},
	"secrets.create": {"provider": {}, "purpose": {}, "value": {}, "idempotency_key": {}}, "secrets.get": {"secret_ref": {}, "revision": {}}, "secrets.list": {"page_size": {}, "page_token": {}}, "secrets.revoke": {"secret_ref": {}, "expected_revision": {}, "idempotency_key": {}},
}

func validateAction(action string, in map[string]any) error {
	bare := strings.TrimPrefix(action, "agent.execution.v2.")
	fields, ok := allowedFields[bare]
	if !ok {
		return ErrUnsupported
	}
	for key := range in {
		if _, ok := fields[key]; !ok {
			return fmt.Errorf("%w: unknown field %s", ErrInvalid, key)
		}
	}
	if _, present := in["record_kind"]; present && stringParam(in, "record_kind") != "cloud_worker" {
		return fmt.Errorf("%w: record_kind must be cloud_worker", ErrInvalid)
	}
	requireID := func(key string) error { _, err := idParam(in, key); return err }
	requireIdem := func() error { _, err := idempotency(in); return err }
	requireRevision := func(key string) error {
		if uintParam(in, key) == 0 {
			return fmt.Errorf("%w: %s must be positive", ErrInvalid, key)
		}
		return nil
	}
	switch bare {
	case "projects.analyze":
		if err := requireID("project_id"); err != nil {
			return err
		}
		if err := requireIdem(); err != nil {
			return err
		}
		return validateSource(in["source"])
	case "analyses.get":
		return requireID("analysis_id")
	case "targets.list", "plans.list", "deployments.list", "runs.list", "service_bindings.list", "secrets.list":
		if err := validatePage(in); err != nil {
			return err
		}
		for _, key := range []string{"project_id", "deployment_id"} {
			if _, present := in[key]; present {
				if _, err := idParam(in, key); err != nil {
					return err
				}
			}
		}
		return nil
	case "targets.get":
		if err := requireID("target_id"); err != nil {
			return err
		}
		return optionalPositive(in, "revision")
	case "targets.import":
		for _, key := range []string{"credential_id", "instance_id"} {
			if key == "instance_id" {
				value := stringParam(in, key)
				if !instanceRE.MatchString(value) {
					return fmt.Errorf("%w: invalid instance_id", ErrInvalid)
				}
			} else if err := requireID(key); err != nil {
				return err
			}
		}
		if err := requireRevision("credential_revision"); err != nil {
			return err
		}
		return requireIdem()
	case "targets.reserve":
		if err := requireID("credential_id"); err != nil {
			return err
		}
		if err := requireRevision("credential_revision"); err != nil {
			return err
		}
		if !instanceTypeRE.MatchString(stringParam(in, "instance_type")) {
			return fmt.Errorf("%w: invalid instance_type", ErrInvalid)
		}
		volume := uintParam(in, "volume_gib")
		if volume < 8 || volume > 16384 {
			return fmt.Errorf("%w: invalid volume_gib", ErrInvalid)
		}
		return requireIdem()
	case "targets.observe":
		if err := requireID("target_id"); err != nil {
			return err
		}
		if err := requireRevision("target_revision"); err != nil {
			return err
		}
		return requireIdem()
	case "plans.create":
		for _, key := range []string{"project_id", "analysis_id", "target_id"} {
			if err := requireID(key); err != nil {
				return err
			}
		}
		if err := requireRevision("target_revision"); err != nil {
			return err
		}
		if err := validatePlanSelection(in); err != nil {
			return err
		}
		return requireIdem()
	case "plans.revise":
		for _, key := range []string{"plan_id", "target_id"} {
			if err := requireID(key); err != nil {
				return err
			}
		}
		if err := requireRevision("target_revision"); err != nil {
			return err
		}
		if err := requireRevision("expected_revision"); err != nil {
			return err
		}
		if err := validatePlanSelection(in); err != nil {
			return err
		}
		return requireIdem()
	case "plans.get":
		if err := requireID("plan_id"); err != nil {
			return err
		}
		return optionalPositive(in, "revision")
	case "deployments.get":
		return requireID("deployment_id")
	case "deployments.events":
		if err := requireID("deployment_id"); err != nil {
			return err
		}
		return validateEvents(in)
	case "runs.create":
		if err := requireID("plan_id"); err != nil {
			return err
		}
		if err := requireRevision("plan_revision"); err != nil {
			return err
		}
		if err := requireIdem(); err != nil {
			return err
		}
		operation := stringParam(in, "operation")
		switch operation {
		case "execute", "deploy", "upgrade", "repair", "destroy":
			if _, ok := in["rollback_of_run_id"]; ok {
				return fmt.Errorf("%w: rollback_of_run_id only applies to rollback", ErrInvalid)
			}
		case "rollback":
			if err := requireID("rollback_of_run_id"); err != nil {
				return err
			}
		default:
			return fmt.Errorf("%w: invalid operation", ErrInvalid)
		}
		if trigger := stringParam(in, "trigger_kind"); trigger != "" {
			switch trigger {
			case "manual", "schedule", "retry", "rollback":
			default:
				return fmt.Errorf("%w: invalid trigger_kind", ErrInvalid)
			}
		}
		return nil
	case "runs.get":
		return requireID("run_id")
	case "runs.cancel", "runs.retry":
		if err := requireID("run_id"); err != nil {
			return err
		}
		if err := requireRevision("expected_revision"); err != nil {
			return err
		}
		return requireIdem()
	case "runs.events":
		if err := requireID("run_id"); err != nil {
			return err
		}
		return validateEvents(in)
	case "artifacts.get":
		return requireID("artifact_id")
	case "artifacts.download":
		if stringParam(in, "record_kind") != RecordKindCloudWorker {
			return fmt.Errorf("%w: record_kind=cloud_worker is required", ErrInvalid)
		}
		if err := requireID("artifact_id"); err != nil {
			return err
		}
		if _, ok := exactBoundedUint(in, "offset_bytes", true, MaxCloudWorkerArtifactDownloadOffsetBytes); !ok {
			return fmt.Errorf("%w: offset_bytes must be a bounded nonnegative integer", ErrInvalid)
		}
		if _, ok := exactBoundedUint(in, "max_chunk_bytes", false, MaxCloudWorkerArtifactDownloadChunkBytes); !ok {
			return fmt.Errorf("%w: max_chunk_bytes must be between 1 and %d", ErrInvalid, MaxCloudWorkerArtifactDownloadChunkBytes)
		}
		return nil
	case "service_bindings.get":
		return requireID("binding_id")
	case "service_bindings.invoke":
		if err := requireID("binding_id"); err != nil {
			return err
		}
		if err := requireRevision("expected_revision"); err != nil {
			return err
		}
		if err := requireIdem(); err != nil {
			return err
		}
		if stringParam(in, "operation") == "" {
			return fmt.Errorf("%w: operation is required", ErrInvalid)
		}
		if _, ok := in["input"].(map[string]any); !ok {
			return fmt.Errorf("%w: input must be an object", ErrInvalid)
		}
		return validateSafeInput(in["input"])
	case "secrets.create":
		if !nameRE.MatchString(stringParam(in, "provider")) {
			return fmt.Errorf("%w: invalid provider", ErrInvalid)
		}
		if stringParam(in, "purpose") != "ai_provider_api_key" {
			return fmt.Errorf("%w: invalid purpose", ErrInvalid)
		}
		value, ok := in["value"].(string)
		if !ok || value == "" || len(value) > 16<<10 || strings.TrimSpace(value) != value || strings.ContainsAny(value, "\x00\r\n") {
			return fmt.Errorf("%w: invalid secret value", ErrInvalid)
		}
		return requireIdem()
	case "secrets.get":
		if err := requireID("secret_ref"); err != nil {
			return err
		}
		return optionalPositive(in, "revision")
	case "secrets.revoke":
		if err := requireID("secret_ref"); err != nil {
			return err
		}
		if err := requireRevision("expected_revision"); err != nil {
			return err
		}
		return requireIdem()
	}
	return nil
}

func exactBoundedUint(in map[string]any, key string, allowZero bool, maximum uint64) (uint64, bool) {
	value, present := in[key]
	if !present {
		return 0, false
	}
	var result uint64
	switch current := value.(type) {
	case float64:
		if current < 0 || current > float64(maximum) || current != float64(uint64(current)) {
			return 0, false
		}
		result = uint64(current)
	case int:
		if current < 0 {
			return 0, false
		}
		result = uint64(current)
	case int64:
		if current < 0 {
			return 0, false
		}
		result = uint64(current)
	case uint64:
		result = current
	default:
		return 0, false
	}
	if result > maximum || (!allowZero && result == 0) {
		return 0, false
	}
	return result, true
}

func optionalPositive(in map[string]any, key string) error {
	if _, ok := in[key]; ok && uintParam(in, key) == 0 {
		return fmt.Errorf("%w: %s must be positive", ErrInvalid, key)
	}
	return nil
}
func validatePage(in map[string]any) error {
	if _, ok := in["page_size"]; ok {
		n := intParam(in, "page_size", -1)
		if n < 1 || n > 200 {
			return fmt.Errorf("%w: invalid page_size", ErrInvalid)
		}
	}
	return nil
}
func validateEvents(in map[string]any) error {
	if _, ok := in["limit"]; ok {
		n := intParam(in, "limit", -1)
		if n < 1 || n > 200 {
			return fmt.Errorf("%w: invalid limit", ErrInvalid)
		}
	}
	return nil
}

func validateSource(raw any) error {
	m, ok := raw.(map[string]any)
	if !ok {
		return fmt.Errorf("%w: source must be an object", ErrInvalid)
	}
	for key := range m {
		switch key {
		case "kind", "location", "commit", "artifact_id", "credential_ref", "credential_revision", "immutable":
		default:
			return fmt.Errorf("%w: unknown source field %s", ErrInvalid, key)
		}
	}
	if !boolValue(m, "immutable") {
		return fmt.Errorf("%w: source must be immutable", ErrInvalid)
	}
	kind, location, commit := stringParam(m, "kind"), stringParam(m, "location"), stringParam(m, "commit")
	credentialRef, credentialRevision := stringParam(m, "credential_ref"), uintParam(m, "credential_revision")
	if (credentialRef == "") != (credentialRevision == 0) {
		return fmt.Errorf("%w: credential_ref and credential_revision must be supplied together", ErrInvalid)
	}
	if credentialRef != "" {
		if _, err := idParam(m, "credential_ref"); err != nil {
			return err
		}
	}
	switch kind {
	case "git_https":
		u, err := url.Parse(location)
		if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Fragment != "" || !commitRE.MatchString(commit) {
			return fmt.Errorf("%w: git source must pin an HTTPS commit", ErrInvalid)
		}
		if stringParam(m, "artifact_id") != "" {
			return fmt.Errorf("%w: git_https source cannot include artifact_id", ErrInvalid)
		}
	case "oci_image":
		parts := strings.Split(location, "@sha256:")
		if len(parts) != 2 || parts[0] == "" || !sha256RE.MatchString(parts[1]) || commit != "" || stringParam(m, "artifact_id") != "" || credentialRef != "" {
			return fmt.Errorf("%w: OCI source must be digest pinned", ErrInvalid)
		}
	case "uploaded_artifact":
		if _, err := idParam(m, "artifact_id"); err != nil {
			return err
		}
		if stringParam(m, "location") != "" || stringParam(m, "commit") != "" || stringParam(m, "credential_ref") != "" || uintParam(m, "credential_revision") != 0 {
			return fmt.Errorf("%w: uploaded artifact source must be immutable and standalone", ErrInvalid)
		}
	default:
		return fmt.Errorf("%w: unsupported source kind", ErrInvalid)
	}
	return nil
}

func validatePlanSelection(in map[string]any) error {
	if stringParam(in, "intent") == "" || stringParam(in, "recipe_id") == "" || !nameRE.MatchString(stringParam(in, "intent")) || !nameRE.MatchString(stringParam(in, "recipe_id")) {
		return fmt.Errorf("%w: plan selection is incomplete", ErrInvalid)
	}
	purpose := stringParam(in, "purpose")
	if purpose != "service" && purpose != "job" {
		return fmt.Errorf("%w: invalid purpose", ErrInvalid)
	}
	if stringParam(in, "recipe_id") == "generic-container-service" && (stringParam(in, "intent") != "deploy" || purpose != "service") {
		return fmt.Errorf("%w: generic-container-service supports deploy only", ErrInvalid)
	}
	if _, err := CompileApprovedPlan(stringParam(in, "recipe_id"), stringParam(in, "intent"), purpose); err != nil {
		return err
	}
	if raw, ok := in["ai_configuration"]; ok {
		config, ok := raw.(map[string]any)
		if !ok {
			return fmt.Errorf("%w: ai_configuration must be an object", ErrInvalid)
		}
		for key := range config {
			switch key {
			case "mode", "provider", "secret_ref", "secret_revision", "secret_purpose", "secret_binding_digest", "status":
			default:
				return fmt.Errorf("%w: unknown ai_configuration field %s", ErrInvalid, key)
			}
		}
		mode, provider := stringParam(config, "mode"), stringParam(config, "provider")
		if !nameRE.MatchString(provider) {
			return fmt.Errorf("%w: invalid ai_configuration provider", ErrInvalid)
		}
		switch mode {
		case "api_key":
			if _, err := idParam(config, "secret_ref"); err != nil {
				return err
			}
			if uintParam(config, "secret_revision") == 0 || stringParam(config, "secret_purpose") != "ai_provider_api_key" || !sha256RE.MatchString(stringParam(config, "secret_binding_digest")) {
				return fmt.Errorf("%w: invalid ai_configuration secret binding", ErrInvalid)
			}
		case "auth_gate":
			if stringParam(config, "status") != "pending_external_auth" {
				return fmt.Errorf("%w: invalid ai_configuration status", ErrInvalid)
			}
		default:
			return fmt.Errorf("%w: invalid ai_configuration mode", ErrInvalid)
		}
	}
	return nil
}

func compiledPlanPayload(in map[string]any) (map[string]any, error) {
	compiled, err := CompileApprovedPlan(stringParam(in, "recipe_id"), stringParam(in, "intent"), stringParam(in, "purpose"))
	if err != nil {
		return nil, err
	}
	steps := make([]any, 0, len(compiled.Steps))
	for _, step := range compiled.Steps {
		steps = append(steps, map[string]any{"type": step.Type, "operation": step.Operation, "service": step.Service})
	}
	commands := make([]any, 0, len(compiled.Commands))
	for _, command := range compiled.Commands {
		commands = append(commands, command)
	}
	return map[string]any{
		"command_steps":          commands,
		"command_step_specs":     steps,
		"command_steps_digest":   compiled.CommandStepsDigest,
		"recipe_digest":          compiled.RecipeDigest,
		"command_schema_version": "systemd/v1",
	}, nil
}

func boolValue(in map[string]any, key string) bool { value, _ := in[key].(bool); return value }

func validateSafeInput(value any) error {
	var walk func(any, int) bool
	walk = func(v any, depth int) bool {
		if depth > 16 {
			return false
		}
		switch x := v.(type) {
		case map[string]any:
			for key, nested := range x {
				normalized := strings.ToLower(strings.ReplaceAll(strings.ReplaceAll(strings.TrimSpace(key), "-", "_"), ".", "_"))
				switch normalized {
				case "authorization", "password", "passwd", "secret", "token", "access_token", "api_key", "private_key", "aws_access_key_id", "aws_secret_access_key", "cookie", "set_cookie":
					return false
				}
				if !walk(nested, depth+1) {
					return false
				}
			}
		case []any:
			for _, nested := range x {
				if !walk(nested, depth+1) {
					return false
				}
			}
		case string:
			return len(x) <= 16<<10
		case nil, bool, float64:
			return true
		default:
			return false
		}
		return true
	}
	if !walk(value, 0) {
		return ErrUnsafeOutput
	}
	return nil
}

func validateProviderPayload(payload map[string]any) error {
	if payload == nil {
		return ErrUnsafeOutput
	}
	return validateSafeInput(payload)
}

func (s *Service) handleMutation(ctx context.Context, authority Authority, action string, in map[string]any) (map[string]any, error) {
	owner := strings.TrimSpace(authority.OwnerID)
	idem, err := idempotency(in)
	if err != nil {
		return nil, err
	}
	digest, _, err := requestDigest(action, in)
	if err != nil {
		return nil, err
	}
	if replay, ok, err := s.replay(ctx, owner, action, idem, digest); err != nil || ok {
		return replay, err
	}
	bare := strings.TrimPrefix(action, "agent.execution.v2.")
	var result map[string]any
	switch bare {
	case "projects.analyze":
		var payload map[string]any
		if s.providers.Analyze != nil {
			payload, err = s.providers.Analyze(ctx, owner, in)
		} else {
			err = ErrMissingPort
		}
		if err == nil {
			if err = validateProviderPayload(payload); err != nil {
				break
			}
			if _, idErr := idParam(payload, "analysis_id"); idErr != nil {
				err = fmt.Errorf("%w: provider analysis_id is invalid", ErrUnsafeOutput)
				break
			}
			id := deterministicID(owner, action, idem)
			record, e := s.putNew(ctx, owner, "analysis", id, "ready", payload)
			err = e
			if err == nil {
				_ = s.emit(ctx, record, "analysis_created", payload)
				result = map[string]any{"analysis": publicRecord(record)}
			}
		}
	case "targets.import", "targets.reserve", "targets.observe":
		var payload map[string]any
		switch bare {
		case "targets.import":
			if s.providers.ImportTarget != nil {
				payload, err = s.providers.ImportTarget(ctx, owner, in)
			} else {
				err = ErrMissingPort
			}
		case "targets.reserve":
			if s.providers.ReserveTarget != nil {
				payload, err = s.providers.ReserveTarget(ctx, owner, in)
			} else {
				err = ErrMissingPort
			}
		case "targets.observe":
			if s.providers.Observe != nil {
				payload, err = s.providers.Observe(ctx, owner, in)
			} else {
				err = ErrMissingPort
			}
		}
		if err == nil {
			if err = validateProviderPayload(payload); err != nil {
				break
			}
			if bare == "targets.observe" {
				// Observation is a readback fact, not a second target row. Keep
				// the durable target revision untouched and return the provider's
				// redacted observation envelope; the event journal remains the
				// replayable audit trail for this readback.
				id := stringParam(payload, "target_id")
				if id == "" {
					id = stringParam(in, "target_id")
				}
				if id == "" {
					err = ErrUnsafeOutput
					break
				}
				if _, idErr := idParam(map[string]any{"target_id": id}, "target_id"); idErr != nil {
					err = fmt.Errorf("%w: provider target_id is invalid", ErrUnsafeOutput)
					break
				}
				if existing, readErr := s.store.Read(ctx, owner, "target", id, 0); readErr == nil {
					_ = s.emit(ctx, existing, "target_observed", payload)
				} else if !errors.Is(readErr, ErrNotFound) {
					err = readErr
					break
				}
				result = map[string]any{"observation": ownedPayload(owner, payload)}
				break
			}
			id := stringParam(payload, "target_id")
			if id == "" {
				if bare == "targets.import" || bare == "targets.reserve" {
					err = fmt.Errorf("%w: provider target_id is required", ErrUnsafeOutput)
					break
				}
				id = deterministicID(owner, action, idem)
			}
			if _, idErr := idParam(map[string]any{"target_id": id}, "target_id"); idErr != nil {
				err = fmt.Errorf("%w: provider target_id is invalid", ErrUnsafeOutput)
				break
			}
			record, e := s.putNew(ctx, owner, "target", id, "active", payload)
			err = e
			if err == nil {
				_ = s.emit(ctx, record, "target_changed", payload)
				result = map[string]any{"target": publicRecord(record)}
				if bare == "targets.observe" {
					result = map[string]any{"observation": publicRecord(record)}
				}
				if bare == "targets.import" {
					if observationID := stringParam(payload, "observation_id"); observationID != "" {
						result["observation_id"] = observationID
						if observation, ok := payload["observation"].(map[string]any); ok {
							result["observation"] = ownedPayload(owner, observation)
						}
					}
				}
			}
		}
	case "plans.create":
		id := deterministicID(owner, action, idem)
		compiled, compileErr := compiledPlanPayload(in)
		if compileErr != nil {
			err = compileErr
			break
		}
		payload := map[string]any{"project_id": stringParam(in, "project_id"), "analysis_id": stringParam(in, "analysis_id"), "target_id": stringParam(in, "target_id"), "target_revision": uintParam(in, "target_revision"), "intent": stringParam(in, "intent"), "recipe_id": stringParam(in, "recipe_id"), "purpose": stringParam(in, "purpose"), "status": "ready", "schema_version": SchemaVersion}
		for key, value := range compiled {
			payload[key] = value
		}
		record, e := s.putNew(ctx, owner, "plan", id, "ready", payload)
		err = e
		if err == nil {
			_ = s.emit(ctx, record, "plan_created", payload)
			result = map[string]any{"plan": publicRecord(record)}
		}
	case "plans.revise":
		id, _ := idParam(in, "plan_id")
		existing, e := s.store.Read(ctx, owner, "plan", id, 0)
		if e != nil {
			err = e
		} else if existing.Revision != uintParam(in, "expected_revision") {
			err = ErrConflict
		} else {
			payload := cloneMap(existing.Payload)
			for _, key := range []string{"intent", "recipe_id", "target_id", "target_revision", "purpose", "ai_configuration"} {
				if value, ok := in[key]; ok {
					payload[key] = value
				}
			}
			compiled, compileErr := compiledPlanPayload(payload)
			if compileErr != nil {
				err = compileErr
				break
			}
			for key, value := range compiled {
				payload[key] = value
			}
			updated, e := s.update(ctx, existing, "ready", payload)
			err = e
			if err == nil {
				_ = s.emit(ctx, updated, "plan_revised", payload)
				result = map[string]any{"plan": publicRecord(updated)}
			}
		}
	case "runs.create":
		if s.runLifecycle == nil || s.providers.Reconcile == nil {
			err = ErrMissingPort
			break
		}
		planID, _ := idParam(in, "plan_id")
		plan, planErr := s.store.Read(ctx, owner, "plan", planID, uintParam(in, "plan_revision"))
		if planErr != nil {
			err = planErr
			break
		}
		command, commandErr := newGenericRunCreateCommand(authority, plan, stringParam(in, "operation"), stringParam(in, "trigger_kind"), stringParam(in, "rollback_of_run_id"), "", idem, s.now().UTC())
		if commandErr != nil {
			err = commandErr
			break
		}
		envelope, createErr := s.runLifecycle.CreateGenericRun(ctx, command)
		if createErr != nil {
			err = createErr
			break
		}
		result = map[string]any{"run": publicRecord(envelope.Run), "stages": []any{stageView(envelope.Stage)}}
	case "runs.retry":
		if s.runLifecycle == nil || s.providers.Reconcile == nil {
			err = ErrMissingPort
			break
		}
		id, _ := idParam(in, "run_id")
		existing, readErr := s.store.Read(ctx, owner, "run", id, 0)
		if readErr != nil {
			err = readErr
			break
		}
		if existing.Revision != uintParam(in, "expected_revision") {
			err = ErrConflict
			break
		}
		switch existing.Status {
		case "failed", "canceled", "rejected", "expired":
		default:
			err = fmt.Errorf("%w: only a terminal unsuccessful run can be retried", ErrConflict)
			break
		}
		if err != nil {
			break
		}
		planID := stringParam(existing.Payload, "plan_id")
		plan, planErr := s.store.Read(ctx, owner, "plan", planID, uintParam(existing.Payload, "plan_revision"))
		if planErr != nil {
			err = planErr
			break
		}
		command, commandErr := newGenericRunCreateCommand(authority, plan, stringParam(existing.Payload, "operation"), "retry", stringParam(existing.Payload, "rollback_of_run_id"), existing.ID, idem, s.now().UTC())
		if commandErr != nil {
			err = commandErr
			break
		}
		envelope, createErr := s.runLifecycle.CreateGenericRun(ctx, command)
		if createErr != nil {
			err = createErr
			break
		}
		result = map[string]any{"run": publicRecord(envelope.Run), "stages": []any{stageView(envelope.Stage)}}
	case "runs.cancel":
		if s.runLifecycle == nil {
			err = ErrMissingPort
			break
		}
		id, _ := idParam(in, "run_id")
		envelope, cancelErr := s.runLifecycle.CancelGenericRun(ctx, GenericRunCancelCommand{Authority: authority, RunID: id, ExpectedRevision: uintParam(in, "expected_revision"), IdempotencyKey: idem, At: s.now().UTC()})
		err = cancelErr
		if err == nil {
			result = map[string]any{"run": publicRecord(envelope.Run), "stages": []any{stageView(envelope.Stage)}}
		}
	case "service_bindings.invoke":
		if s.providers.Invoke == nil {
			err = ErrMissingPort
		} else {
			payload, e := s.providers.Invoke(ctx, owner, in)
			err = e
			if err == nil {
				if e = validateSafeInput(payload); e != nil {
					err = e
				} else {
					result = map[string]any{"result": payload}
				}
			}
		}
	default:
		// All mutation tokens are explicit above.  A future action must extend
		// the allow-list and handler together; no generic passthrough exists.
		err = ErrUnsupported
	}
	if err != nil {
		return nil, err
	}
	if err := s.saveReplay(ctx, owner, action, idem, digest, result); err != nil {
		return nil, err
	}
	return result, nil
}

func (s *Service) handleSecret(ctx context.Context, owner, action string, in map[string]any) (map[string]any, error) {
	if action == "agent.execution.v2.secrets.get" || action == "agent.execution.v2.secrets.list" {
		if action == "agent.execution.v2.secrets.get" {
			ref, _ := idParam(in, "secret_ref")
			secret, err := s.store.ReadSecret(ctx, owner, ref, uintParam(in, "revision"))
			if err != nil {
				return nil, err
			}
			return map[string]any{"secret": publicSecret(secret)}, nil
		}
		items, next, err := s.store.ListSecrets(ctx, owner, stringParam(in, "page_token"), intParam(in, "page_size", 100))
		if err != nil {
			return nil, err
		}
		values := make([]any, 0, len(items))
		for _, item := range items {
			values = append(values, publicSecret(item))
		}
		return map[string]any{"secrets": values, "next_page_token": next}, nil
	}
	idem, err := idempotency(in)
	if err != nil {
		return nil, err
	}
	digest, _, err := requestDigest(action, in)
	if err != nil {
		return nil, err
	}
	if replay, ok, err := s.replay(ctx, owner, action, idem, digest); err != nil || ok {
		return replay, err
	}
	switch action {
	case "agent.execution.v2.secrets.create":
		value := stringParam(in, "value")
		sum := sha256.Sum256([]byte(value))
		ref := deterministicID(owner, action, idem)
		now := s.now().UTC()
		secret, e := s.store.SaveSecret(ctx, Secret{OwnerID: owner, Ref: ref, Revision: 1, Provider: stringParam(in, "provider"), Purpose: stringParam(in, "purpose"), Value: value, BindingDigest: hex.EncodeToString(sum[:]), Status: "active", CreatedAt: now, UpdatedAt: now})
		if e != nil {
			return nil, e
		}
		result := map[string]any{"secret": publicSecret(secret)}
		if e = s.saveReplay(ctx, owner, action, idem, digest, result); e != nil {
			return nil, e
		}
		return result, nil
	case "agent.execution.v2.secrets.revoke":
		ref, _ := idParam(in, "secret_ref")
		secret, e := s.store.ReadSecret(ctx, owner, ref, 0)
		if e != nil {
			return nil, e
		}
		if secret.Revision != uintParam(in, "expected_revision") {
			return nil, ErrConflict
		}
		secret.Status = "revoked"
		secret.UpdatedAt = s.now().UTC()
		updated, e := s.store.RevokeSecret(ctx, secret, secret.Revision)
		if e != nil {
			return nil, e
		}
		result := map[string]any{"secret": publicSecret(updated)}
		if e = s.saveReplay(ctx, owner, action, idem, digest, result); e != nil {
			return nil, e
		}
		return result, nil
	default:
		return nil, ErrUnsupported
	}
}

func publicSecret(secret Secret) map[string]any {
	return map[string]any{"secret_ref": secret.Ref, "revision": secret.Revision, "provider": secret.Provider, "purpose": secret.Purpose, "binding_digest": secret.BindingDigest, "status": secret.Status, "created_at": secret.CreatedAt.UTC().Format(time.RFC3339Nano), "updated_at": secret.UpdatedAt.UTC().Format(time.RFC3339Nano)}
}
