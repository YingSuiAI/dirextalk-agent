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

	"github.com/YingSuiAI/dirextalk-agent/internal/coretask"
	"github.com/google/uuid"
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
	"plans.revise": {"plan_id": {}, "intent": {}, "recipe_id": {}, "target_id": {}, "target_revision": {}, "purpose": {}, "ai_configuration": {}, "idempotency_key": {}, "expected_revision": {}}, "plans.get": {"plan_id": {}, "revision": {}}, "plans.list": {"page_size": {}, "page_token": {}},
	"deployments.list": {"project_id": {}, "page_size": {}, "page_token": {}}, "deployments.get": {"deployment_id": {}}, "deployments.events": {"deployment_id": {}, "after_sequence": {}, "limit": {}},
	"runs.create": {"plan_id": {}, "plan_revision": {}, "operation": {}, "trigger_kind": {}, "rollback_of_run_id": {}, "idempotency_key": {}}, "runs.get": {"run_id": {}}, "runs.list": {"project_id": {}, "deployment_id": {}, "page_size": {}, "page_token": {}}, "runs.cancel": {"run_id": {}, "idempotency_key": {}, "expected_revision": {}}, "runs.retry": {"run_id": {}, "idempotency_key": {}, "expected_revision": {}}, "runs.reconcile": {"run_id": {}, "stage_id": {}, "idempotency_key": {}, "expected_revision": {}}, "runs.events": {"run_id": {}, "after_sequence": {}, "limit": {}},
	"confirmations.get": {"confirmation_id": {}}, "confirmations.list": {"page_size": {}, "page_token": {}, "states": {}}, "confirmations.confirm": {"confirmation_id": {}, "idempotency_key": {}, "expected_revision": {}}, "confirmations.reject": {"confirmation_id": {}, "idempotency_key": {}, "expected_revision": {}},
	"artifacts.get": {"artifact_id": {}}, "service_bindings.list": {"project_id": {}, "page_size": {}, "page_token": {}}, "service_bindings.get": {"binding_id": {}}, "service_bindings.invoke": {"binding_id": {}, "operation": {}, "idempotency_key": {}, "expected_revision": {}, "input": {}},
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
	case "targets.list", "plans.list", "deployments.list", "runs.list", "confirmations.list", "service_bindings.list", "secrets.list":
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
		if bare == "confirmations.list" {
			if raw, ok := in["states"]; ok {
				values := stateValues(raw)
				if values == nil || len(values) > 5 {
					return fmt.Errorf("%w: states must be an array", ErrInvalid)
				}
				seen := map[string]bool{}
				for _, state := range values {
					switch state {
					case "pending", "confirmed", "consumed", "rejected", "expired":
					default:
						return fmt.Errorf("%w: invalid confirmation state", ErrInvalid)
					}
					if seen[state] {
						return fmt.Errorf("%w: duplicate confirmation state", ErrInvalid)
					}
					seen[state] = true
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
		if operation == "" {
			return fmt.Errorf("%w: operation is required", ErrInvalid)
		}
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
	case "runs.reconcile":
		if err := requireID("run_id"); err != nil {
			return err
		}
		if err := requireID("stage_id"); err != nil {
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
	case "confirmations.get":
		return requireID("confirmation_id")
	case "confirmations.confirm", "confirmations.reject":
		if err := requireID("confirmation_id"); err != nil {
			return err
		}
		if err := requireRevision("expected_revision"); err != nil {
			return err
		}
		return requireIdem()
	case "artifacts.get":
		return requireID("artifact_id")
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

func stateValues(raw any) []string {
	switch values := raw.(type) {
	case []any:
		out := make([]string, 0, len(values))
		for _, value := range values {
			state, ok := value.(string)
			if !ok {
				return nil
			}
			out = append(out, state)
		}
		return out
	case []string:
		return append([]string(nil), values...)
	default:
		return nil
	}
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

func (s *Service) handleMutation(ctx context.Context, scope coretask.OwnerScope, action string, in map[string]any) (map[string]any, error) {
	idem, err := idempotency(in)
	if err != nil {
		return nil, err
	}
	digest, _, err := requestDigest(action, in)
	if err != nil {
		return nil, err
	}
	replay, ok, claim, err := s.beginReplay(ctx, scope, action, idem, digest)
	if err != nil || ok {
		return replay, err
	}
	ctx = context.WithValue(ctx, replayIdentityContextKey{}, replayIdentity{action: action, key: idem, digest: append([]byte(nil), digest...)})
	completed := false
	dispatched := claim.Dispatched
	defer func() {
		if !completed && !dispatched {
			_ = s.store.AbortReplay(context.WithoutCancel(ctx), scope, action, idem, digest, claim.Token)
		}
	}()
	bare := strings.TrimPrefix(action, "agent.execution.v2.")
	var result map[string]any
	switch bare {
	case "projects.analyze":
		if s.providers.Analyze == nil {
			err = ErrMissingPort
			break
		}
		var payload map[string]any
		var providerDispatched bool
		payload, providerDispatched, err = s.providerPayload(ctx, scope, action, idem, digest, claim, func() (map[string]any, error) {
			return s.providers.Analyze(ctx, scope, in)
		}, func(payload map[string]any) error {
			if err := validateProviderPayload(payload); err != nil {
				return err
			}
			if _, idErr := idParam(payload, "analysis_id"); idErr != nil {
				return fmt.Errorf("%w: provider analysis_id is invalid", ErrUnsafeOutput)
			}
			return nil
		})
		dispatched = dispatched || providerDispatched
		if err == nil {
			id := deterministicID(scope, action, idem)
			record, e := s.putNew(ctx, scope, "analysis", id, "ready", payload)
			err = e
			if err == nil {
				if err = s.emit(ctx, record, "analysis_created", payload); err != nil {
					break
				}
				result = map[string]any{"analysis": publicRecord(record)}
			}
		}
	case "targets.import", "targets.reserve", "targets.observe":
		var provider func() (map[string]any, error)
		switch {
		case bare == "targets.import" && s.providers.ImportTarget != nil:
			provider = func() (map[string]any, error) { return s.providers.ImportTarget(ctx, scope, in) }
		case bare == "targets.reserve" && s.providers.ReserveTarget != nil:
			provider = func() (map[string]any, error) { return s.providers.ReserveTarget(ctx, scope, in) }
		case bare == "targets.observe" && s.providers.Observe != nil:
			provider = func() (map[string]any, error) { return s.providers.Observe(ctx, scope, in) }
		default:
			err = ErrMissingPort
			break
		}
		if err != nil {
			break
		}
		var payload map[string]any
		var providerDispatched bool
		payload, providerDispatched, err = s.providerPayload(ctx, scope, action, idem, digest, claim, provider, func(payload map[string]any) error {
			if err := validateProviderPayload(payload); err != nil {
				return err
			}
			id := stringParam(payload, "target_id")
			if id == "" && bare == "targets.observe" {
				id = stringParam(in, "target_id")
			}
			if _, idErr := idParam(map[string]any{"target_id": id}, "target_id"); idErr != nil {
				return fmt.Errorf("%w: provider target_id is invalid", ErrUnsafeOutput)
			}
			return nil
		})
		dispatched = dispatched || providerDispatched
		if err == nil {
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
				if existing, readErr := s.store.Read(ctx, scope, "target", id, 0); readErr == nil {
					if err = s.emit(ctx, existing, "target_observed", payload); err != nil {
						break
					}
				} else if !errors.Is(readErr, ErrNotFound) {
					err = readErr
					break
				}
				result = map[string]any{"observation": ownedPayload(scope, payload)}
				break
			}
			id := stringParam(payload, "target_id")
			if id == "" {
				if bare == "targets.import" || bare == "targets.reserve" {
					err = fmt.Errorf("%w: provider target_id is required", ErrUnsafeOutput)
					break
				}
				id = deterministicID(scope, action, idem)
			}
			record, e := s.putNew(ctx, scope, "target", id, "active", payload)
			err = e
			if err == nil {
				if err = s.emit(ctx, record, "target_changed", payload); err != nil {
					break
				}
				result = map[string]any{"target": publicRecord(record)}
				if bare == "targets.observe" {
					result = map[string]any{"observation": publicRecord(record)}
				}
				if bare == "targets.import" {
					if observationID := stringParam(payload, "observation_id"); observationID != "" {
						result["observation_id"] = observationID
						if observation, ok := payload["observation"].(map[string]any); ok {
							result["observation"] = ownedPayload(scope, observation)
						}
					}
				}
			}
		}
	case "plans.create":
		id := deterministicID(scope, action, idem)
		compiled, compileErr := compiledPlanPayload(in)
		if compileErr != nil {
			err = compileErr
			break
		}
		payload := map[string]any{"project_id": stringParam(in, "project_id"), "analysis_id": stringParam(in, "analysis_id"), "target_id": stringParam(in, "target_id"), "target_revision": uintParam(in, "target_revision"), "intent": stringParam(in, "intent"), "recipe_id": stringParam(in, "recipe_id"), "purpose": stringParam(in, "purpose"), "status": "ready", "schema_version": SchemaVersion}
		for key, value := range compiled {
			payload[key] = value
		}
		record, e := s.putNew(ctx, scope, "plan", id, "ready", payload)
		err = e
		if err == nil {
			if err = s.emit(ctx, record, "plan_created", payload); err != nil {
				break
			}
			result = map[string]any{"plan": publicRecord(record)}
		}
	case "plans.revise":
		id, _ := idParam(in, "plan_id")
		existing, e := s.mutationBase(ctx, scope, "plan", id, uintParam(in, "expected_revision"))
		if e != nil {
			err = e
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
				if err = s.emit(ctx, updated, "plan_revised", payload); err != nil {
					break
				}
				result = map[string]any{"plan": publicRecord(updated)}
			}
		}
	case "runs.create":
		planID, _ := idParam(in, "plan_id")
		plan, planErr := s.store.Read(ctx, scope, "plan", planID, uintParam(in, "plan_revision"))
		if planErr != nil {
			err = planErr
		} else {
			id := deterministicID(scope, action, idem)
			operation := stringParam(in, "operation")
			stageID := stageIDForRun(scope, id, planID, operation)
			taskID := taskIDForStage(scope, stageID)
			confirmationID := uuid.NewSHA1(uuid.NameSpaceOID, []byte(id+"\x00confirmation")).String()
			// putNew verifies the complete replay identity and payload if a crash
			// left the deterministic run behind before the replay receipt.
			payload := map[string]any{"plan_id": planID, "plan_revision": plan.Revision, "operation": operation, "trigger_kind": stringParam(in, "trigger_kind"), "status": "waiting_user", "revision": uint64(1), "requires_confirmation": true, "confirmation_id": confirmationID, "stage_id": stageID, "task_id": taskID, "dispatch_mode": "public_reconcile"}
			record, createErr := s.putNew(ctx, scope, "run", id, "waiting_user", payload)
			if createErr != nil {
				err = createErr
				break
			}
			stage, stageErr := s.putNew(ctx, scope, "stage", stageID, "waiting_user", stageRecordPayload(scope, id, planID, operation, taskID, confirmationID, plan.Revision))
			if stageErr != nil {
				err = stageErr
				break
			}
			confirmationPayload := map[string]any{"run_id": id, "stage_id": stageID, "state": "pending", "binding": map[string]any{"plan_id": planID, "plan_revision": plan.Revision, "operation": operation, "stage_id": stageID, "stage_revision": stage.Revision, "task_id": taskID}, "preview": map[string]any{"operation": operation, "stage_id": stageID, "task_id": taskID}}
			confirmation, confirmationErr := s.putNew(ctx, scope, "confirmation", confirmationID, "pending", confirmationPayload)
			if confirmationErr == nil {
				confirmationErr = s.emit(ctx, confirmation, "confirmation_created", confirmationPayload)
			}
			if confirmationErr != nil {
				err = confirmationErr
				break
			}
			if err = s.emit(ctx, record, "run_created", record.Payload); err != nil {
				break
			}
			result = map[string]any{"run": publicRecord(record), "stages": []any{stageView(stage)}}
		}
	case "runs.cancel", "runs.reconcile":
		id, _ := idParam(in, "run_id")
		existing, e := s.mutationBase(ctx, scope, "run", id, uintParam(in, "expected_revision"))
		if e != nil {
			err = e
		} else {
			stage, stageErr := stageForRun(ctx, s.store, scope, existing)
			if stageErr != nil {
				err = stageErr
				break
			}
			if bare == "runs.reconcile" {
				if stringParam(in, "stage_id") != stage.ID {
					err = ErrConflict
					break
				}
				if stageTerminal(stage.Status) {
					if existing.Status != stage.Status {
						recoveredPayload := cloneMap(existing.Payload)
						for key, value := range stage.Payload {
							if key == "status" || key == "reason" || key == "target_id" || key == "plan_id" || key == "observation" || key == "provisioning" || key == "materialized_target" || key == "provisioning_started" || key == "provisioning_destroy_started" {
								recoveredPayload[key] = value
							}
						}
						if recovered, recoverErr := s.update(ctx, existing, stage.Status, recoveredPayload); recoverErr == nil {
							existing = recovered
						}
					}
					result = map[string]any{"run": publicRecord(existing), "stages": []any{stageView(stage)}}
					break
				}
				if stage.Status == "waiting_user" {
					err = fmt.Errorf("%w: confirmation is required before reconcile", ErrConflict)
					break
				}
				// A reconcile is authorized only by the confirmation bound to
				// this exact run/stage.  The stage status is a durable projection,
				// not an authority by itself: a partial write or manual mutation
				// must never let the provider run without a confirmed operation.
				confirmationID := stringParam(stage.Payload, "confirmation_id")
				if confirmationID == "" {
					err = fmt.Errorf("%w: stage confirmation binding is missing", ErrConflict)
					break
				}
				confirmation, confirmationErr := s.store.Read(ctx, scope, "confirmation", confirmationID, 0)
				if confirmationErr != nil {
					err = confirmationErr
					break
				}
				if stringParam(confirmation.Payload, "run_id") != existing.ID || stringParam(confirmation.Payload, "stage_id") != stage.ID || stringParam(confirmation.Payload, "state") != "confirmed" || confirmation.Status != "confirmed" {
					err = fmt.Errorf("%w: confirmation is not bound and confirmed", ErrConflict)
					break
				}
			}
			status := "canceled"
			eventType := "run_canceled"
			payload := cloneMap(existing.Payload)
			if bare == "runs.reconcile" {
				if s.providers.Reconcile == nil {
					err = ErrMissingPort
					break
				}
				providerPayload, providerDispatched, pe := s.providerPayload(ctx, scope, action, idem, digest, claim, func() (map[string]any, error) {
					return s.providers.Reconcile(ctx, scope, in)
				}, func(providerPayload map[string]any) error {
					if err := validateSafeInput(providerPayload); err != nil {
						return err
					}
					for key, expected := range map[string]string{"run_id": existing.ID, "stage_id": stage.ID, "confirmation_id": stringParam(stage.Payload, "confirmation_id"), "task_id": stringParam(stage.Payload, "task_id")} {
						if actual := stringParam(providerPayload, key); actual != "" && actual != expected {
							return fmt.Errorf("%w: provider %s binding mismatch", ErrConflict, key)
						}
					}
					status := stringParam(providerPayload, "status")
					if status == "" {
						status = "succeeded"
					}
					switch status {
					case "succeeded", "failed", "canceled", "uncertain", "running", "queued":
						return nil
					default:
						return ErrUnsafeOutput
					}
				})
				dispatched = dispatched || providerDispatched
				if pe != nil {
					err = pe
					break
				}
				for key, value := range providerPayload {
					payload[key] = value
				}
				status = stringParam(providerPayload, "status")
				if status == "" {
					status = "succeeded"
				}
				eventType = "run_reconciled"
			}
			if err != nil {
				break
			}
			updated, e := s.update(ctx, existing, status, payload)
			err = e
			if err == nil {
				if err = s.emit(ctx, updated, eventType, payload); err != nil {
					break
				}
				stagePayload := cloneMap(stage.Payload)
				stagePayload["status"] = status
				stagePayload["run_revision"] = updated.Revision
				for key, value := range payload {
					if key == "status" || key == "reason" || key == "target_id" || key == "plan_id" || key == "observation" || key == "provisioning" || key == "materialized_target" || key == "provisioning_started" || key == "provisioning_destroy_started" {
						stagePayload[key] = value
					}
				}
				updatedStage, stageUpdateErr := s.ensureUpdate(ctx, stage, status, stagePayload)
				if stageUpdateErr != nil {
					err = stageUpdateErr
					break
				}
				stage = updatedStage
				result = map[string]any{"run": publicRecord(updated), "stages": []any{stageView(stage)}}
			}
		}
	case "runs.retry":
		id, _ := idParam(in, "run_id")
		existing, e := s.store.Read(ctx, scope, "run", id, 0)
		if e != nil {
			err = e
		} else if existing.Revision != uintParam(in, "expected_revision") {
			err = ErrConflict
		} else {
			newID := deterministicID(scope, action, idem)
			payload := cloneMap(existing.Payload)
			payload["retry_of_run_id"] = existing.ID
			payload["status"] = "waiting_user"
			planID := stringParam(payload, "plan_id")
			operation := stringParam(payload, "operation")
			stageID := stageIDForRun(scope, newID, planID, operation)
			taskID := taskIDForStage(scope, stageID)
			confirmationID := uuid.NewSHA1(uuid.NameSpaceOID, []byte(newID+"\x00confirmation")).String()
			payload["stage_id"] = stageID
			payload["task_id"] = taskID
			payload["confirmation_id"] = confirmationID
			payload["confirmation_state"] = "pending"
			payload["requires_confirmation"] = true
			delete(payload, "provisioning_started")
			delete(payload, "provision_intent_id")
			record, e := s.putNew(ctx, scope, "run", newID, "waiting_user", payload)
			err = e
			if err == nil {
				stagePayload := stageRecordPayload(scope, newID, planID, operation, taskID, confirmationID, uintParam(payload, "plan_revision"))
				stage, stageErr := s.putNew(ctx, scope, "stage", stageID, "waiting_user", stagePayload)
				if stageErr != nil {
					err = stageErr
					break
				}
				confirmationPayload := map[string]any{"run_id": newID, "stage_id": stageID, "state": "pending", "binding": map[string]any{"plan_id": planID, "plan_revision": uintParam(payload, "plan_revision"), "operation": operation, "stage_id": stageID, "stage_revision": stage.Revision, "task_id": taskID}, "preview": map[string]any{"operation": operation, "stage_id": stageID, "task_id": taskID}}
				confirmation, confirmationErr := s.putNew(ctx, scope, "confirmation", confirmationID, "pending", confirmationPayload)
				if confirmationErr != nil {
					err = confirmationErr
					break
				}
				if err = s.emit(ctx, record, "run_retried", payload); err != nil {
					break
				}
				if err = s.emit(ctx, confirmation, "confirmation_created", confirmationPayload); err != nil {
					break
				}
				result = map[string]any{"run": publicRecord(record), "stages": []any{stageView(stage)}}
			}
		}
	case "confirmations.confirm", "confirmations.reject":
		id, _ := idParam(in, "confirmation_id")
		existing, e := s.mutationBase(ctx, scope, "confirmation", id, uintParam(in, "expected_revision"))
		if e != nil {
			err = e
		} else {
			status := "confirmed"
			if bare == "confirmations.reject" {
				status = "rejected"
			}
			payload := cloneMap(existing.Payload)
			payload["state"] = status
			updated, e := s.update(ctx, existing, status, payload)
			err = e
			if err == nil {
				if err = s.emit(ctx, updated, "confirmation_"+status, payload); err != nil {
					break
				}
				if runID := stringParam(payload, "run_id"); runID != "" {
					run, runErr := s.store.Read(ctx, scope, "run", runID, 0)
					if runErr != nil {
						err = runErr
						break
					}
					if run.Revision > 0 {
						nextStatus := "queued"
						if status == "rejected" {
							nextStatus = "rejected"
						}
						nextPayload := cloneMap(run.Payload)
						nextPayload["confirmation_state"] = status
						next, updateErr := s.ensureUpdate(ctx, run, nextStatus, nextPayload)
						if updateErr != nil {
							err = updateErr
							break
						}
						if err = s.emit(ctx, next, "run_"+nextStatus, nextPayload); err != nil {
							break
						}
						stage, stageErr := stageForRun(ctx, s.store, scope, run)
						if stageErr != nil {
							err = stageErr
							break
						}
						if stage.Status == "waiting_user" {
							stagePayload := cloneMap(stage.Payload)
							stagePayload["status"] = nextStatus
							stagePayload["confirmation_state"] = status
							if _, updateErr = s.ensureUpdate(ctx, stage, nextStatus, stagePayload); updateErr != nil {
								err = updateErr
								break
							}
						}
					}
				}
				if err != nil {
					break
				}
				result = map[string]any{"confirmation": publicRecord(updated)}
			}
		}
	case "service_bindings.invoke":
		if s.providers.Invoke == nil {
			err = ErrMissingPort
		} else {
			payload, providerDispatched, providerErr := s.providerPayload(ctx, scope, action, idem, digest, claim, func() (map[string]any, error) {
				return s.providers.Invoke(ctx, scope, in)
			}, func(payload map[string]any) error { return validateSafeInput(payload) })
			dispatched = dispatched || providerDispatched
			err = providerErr
			if err == nil {
				result = map[string]any{"result": payload}
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
	if err := s.completeReplay(ctx, scope, action, idem, digest, claim.Token, result); err != nil {
		return nil, err
	}
	completed = true
	return result, nil
}

func (s *Service) handleSecret(ctx context.Context, scope coretask.OwnerScope, action string, in map[string]any) (map[string]any, error) {
	if action == "agent.execution.v2.secrets.get" || action == "agent.execution.v2.secrets.list" {
		if action == "agent.execution.v2.secrets.get" {
			ref, _ := idParam(in, "secret_ref")
			secret, err := s.store.ReadSecret(ctx, scope, ref, uintParam(in, "revision"))
			if err != nil {
				return nil, err
			}
			return map[string]any{"secret": publicSecret(secret)}, nil
		}
		items, next, err := s.store.ListSecrets(ctx, scope, stringParam(in, "page_token"), intParam(in, "page_size", 100))
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
	replay, ok, claim, err := s.beginReplay(ctx, scope, action, idem, digest)
	if err != nil || ok {
		return replay, err
	}
	ctx = context.WithValue(ctx, replayIdentityContextKey{}, replayIdentity{action: action, key: idem, digest: append([]byte(nil), digest...)})
	completed := false
	defer func() {
		if !completed {
			_ = s.store.AbortReplay(context.WithoutCancel(ctx), scope, action, idem, digest, claim.Token)
		}
	}()
	switch action {
	case "agent.execution.v2.secrets.create":
		value := stringParam(in, "value")
		sum := sha256.Sum256([]byte(value))
		ref := deterministicID(scope, action, idem)
		now := s.now().UTC()
		desired := Secret{OwnerID: scope.OwnerID, AccountGeneration: scope.AccountGeneration, Ref: ref, Revision: 1, Provider: stringParam(in, "provider"), Purpose: stringParam(in, "purpose"), Value: value, BindingDigest: hex.EncodeToString(sum[:]), Status: "active", CreatedAt: now, UpdatedAt: now}
		bindSecretReplayMutation(ctx, &desired)
		secret, e := s.store.SaveSecret(ctx, desired)
		if errors.Is(e, ErrConflict) {
			existing, readErr := s.store.ReadSecret(ctx, scope, ref, 0)
			if readErr == nil && existing.Revision == desired.Revision && existing.Provider == desired.Provider && existing.Purpose == desired.Purpose && existing.BindingDigest == desired.BindingDigest && existing.Status == desired.Status && existing.Value == desired.Value && sameSecretReplayMutation(ctx, existing) {
				secret, e = existing, nil
			}
		}
		if e != nil {
			return nil, e
		}
		result := map[string]any{"secret": publicSecret(secret)}
		if e = s.completeReplay(ctx, scope, action, idem, digest, claim.Token, result); e != nil {
			return nil, e
		}
		completed = true
		return result, nil
	case "agent.execution.v2.secrets.revoke":
		ref, _ := idParam(in, "secret_ref")
		secret, e := s.store.ReadSecret(ctx, scope, ref, 0)
		if e != nil {
			return nil, e
		}
		expected := uintParam(in, "expected_revision")
		if secret.Revision == expected+1 && secret.Status == "revoked" && sameSecretReplayMutation(ctx, secret) {
			result := map[string]any{"secret": publicSecret(secret)}
			if e = s.completeReplay(ctx, scope, action, idem, digest, claim.Token, result); e != nil {
				return nil, e
			}
			completed = true
			return result, nil
		}
		if secret.Revision != expected {
			return nil, ErrConflict
		}
		secret.Status = "revoked"
		secret.UpdatedAt = s.now().UTC()
		bindSecretReplayMutation(ctx, &secret)
		updated, e := s.store.RevokeSecret(ctx, secret, secret.Revision)
		if e != nil {
			return nil, e
		}
		result := map[string]any{"secret": publicSecret(updated)}
		if e = s.completeReplay(ctx, scope, action, idem, digest, claim.Token, result); e != nil {
			return nil, e
		}
		completed = true
		return result, nil
	default:
		return nil, ErrUnsupported
	}
}

func publicSecret(secret Secret) map[string]any {
	return map[string]any{"owner_id": secret.OwnerID, "account_generation": secret.AccountGeneration, "secret_ref": secret.Ref, "revision": secret.Revision, "provider": secret.Provider, "purpose": secret.Purpose, "binding_digest": secret.BindingDigest, "status": secret.Status, "created_at": secret.CreatedAt.UTC().Format(time.RFC3339Nano), "updated_at": secret.UpdatedAt.UTC().Format(time.RFC3339Nano)}
}
