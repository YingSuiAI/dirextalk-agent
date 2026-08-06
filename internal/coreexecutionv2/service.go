package coreexecutionv2

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/coretask"
	"github.com/google/uuid"
)

var actionNames = []string{
	"agent.execution.v2.projects.analyze", "agent.execution.v2.analyses.get",
	"agent.execution.v2.targets.list", "agent.execution.v2.targets.get", "agent.execution.v2.targets.import", "agent.execution.v2.targets.reserve", "agent.execution.v2.targets.observe",
	"agent.execution.v2.plans.create", "agent.execution.v2.plans.revise", "agent.execution.v2.plans.get", "agent.execution.v2.plans.list",
	"agent.execution.v2.deployments.list", "agent.execution.v2.deployments.get", "agent.execution.v2.deployments.events",
	"agent.execution.v2.runs.create", "agent.execution.v2.runs.get", "agent.execution.v2.runs.list", "agent.execution.v2.runs.cancel", "agent.execution.v2.runs.retry", "agent.execution.v2.runs.reconcile", "agent.execution.v2.runs.events",
	"agent.execution.v2.confirmations.get", "agent.execution.v2.confirmations.list", "agent.execution.v2.confirmations.confirm", "agent.execution.v2.confirmations.reject",
	"agent.execution.v2.artifacts.get", "agent.execution.v2.service_bindings.list", "agent.execution.v2.service_bindings.get", "agent.execution.v2.service_bindings.invoke",
	"agent.execution.v2.secrets.create", "agent.execution.v2.secrets.get", "agent.execution.v2.secrets.list", "agent.execution.v2.secrets.revoke",
}

var actionSet = func() map[string]struct{} {
	m := make(map[string]struct{}, len(actionNames))
	for _, action := range actionNames {
		m[action] = struct{}{}
	}
	return m
}()

// Actions returns a defensive copy of the public action tokens.  The order is
// frozen because it is included in capability catalog acceptance tests.
func Actions() []string { return append([]string(nil), actionNames...) }

type Service struct {
	store     Store
	providers Providers
	ready     func() bool
	now       func() time.Time
}

type replayIdentity struct {
	action string
	key    string
	digest []byte
}

type replayIdentityContextKey struct{}

func NewService(cfg Config) (*Service, error) {
	if cfg.Store == nil {
		return nil, ErrInvalid
	}
	if typed := AdaptTypedPorts(cfg.Typed); typed.Analyze != nil || typed.ImportTarget != nil || typed.ReserveTarget != nil || typed.Observe != nil || typed.Invoke != nil || typed.Reconcile != nil {
		// Typed ports are the production boundary. Keep explicitly supplied
		// callbacks available for narrow tests/embeddings, but never let a
		// partially populated callback set shadow a typed route.
		if cfg.Providers.Analyze == nil {
			cfg.Providers.Analyze = typed.Analyze
		}
		if cfg.Providers.ImportTarget == nil {
			cfg.Providers.ImportTarget = typed.ImportTarget
		}
		if cfg.Providers.ReserveTarget == nil {
			cfg.Providers.ReserveTarget = typed.ReserveTarget
		}
		if cfg.Providers.Observe == nil {
			cfg.Providers.Observe = typed.Observe
		}
		if cfg.Providers.Invoke == nil {
			cfg.Providers.Invoke = typed.Invoke
		}
		if cfg.Providers.Reconcile == nil {
			cfg.Providers.Reconcile = typed.Reconcile
		}
		if cfg.Ready == nil {
			cfg.Ready = cfg.Typed.Ready
			if cfg.Ready == nil {
				cfg.Ready = func() bool { return false }
			}
		}
	}
	if cfg.Now == nil {
		cfg.Now = func() time.Time { return time.Now().UTC() }
	}
	if cfg.Ready == nil {
		cfg.Ready = func() bool { return true }
	}
	return &Service{store: cfg.Store, providers: cfg.Providers, ready: cfg.Ready, now: cfg.Now}, nil
}

func (s *Service) Ready() bool { return s != nil && s.ready != nil && s.ready() }

// ActionReady reports whether the exact provider dependency for an action is
// present. It is used by composition/readiness tests; Handle still returns a
// precise ErrMissingPort when a caller reaches an unavailable mutation.
func (s *Service) ActionReady(action string) bool {
	if s == nil || !s.Ready() || !validAction(action) {
		return false
	}
	switch action {
	case "agent.execution.v2.projects.analyze":
		return s.providers.Analyze != nil
	case "agent.execution.v2.targets.import":
		return s.providers.ImportTarget != nil
	case "agent.execution.v2.targets.reserve":
		return s.providers.ReserveTarget != nil
	case "agent.execution.v2.targets.observe":
		return s.providers.Observe != nil
	case "agent.execution.v2.service_bindings.invoke":
		return s.providers.Invoke != nil
	case "agent.execution.v2.runs.reconcile":
		return s.providers.Reconcile != nil
	default:
		return true
	}
}

// ReadyForPublication is deliberately stricter than Ready. The neutral
// catalog cannot express readiness per operation, so a process must prove all
// provider-backed routes before publishing a misleading 33-operation
// capability. Individual direct calls still get a precise ErrMissingPort.
func (s *Service) ReadyForPublication() bool {
	if s == nil || !s.Ready() {
		return false
	}
	return s.providers.Analyze != nil && s.providers.ImportTarget != nil && s.providers.ReserveTarget != nil && s.providers.Observe != nil && s.providers.Invoke != nil && s.providers.Reconcile != nil
}

func (s *Service) ReadinessReason() string {
	if s == nil || !s.Ready() {
		return "execution.v2 provider composition is not ready"
	}
	if s.providers.Analyze == nil {
		return "execution.v2 analyze provider is unavailable"
	}
	if s.providers.ImportTarget == nil {
		return "execution.v2 target import provider is unavailable"
	}
	if s.providers.ReserveTarget == nil {
		return "execution.v2 target reservation provider is unavailable"
	}
	if s.providers.Observe == nil {
		return "execution.v2 target observation provider is unavailable"
	}
	if s.providers.Invoke == nil {
		return "execution.v2 binding invocation provider is unavailable"
	}
	if s.providers.Reconcile == nil {
		return "execution.v2 run reconciliation provider is unavailable"
	}
	return ""
}

func (s *Service) Get(ctx context.Context, scope coretask.OwnerScope, kind, id string, revision uint64) (Record, error) {
	if s == nil || s.store == nil || scope.Validate() != nil {
		return Record{}, ErrInvalid
	}
	scope.OwnerID = strings.TrimSpace(scope.OwnerID)
	return s.store.Read(ctx, scope, strings.TrimSpace(kind), strings.TrimSpace(id), revision)
}

func (s *Service) Events(ctx context.Context, scope coretask.OwnerScope, kind, id string, after uint64, limit int) ([]Event, uint64, error) {
	if s == nil || s.store == nil || scope.Validate() != nil {
		return nil, 0, ErrInvalid
	}
	if limit < 1 || limit > 200 {
		return nil, 0, ErrInvalid
	}
	scope.OwnerID = strings.TrimSpace(scope.OwnerID)
	return s.store.Events(ctx, scope, strings.TrimSpace(kind), strings.TrimSpace(id), after, limit)
}

func validAction(action string) bool {
	_, ok := actionSet[action]
	return ok
}

func (s *Service) Handle(ctx context.Context, scope coretask.OwnerScope, action string, params map[string]any) (map[string]any, error) {
	if s == nil || !s.Ready() {
		return nil, ErrNotReady
	}
	if scope.Validate() != nil || !validAction(action) {
		return nil, ErrInvalid
	}
	scope.OwnerID = strings.TrimSpace(scope.OwnerID)
	params = cloneMap(params)
	if err := validateAction(action, params); err != nil {
		return nil, err
	}
	if strings.HasPrefix(action, "agent.execution.v2.secrets.") {
		return s.handleSecret(ctx, scope, action, params)
	}
	if isReadAction(action) {
		return s.handleRead(ctx, scope, action, params)
	}
	return s.handleMutation(ctx, scope, action, params)
}

func isReadAction(action string) bool {
	switch action {
	case "agent.execution.v2.analyses.get", "agent.execution.v2.targets.list", "agent.execution.v2.targets.get", "agent.execution.v2.plans.get", "agent.execution.v2.plans.list", "agent.execution.v2.deployments.list", "agent.execution.v2.deployments.get", "agent.execution.v2.deployments.events", "agent.execution.v2.runs.get", "agent.execution.v2.runs.list", "agent.execution.v2.runs.events", "agent.execution.v2.confirmations.get", "agent.execution.v2.confirmations.list", "agent.execution.v2.artifacts.get", "agent.execution.v2.service_bindings.list", "agent.execution.v2.service_bindings.get", "agent.execution.v2.secrets.get", "agent.execution.v2.secrets.list":
		return true
	default:
		return false
	}
}

func kindForAction(action string) string {
	bare := strings.TrimPrefix(action, "agent.execution.v2.")
	part := strings.SplitN(bare, ".", 2)[0]
	switch part {
	case "projects":
		return "analysis"
	case "analyses":
		return "analysis"
	case "targets":
		return "target"
	case "plans":
		return "plan"
	case "deployments":
		return "deployment"
	case "runs":
		return "run"
	case "confirmations":
		return "confirmation"
	case "artifacts":
		return "artifact"
	case "service_bindings":
		return "binding"
	default:
		return ""
	}
}

func idField(action string) string {
	switch action {
	case "agent.execution.v2.analyses.get":
		return "analysis_id"
	case "agent.execution.v2.targets.get", "agent.execution.v2.targets.observe":
		return "target_id"
	case "agent.execution.v2.plans.get", "agent.execution.v2.plans.revise":
		return "plan_id"
	case "agent.execution.v2.deployments.get", "agent.execution.v2.deployments.events":
		return "deployment_id"
	case "agent.execution.v2.runs.get", "agent.execution.v2.runs.cancel", "agent.execution.v2.runs.retry", "agent.execution.v2.runs.reconcile", "agent.execution.v2.runs.events":
		return "run_id"
	case "agent.execution.v2.confirmations.get", "agent.execution.v2.confirmations.confirm", "agent.execution.v2.confirmations.reject":
		return "confirmation_id"
	case "agent.execution.v2.artifacts.get":
		return "artifact_id"
	case "agent.execution.v2.service_bindings.get", "agent.execution.v2.service_bindings.invoke":
		return "binding_id"
	default:
		return ""
	}
}

func stringParam(params map[string]any, key string) string {
	value, _ := params[key].(string)
	return strings.TrimSpace(value)
}

func idParam(params map[string]any, key string) (string, error) {
	value := stringParam(params, key)
	if value == "" {
		return "", fmt.Errorf("%w: %s is required", ErrInvalid, key)
	}
	parsed, err := uuid.Parse(value)
	if err != nil || parsed.String() != value {
		return "", fmt.Errorf("%w: %s must be a UUID", ErrInvalid, key)
	}
	return value, nil
}

func idempotency(params map[string]any) (string, error) {
	value, err := idParam(params, "idempotency_key")
	if err != nil {
		return "", err
	}
	return value, nil
}

func requestDigest(action string, params map[string]any) ([]byte, string, error) {
	// Idempotency keys identify the replay slot and deterministic resource ID;
	// they are not business input. Excluding the key lets a retry with the same
	// operation identity compare only canonical business fields, and prevents
	// transient request IDs from changing the digest.
	canonical := cloneMap(params)
	delete(canonical, "idempotency_key")
	raw, err := json.Marshal(struct {
		Action string         `json:"action"`
		Input  map[string]any `json:"input"`
	}{Action: action, Input: canonical})
	if err != nil {
		return nil, "", err
	}
	digest := sha256.Sum256(raw)
	return digest[:], hex.EncodeToString(digest[:]), nil
}

func deterministicID(scope coretask.OwnerScope, action, idempotencyKey string) string {
	return uuid.NewSHA1(uuid.NameSpaceOID, []byte(fmt.Sprintf("%s\x00%d\x00%s\x00%s", scope.OwnerID, scope.AccountGeneration, action, idempotencyKey))).String()
}

func (s *Service) beginReplay(ctx context.Context, scope coretask.OwnerScope, action, idem string, digest []byte) (map[string]any, bool, ReplayClaim, error) {
	const replayLease = 5 * time.Minute
	for {
		claim, err := s.store.BeginReplay(ctx, scope, action, idem, digest, s.now().UTC(), replayLease)
		if errors.Is(err, ErrReplayInProgress) {
			timer := time.NewTimer(10 * time.Millisecond)
			select {
			case <-ctx.Done():
				timer.Stop()
				return nil, false, ReplayClaim{}, ctx.Err()
			case <-timer.C:
				continue
			}
		}
		if err != nil {
			return nil, false, ReplayClaim{}, err
		}
		if !claim.Completed {
			if claim.Dispatched && len(claim.ProviderResponse) == 0 {
				return nil, false, claim, ErrReplayInProgress
			}
			return nil, false, claim, nil
		}
		var result map[string]any
		if err := json.Unmarshal(claim.Response, &result); err != nil {
			return nil, true, ReplayClaim{}, ErrConflict
		}
		return result, true, ReplayClaim{}, nil
	}
}

func (s *Service) providerPayload(ctx context.Context, scope coretask.OwnerScope, action, idem string, digest []byte, claim ReplayClaim, call func() (map[string]any, error), validate func(map[string]any) error) (map[string]any, bool, error) {
	if claim.Dispatched {
		var payload map[string]any
		if err := json.Unmarshal(claim.ProviderResponse, &payload); err != nil || payload == nil {
			return nil, true, ErrConflict
		}
		if err := validate(payload); err != nil {
			return nil, true, err
		}
		return payload, true, nil
	}
	if err := s.store.MarkReplayDispatched(ctx, scope, action, idem, digest, claim.Token, s.now().UTC()); err != nil {
		return nil, false, err
	}
	payload, err := call()
	if err != nil {
		return nil, true, err
	}
	if err := validate(payload); err != nil {
		return nil, true, err
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		return nil, true, err
	}
	if err := s.store.StoreReplayProviderResponse(ctx, scope, action, idem, digest, claim.Token, raw, s.now().UTC()); err != nil {
		return nil, true, err
	}
	return payload, true, nil
}

func (s *Service) completeReplay(ctx context.Context, scope coretask.OwnerScope, action, idem string, digest []byte, token string, result map[string]any) error {
	raw, err := json.Marshal(result)
	if err != nil {
		return err
	}
	return s.store.CompleteReplay(ctx, scope, action, idem, digest, token, raw, s.now().UTC())
}

func equalBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func ownedPayload(scope coretask.OwnerScope, payload map[string]any) map[string]any {
	out := cloneMap(payload)
	out["owner_id"] = scope.OwnerID
	out["account_generation"] = scope.AccountGeneration
	return out
}

func digestPayload(payload map[string]any) string {
	raw, _ := json.Marshal(payload)
	digest := sha256.Sum256(raw)
	return hex.EncodeToString(digest[:])
}

func (s *Service) putNew(ctx context.Context, scope coretask.OwnerScope, kind, id, status string, payload map[string]any) (Record, error) {
	now := s.now().UTC()
	payload = ownedPayload(scope, payload)
	record := Record{OwnerID: scope.OwnerID, AccountGeneration: scope.AccountGeneration, Kind: kind, ID: id, Revision: 1, Status: status, Digest: digestPayload(payload), Payload: payload, CreatedAt: now, UpdatedAt: now}
	bindReplayMutation(ctx, &record)
	created, err := s.store.Create(ctx, record)
	if !errors.Is(err, ErrConflict) {
		return created, err
	}
	existing, readErr := s.store.Read(ctx, scope, kind, id, 0)
	if readErr == nil && existing.Revision == 1 && existing.Status == record.Status && existing.Digest == record.Digest && sameReplayMutation(ctx, existing) {
		return existing, nil
	}
	return Record{}, err
}

func (s *Service) update(ctx context.Context, record Record, status string, payload map[string]any) (Record, error) {
	payload = ownedPayload(canonicalScope(record), payload)
	record.Status = status
	record.Digest = digestPayload(payload)
	record.Payload = payload
	record.UpdatedAt = s.now().UTC()
	bindReplayMutation(ctx, &record)
	updated, err := s.store.Update(ctx, record, record.Revision)
	if !errors.Is(err, ErrConflict) {
		return updated, err
	}
	current, readErr := s.store.Read(ctx, canonicalScope(record), record.Kind, record.ID, 0)
	if readErr == nil && current.Revision == record.Revision+1 && current.Status == record.Status && current.Digest == record.Digest && sameReplayMutation(ctx, current) {
		return current, nil
	}
	return Record{}, err
}

func (s *Service) ensureUpdate(ctx context.Context, record Record, status string, payload map[string]any) (Record, error) {
	desired := ownedPayload(canonicalScope(record), payload)
	if record.Status == status && record.Digest == digestPayload(desired) && sameReplayMutation(ctx, record) {
		return record, nil
	}
	return s.update(ctx, record, status, payload)
}

func (s *Service) mutationBase(ctx context.Context, scope coretask.OwnerScope, kind, id string, expected uint64) (Record, error) {
	current, err := s.store.Read(ctx, scope, kind, id, 0)
	if err != nil {
		return Record{}, err
	}
	if current.Revision == expected {
		return current, nil
	}
	if current.Revision != expected+1 {
		return Record{}, ErrConflict
	}
	if !sameReplayMutation(ctx, current) {
		return Record{}, ErrConflict
	}
	base, err := s.store.Read(ctx, scope, kind, id, expected)
	if err != nil {
		return Record{}, ErrConflict
	}
	return base, nil
}

func bindReplayMutation(ctx context.Context, record *Record) {
	replay, ok := ctx.Value(replayIdentityContextKey{}).(replayIdentity)
	if !ok || record == nil {
		return
	}
	record.MutationAction = replay.action
	record.MutationKey = replay.key
	record.MutationDigest = append([]byte(nil), replay.digest...)
}

func sameReplayMutation(ctx context.Context, record Record) bool {
	replay, ok := ctx.Value(replayIdentityContextKey{}).(replayIdentity)
	return ok && record.MutationAction == replay.action && record.MutationKey == replay.key && equalBytes(record.MutationDigest, replay.digest)
}

func bindSecretReplayMutation(ctx context.Context, secret *Secret) {
	replay, ok := ctx.Value(replayIdentityContextKey{}).(replayIdentity)
	if !ok || secret == nil {
		return
	}
	secret.MutationAction = replay.action
	secret.MutationKey = replay.key
	secret.MutationDigest = append([]byte(nil), replay.digest...)
}

func sameSecretReplayMutation(ctx context.Context, secret Secret) bool {
	replay, ok := ctx.Value(replayIdentityContextKey{}).(replayIdentity)
	return ok && secret.MutationAction == replay.action && secret.MutationKey == replay.key && equalBytes(secret.MutationDigest, replay.digest)
}

func (s *Service) emit(ctx context.Context, record Record, eventType string, payload map[string]any) error {
	eventID := uuid.NewString()
	if replay, ok := ctx.Value(replayIdentityContextKey{}).(replayIdentity); ok {
		eventID = uuid.NewSHA1(uuid.NameSpaceOID, []byte(fmt.Sprintf("%s\x00%d\x00%s\x00%s\x00%d\x00%s\x00%s\x00%s", record.OwnerID, record.AccountGeneration, record.Kind, record.ID, record.Revision, eventType, replay.action, replay.key))).String()
	}
	_, err := s.store.AppendEvent(ctx, Event{OwnerID: record.OwnerID, AccountGeneration: record.AccountGeneration, Kind: record.Kind, ResourceID: record.ID, EventID: eventID, Type: eventType, Payload: ownedPayload(canonicalScope(record), payload), CreatedAt: s.now().UTC()})
	return err
}

func canonicalScope(record Record) coretask.OwnerScope {
	return coretask.OwnerScope{OwnerID: record.OwnerID, AccountGeneration: record.AccountGeneration}
}

func (s *Service) handleRead(ctx context.Context, scope coretask.OwnerScope, action string, in map[string]any) (map[string]any, error) {
	kind := kindForAction(action)
	if action == "agent.execution.v2.deployments.events" || action == "agent.execution.v2.runs.events" {
		field := idField(action)
		id, err := idParam(in, field)
		if err != nil {
			return nil, err
		}
		after := uintParam(in, "after_sequence")
		limit := intParam(in, "limit", 100)
		if limit < 1 || limit > 200 {
			return nil, ErrInvalid
		}
		events, next, err := s.store.Events(ctx, scope, kind, id, after, limit)
		if err != nil {
			return nil, err
		}
		values := make([]any, 0, len(events))
		for _, event := range events {
			item := ownedPayload(scope, event.Payload)
			item["event_id"], item["sequence"], item["type"], item["at"] = event.EventID, event.Sequence, event.Type, event.CreatedAt.UTC().Format(time.RFC3339Nano)
			if kind == "run" {
				item["run_id"] = id
			} else {
				item["deployment_id"] = id
			}
			values = append(values, item)
		}
		return map[string]any{"events": values, "next_sequence": next}, nil
	}
	if action == "agent.execution.v2.targets.list" || action == "agent.execution.v2.plans.list" || action == "agent.execution.v2.deployments.list" || action == "agent.execution.v2.runs.list" || action == "agent.execution.v2.confirmations.list" || action == "agent.execution.v2.service_bindings.list" || action == "agent.execution.v2.secrets.list" {
		limit := intParam(in, "page_size", 100)
		if limit == 0 {
			limit = intParam(in, "limit", 100)
		}
		if limit < 1 || limit > 200 {
			return nil, ErrInvalid
		}
		filter := map[string]string{}
		for _, key := range []string{"project_id", "deployment_id", "status"} {
			if value := stringParam(in, key); value != "" {
				filter[key] = value
			}
		}
		if action == "agent.execution.v2.confirmations.list" {
			if raw, ok := in["states"]; ok {
				states := stateValues(raw)
				if len(states) > 0 {
					filter["state"] = strings.Join(states, ",")
				}
			}
		}
		items, next, err := s.store.List(ctx, scope, kind, filter, stringParam(in, "page_token"), limit)
		if err != nil {
			return nil, err
		}
		values := make([]any, 0, len(items))
		for _, item := range items {
			values = append(values, publicRecord(item))
		}
		key := "targets"
		switch kind {
		case "plan":
			key = "plans"
		case "deployment":
			key = "deployments"
		case "run":
			key = "runs"
		case "confirmation":
			key = "confirmations"
		case "binding":
			key = "bindings"
		case "secret":
			key = "secrets"
		}
		return map[string]any{key: values, "next_page_token": next}, nil
	}
	field := idField(action)
	id, err := idParam(in, field)
	if err != nil {
		return nil, err
	}
	revision := uintParam(in, "revision")
	record, err := s.store.Read(ctx, scope, kind, id, revision)
	if err != nil {
		return nil, err
	}
	key := map[string]string{"analysis": "analysis", "target": "target", "plan": "plan", "deployment": "deployment", "run": "run", "confirmation": "confirmation", "artifact": "artifact", "binding": "binding"}[kind]
	result := map[string]any{key: publicRecord(record)}
	if kind == "run" {
		stages := []any{}
		if stage, stageErr := stageForRun(ctx, s.store, scope, record); stageErr == nil {
			stages = append(stages, stageView(stage))
		} else if !errors.Is(stageErr, ErrNotFound) {
			return nil, stageErr
		}
		result["stages"] = stages
	}
	return result, nil
}

func publicRecord(record Record) map[string]any {
	out := ownedPayload(canonicalScope(record), record.Payload)
	out["id"] = record.ID
	out["revision"] = record.Revision
	out["status"] = record.Status
	out["digest"] = record.Digest
	out["created_at"] = record.CreatedAt.UTC().Format(time.RFC3339Nano)
	out["updated_at"] = record.UpdatedAt.UTC().Format(time.RFC3339Nano)
	// Preserve the public names used by the ProductCore envelopes.
	if record.Kind == "analysis" {
		out["analysis_id"] = record.ID
	}
	if record.Kind == "target" {
		out["target_id"] = record.ID
	}
	if record.Kind == "plan" {
		out["plan_id"] = record.ID
	}
	if record.Kind == "deployment" {
		out["deployment_id"] = record.ID
	}
	if record.Kind == "run" {
		out["run_id"] = record.ID
	}
	if record.Kind == "confirmation" {
		out["confirmation_id"] = record.ID
	}
	if record.Kind == "artifact" {
		out["artifact_id"] = record.ID
	}
	if record.Kind == "binding" {
		out["binding_id"] = record.ID
	}
	return out
}

func intParam(in map[string]any, key string, def int) int {
	value, ok := in[key]
	if !ok {
		return def
	}
	switch n := value.(type) {
	case float64:
		if n >= 0 && n == float64(int(n)) {
			return int(n)
		}
	case int:
		return n
	case int64:
		return int(n)
	case uint64:
		return int(n)
	}
	return -1
}

func uintParam(in map[string]any, key string) uint64 {
	value, ok := in[key]
	if !ok {
		return 0
	}
	switch n := value.(type) {
	case float64:
		if n >= 0 && n == float64(uint64(n)) {
			return uint64(n)
		}
	case int:
		if n >= 0 {
			return uint64(n)
		}
	case int64:
		if n >= 0 {
			return uint64(n)
		}
	case uint64:
		return n
	}
	return 0
}

func sortedRecords(items []Record) {
	sort.Slice(items, func(i, j int) bool {
		if items[i].CreatedAt.Equal(items[j].CreatedAt) {
			return items[i].ID < items[j].ID
		}
		return items[i].CreatedAt.Before(items[j].CreatedAt)
	})
}
