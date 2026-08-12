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

	"github.com/google/uuid"
)

var actionNames = []string{
	"agent.execution.v2.projects.analyze", "agent.execution.v2.analyses.get",
	"agent.execution.v2.targets.list", "agent.execution.v2.targets.get", "agent.execution.v2.targets.import", "agent.execution.v2.targets.reserve", "agent.execution.v2.targets.observe",
	"agent.execution.v2.plans.create", "agent.execution.v2.plans.revise", "agent.execution.v2.plans.get", "agent.execution.v2.plans.list",
	"agent.execution.v2.deployments.list", "agent.execution.v2.deployments.get", "agent.execution.v2.deployments.events",
	"agent.execution.v2.runs.create", "agent.execution.v2.runs.get", "agent.execution.v2.runs.list", "agent.execution.v2.runs.cancel", "agent.execution.v2.runs.retry", "agent.execution.v2.runs.events",
	"agent.execution.v2.artifacts.get", "agent.execution.v2.artifacts.download", "agent.execution.v2.service_bindings.list", "agent.execution.v2.service_bindings.get", "agent.execution.v2.service_bindings.invoke",
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
	store         Store
	providers     Providers
	cloudWorker   CloudWorkerExecutionPort
	runLifecycle  GenericRunLifecycle
	ready         func() bool
	providerReady func() bool
	now           func() time.Time
}

func NewService(cfg Config) (*Service, error) {
	if cfg.Store == nil {
		return nil, ErrInvalid
	}
	providerReady := cfg.Typed.Ready
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
	}
	if cfg.Now == nil {
		cfg.Now = func() time.Time { return time.Now().UTC() }
	}
	if cfg.Ready == nil {
		cfg.Ready = func() bool { return true }
	}
	if providerReady == nil {
		providerReady = cfg.Ready
	}
	if cfg.RunLifecycle == nil {
		cfg.RunLifecycle, _ = cfg.Store.(GenericRunLifecycle)
	}
	return &Service{store: cfg.Store, providers: cfg.Providers, cloudWorker: cfg.CloudWorker, runLifecycle: cfg.RunLifecycle, ready: cfg.Ready, providerReady: providerReady, now: cfg.Now}, nil
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
		return s.providerReady != nil && s.providerReady() && s.providers.Analyze != nil
	case "agent.execution.v2.targets.import":
		return s.providerReady != nil && s.providerReady() && s.providers.ImportTarget != nil
	case "agent.execution.v2.targets.reserve":
		return s.providerReady != nil && s.providerReady() && s.providers.ReserveTarget != nil
	case "agent.execution.v2.targets.observe":
		return s.providerReady != nil && s.providerReady() && s.providers.Observe != nil
	case "agent.execution.v2.service_bindings.invoke":
		return s.providerReady != nil && s.providerReady() && s.providers.Invoke != nil
	case "agent.execution.v2.runs.create", "agent.execution.v2.runs.retry":
		return s.providerReady != nil && s.providerReady() && s.providers.Reconcile != nil && s.runLifecycle != nil
	case "agent.execution.v2.artifacts.download":
		return s.cloudWorker != nil
	default:
		return true
	}
}

func (s *Service) genericProviderReady() bool {
	if s == nil || s.providerReady == nil || !s.providerReady() {
		return false
	}
	return s.providers.Analyze != nil || s.providers.ImportTarget != nil ||
		s.providers.ReserveTarget != nil || s.providers.Observe != nil ||
		s.providers.Invoke != nil || (s.providers.Reconcile != nil && s.runLifecycle != nil)
}

// ReadyForPublication keeps the two Execution V2 authorities independent.
// A process may publish the shared catalog for the Cloud Worker read/cancel
// route, for at least one ready generic typed provider route, or for both.
// Missing routes remain fail-closed at their exact dispatch boundary.
func (s *Service) ReadyForPublication() bool {
	if s == nil || !s.Ready() {
		return false
	}
	return s.cloudWorker != nil || s.genericProviderReady()
}

func (s *Service) ReadinessReason() string {
	if s == nil || !s.Ready() {
		return "execution.v2 provider composition is not ready"
	}
	if s.cloudWorker == nil && !s.genericProviderReady() {
		return "execution.v2 has no ready Cloud Worker or generic typed provider route"
	}
	return ""
}

func (s *Service) Get(ctx context.Context, owner, kind, id string, revision uint64) (Record, error) {
	if s == nil || s.store == nil || strings.TrimSpace(owner) == "" {
		return Record{}, ErrInvalid
	}
	return s.store.Read(ctx, strings.TrimSpace(owner), strings.TrimSpace(kind), strings.TrimSpace(id), revision)
}

func (s *Service) Events(ctx context.Context, owner, kind, id string, after uint64, limit int) ([]Event, uint64, error) {
	if s == nil || s.store == nil || strings.TrimSpace(owner) == "" {
		return nil, 0, ErrInvalid
	}
	if limit < 1 || limit > 200 {
		return nil, 0, ErrInvalid
	}
	return s.store.Events(ctx, strings.TrimSpace(owner), strings.TrimSpace(kind), strings.TrimSpace(id), after, limit)
}

func validAction(action string) bool {
	_, ok := actionSet[action]
	return ok
}

func (s *Service) Handle(ctx context.Context, owner, action string, params map[string]any) (map[string]any, error) {
	return s.HandleWithAuthority(ctx, Authority{OwnerID: owner}, action, params)
}

// HandleWithAuthority is the authenticated entry point for requests that can
// reach Cloud Worker records. Generic Execution V2 calls continue to use the
// owner-only authority; explicit cloud_worker routing additionally requires a
// positive account generation.
func (s *Service) HandleWithAuthority(ctx context.Context, authority Authority, action string, params map[string]any) (map[string]any, error) {
	if s == nil || !s.Ready() {
		return nil, ErrNotReady
	}
	owner := strings.TrimSpace(authority.OwnerID)
	if owner == "" || !validAction(action) {
		return nil, ErrInvalid
	}
	authority.OwnerID = owner
	params = cloneMap(params)
	if err := validateAction(action, params); err != nil {
		return nil, err
	}
	if stringParam(params, "record_kind") == RecordKindCloudWorker {
		if authority.AccountGeneration == 0 {
			return nil, fmt.Errorf("%w: positive account generation is required for cloud_worker", ErrInvalid)
		}
		return s.handleCloudWorker(ctx, authority, action, params)
	}
	if strings.HasPrefix(action, "agent.execution.v2.secrets.") {
		return s.handleSecret(ctx, owner, action, params)
	}
	if isReadAction(action) {
		return s.handleRead(ctx, owner, action, params)
	}
	return s.handleMutation(ctx, authority, action, params)
}

func isReadAction(action string) bool {
	switch action {
	case "agent.execution.v2.analyses.get", "agent.execution.v2.targets.list", "agent.execution.v2.targets.get", "agent.execution.v2.plans.get", "agent.execution.v2.plans.list", "agent.execution.v2.deployments.list", "agent.execution.v2.deployments.get", "agent.execution.v2.deployments.events", "agent.execution.v2.runs.get", "agent.execution.v2.runs.list", "agent.execution.v2.runs.events", "agent.execution.v2.artifacts.get", "agent.execution.v2.artifacts.download", "agent.execution.v2.service_bindings.list", "agent.execution.v2.service_bindings.get", "agent.execution.v2.secrets.get", "agent.execution.v2.secrets.list":
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
	case "agent.execution.v2.runs.get", "agent.execution.v2.runs.cancel", "agent.execution.v2.runs.retry", "agent.execution.v2.runs.events":
		return "run_id"
	case "agent.execution.v2.artifacts.get", "agent.execution.v2.artifacts.download":
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

func deterministicID(owner, action, idempotencyKey string) string {
	return uuid.NewSHA1(uuid.NameSpaceOID, []byte(owner+"\x00"+action+"\x00"+idempotencyKey)).String()
}

func (s *Service) replay(ctx context.Context, owner, action, idem string, digest []byte) (map[string]any, bool, error) {
	replay, ok, err := s.store.Replay(ctx, owner, action, idem)
	if err != nil || !ok {
		return nil, ok, err
	}
	if !equalBytes(replay.Digest, digest) {
		return nil, true, ErrConflict
	}
	var result map[string]any
	if err := json.Unmarshal(replay.Response, &result); err != nil {
		return nil, true, ErrConflict
	}
	return result, true, nil
}

func (s *Service) saveReplay(ctx context.Context, owner, action, idem string, digest []byte, result map[string]any) error {
	raw, err := json.Marshal(result)
	if err != nil {
		return err
	}
	return s.store.SaveReplay(ctx, owner, action, idem, digest, raw)
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

func ownedPayload(owner string, payload map[string]any) map[string]any {
	out := cloneMap(payload)
	out["owner_id"] = owner
	return out
}

func digestPayload(payload map[string]any) string {
	raw, _ := json.Marshal(payload)
	digest := sha256.Sum256(raw)
	return hex.EncodeToString(digest[:])
}

func (s *Service) putNew(ctx context.Context, owner, kind, id, status string, payload map[string]any) (Record, error) {
	now := s.now().UTC()
	payload = ownedPayload(owner, payload)
	record := Record{OwnerID: owner, Kind: kind, ID: id, Revision: 1, Status: status, Digest: digestPayload(payload), Payload: payload, CreatedAt: now, UpdatedAt: now}
	return s.store.Create(ctx, record)
}

func (s *Service) update(ctx context.Context, record Record, status string, payload map[string]any) (Record, error) {
	payload = ownedPayload(record.OwnerID, payload)
	record.Status = status
	record.Digest = digestPayload(payload)
	record.Payload = payload
	record.UpdatedAt = s.now().UTC()
	return s.store.Update(ctx, record, record.Revision)
}

func (s *Service) emit(ctx context.Context, record Record, eventType string, payload map[string]any) error {
	_, err := s.store.AppendEvent(ctx, Event{OwnerID: record.OwnerID, Kind: record.Kind, ResourceID: record.ID, EventID: uuid.NewString(), Type: eventType, Payload: ownedPayload(record.OwnerID, payload), CreatedAt: s.now().UTC()})
	return err
}

func (s *Service) handleRead(ctx context.Context, owner, action string, in map[string]any) (map[string]any, error) {
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
		events, next, err := s.store.Events(ctx, owner, kind, id, after, limit)
		if err != nil {
			return nil, err
		}
		values := make([]any, 0, len(events))
		for _, event := range events {
			item := ownedPayload(owner, event.Payload)
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
	if action == "agent.execution.v2.targets.list" || action == "agent.execution.v2.plans.list" || action == "agent.execution.v2.deployments.list" || action == "agent.execution.v2.runs.list" || action == "agent.execution.v2.service_bindings.list" || action == "agent.execution.v2.secrets.list" {
		limit := intParam(in, "page_size", 100)
		if limit < 1 || limit > 200 {
			return nil, ErrInvalid
		}
		filter := map[string]string{}
		for _, key := range []string{"project_id", "deployment_id", "status"} {
			if value := stringParam(in, key); value != "" {
				filter[key] = value
			}
		}
		items, next, err := s.store.List(ctx, owner, kind, filter, stringParam(in, "page_token"), limit)
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
	record, err := s.store.Read(ctx, owner, kind, id, revision)
	if err != nil {
		return nil, err
	}
	key := map[string]string{"analysis": "analysis", "target": "target", "plan": "plan", "deployment": "deployment", "run": "run", "artifact": "artifact", "binding": "binding"}[kind]
	result := map[string]any{key: publicRecord(record)}
	if kind == "run" {
		stages := []any{}
		if stage, stageErr := stageForRun(ctx, s.store, owner, record); stageErr == nil {
			stages = append(stages, stageView(stage))
		} else if !errors.Is(stageErr, ErrNotFound) {
			return nil, stageErr
		}
		result["stages"] = stages
	}
	return result, nil
}

func publicRecord(record Record) map[string]any {
	out := ownedPayload(record.OwnerID, record.Payload)
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
