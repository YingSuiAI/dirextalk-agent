// Package production contains the Agent-owned execution.v2 provider
// composition.  It is intentionally a narrow bridge: callers supply typed
// AWS inspection/catalog seams and the adapter builds the six
// coreexecutionv2.ProviderInterfaces.  No action names, SDK requests,
// endpoints, shell commands, or credential bytes cross this package.
package production

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/coreexecutionv2"
	"github.com/YingSuiAI/dirextalk-agent/internal/coreworkload"
	workaws "github.com/YingSuiAI/dirextalk-agent/internal/coreworkload/aws"
	"github.com/google/uuid"
)

var (
	ErrInvalid     = errors.New("execution.v2 production: invalid composition")
	ErrNotReady    = errors.New("execution.v2 production: provider composition is not ready")
	ErrConflict    = errors.New("execution.v2 production: provider readback conflict")
	ErrUnavailable = errors.New("execution.v2 production: typed provider unavailable")
)

var operationNameRE = regexp.MustCompile(`^[a-z][a-z0-9._-]{0,63}$`)

// CredentialRevision resolves the exact durable credential revision without
// returning secret material. It is required so a request cannot reuse a
// rotated credential under the same reference ID.
type CredentialRevision func(context.Context, string) (uint64, error)

// Inspector is the only AWS target read boundary used by this adapter. An
// implementation should be backed by the existing typed SSM/ECS provider and
// perform identity/readback fencing before returning facts.
type Inspector interface {
	Inspect(context.Context, coreworkload.TargetSettings, workaws.CredentialHandle) (Inspection, error)
	Ready() bool
}

type InspectorFunc func(context.Context, coreworkload.TargetSettings, workaws.CredentialHandle) (Inspection, error)

func (f InspectorFunc) Inspect(ctx context.Context, target coreworkload.TargetSettings, credential workaws.CredentialHandle) (Inspection, error) {
	if f == nil {
		return Inspection{}, ErrUnavailable
	}
	return f(ctx, target, credential)
}
func (f InspectorFunc) Ready() bool { return f != nil }

// ReservationCatalog is a read-only regional offer/price catalog. Reserving
// an execution target only persists an immutable intent; it never creates an
// EC2 instance or invokes a CloudFormation mutation.
type ReservationCatalog interface {
	ResolveReservation(context.Context, workaws.CredentialHandle, string, uint64) (ReservationOffer, error)
	Ready() bool
}

type ReservationOffer struct {
	InfrastructureProfileID string
	AMIParameter            string
	InstanceType            string
	AvailabilityZone        string
	VolumeGiB               uint64
	Architecture            string
	ManagementTransport     string
	PublicIP                bool
	PublicInbound           bool
	CostAmount              string
	CostCurrency            string
	CostExpiresAt           time.Time
}

// BindingInvoker is a schema-pinned capability invoker. The implementation
// must enforce an explicit operation allowlist and use typed requests; a
// generic HTTP/AWS passthrough is deliberately not representable here.
type BindingInvoker interface {
	Invoke(context.Context, string, coreexecutionv2.InvokeRequest) (map[string]any, error)
	Ready() bool
}

// RunReconciler reads an already persisted provider outcome. It must never
// retry or dispatch an unknown mutation.
type RunReconciler interface {
	Reconcile(context.Context, string, coreexecutionv2.ReconcileRequest) (map[string]any, error)
	Ready() bool
}

type Config struct {
	Enabled             bool
	Store               coreexecutionv2.Store
	Credentials         workaws.CredentialResolver
	CredentialRevision  CredentialRevision
	Inspector           Inspector
	Reservations        ReservationCatalog
	ImportTarget        coreworkload.TargetSettings
	CredentialReference string
	Probe               func(context.Context) error
	ProbeTimeout        time.Duration
	BindingOperations   []string
	Invoker             BindingInvoker
	Reconciler          RunReconciler
	Now                 func() time.Time
}

// Composition owns the six typed provider interfaces and the readiness proof
// captured during startup. It is safe to pass Interfaces directly to
// coreexecutionv2.NewServiceWithProviderInterfaces.
type Composition struct {
	interfaces coreexecutionv2.ProviderInterfaces
	ready      atomic.Bool
	reason     string
}

func New(cfg Config) (*Composition, error) {
	if !cfg.Enabled {
		return nil, nil
	}
	if cfg.Store == nil || cfg.Credentials == nil || cfg.CredentialRevision == nil || cfg.Inspector == nil || !cfg.Inspector.Ready() || cfg.Reservations == nil || !cfg.Reservations.Ready() || cfg.Probe == nil {
		return nil, fmt.Errorf("%w: durable store, exact credentials, inspector, reservation catalog, and probe are required", ErrInvalid)
	}
	if cfg.ProbeTimeout <= 0 {
		cfg.ProbeTimeout = 10 * time.Second
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if err := validateBindingOperations(cfg.BindingOperations); err != nil {
		return nil, err
	}
	if err := cfg.ImportTarget.ValidateProviderTarget(coreworkload.TargetAWSEC2SSM); err != nil {
		return nil, fmt.Errorf("%w: import target: %v", ErrInvalid, err)
	}
	if strings.TrimSpace(cfg.CredentialReference) == "" || !coreworkload.ValidUUID(cfg.CredentialReference) {
		return nil, fmt.Errorf("%w: credential_reference must be canonical UUID", ErrInvalid)
	}
	a := &Adapter{cfg: cfg, allowed: append([]string(nil), cfg.BindingOperations...)}
	if a.cfg.Invoker == nil {
		for _, operation := range a.allowed {
			if operation != "target.observe" {
				return nil, fmt.Errorf("%w: default binding invoker only supports target.observe", ErrInvalid)
			}
		}
		a.cfg.Invoker = storeInvoker{adapter: a}
	}
	if a.cfg.Reconciler == nil {
		a.cfg.Reconciler = storeReconciler{adapter: a}
	}
	if !a.cfg.Invoker.Ready() {
		return nil, fmt.Errorf("%w: binding invoker is unavailable", ErrInvalid)
	}
	if !a.cfg.Reconciler.Ready() {
		return nil, fmt.Errorf("%w: run reconciler is unavailable", ErrInvalid)
	}
	a.ready.Store(true)
	composition := &Composition{interfaces: a.ProviderInterfaces(), reason: ""}
	composition.ready.Store(true)
	return composition, nil
}

func validateBindingOperations(values []string) error {
	if len(values) == 0 {
		return fmt.Errorf("%w: at least one binding operation must be allowlisted", ErrInvalid)
	}
	seen := map[string]struct{}{}
	for _, value := range values {
		value = strings.TrimSpace(value)
		if !operationNameRE.MatchString(value) {
			return fmt.Errorf("%w: invalid binding operation", ErrInvalid)
		}
		if value == "workload.apply" || value == "workload.destroy" {
			return fmt.Errorf("%w: workload mutations require a confirmed run", ErrInvalid)
		}
		if _, ok := seen[value]; ok {
			return fmt.Errorf("%w: duplicate binding operation", ErrInvalid)
		}
		seen[value] = struct{}{}
	}
	return nil
}

func (c *Composition) Interfaces() coreexecutionv2.ProviderInterfaces {
	if c == nil {
		return coreexecutionv2.ProviderInterfaces{}
	}
	return c.interfaces
}
func (c *Composition) Ready() bool { return c != nil && c.ready.Load() }
func (c *Composition) ReadinessReason() string {
	if c == nil {
		return string(ErrNotReady.Error())
	}
	return c.reason
}

type Adapter struct {
	cfg           Config
	allowed       []string
	ready         atomic.Bool
	probeMu       sync.Mutex
	probeComplete atomic.Bool
}

func (a *Adapter) Ready() bool { return a != nil && a.ready.Load() }

// ensureProbe is the explicit first-action readiness gate. Composition must
// never contact AWS during process startup; the first provider action performs
// one exact configured probe and publishes the result for subsequent calls.
func (a *Adapter) ensureProbe(ctx context.Context) error {
	if a == nil || !a.Ready() || a.cfg.Probe == nil {
		return ErrNotReady
	}
	if a.probeComplete.Load() {
		return nil
	}
	a.probeMu.Lock()
	defer a.probeMu.Unlock()
	if a.probeComplete.Load() {
		return nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	probeCtx, cancel := context.WithTimeout(ctx, a.cfg.ProbeTimeout)
	err := a.cfg.Probe(probeCtx)
	cancel()
	if err != nil {
		return fmt.Errorf("%w: lazy readiness probe failed: %v", ErrNotReady, redactProviderError(err))
	}
	a.probeComplete.Store(true)
	return nil
}

func (a *Adapter) ProviderInterfaces() coreexecutionv2.ProviderInterfaces {
	return coreexecutionv2.ProviderInterfaces{
		Analyze:       analyzeProvider{adapter: a},
		ImportTarget:  importProvider{adapter: a},
		ReserveTarget: reserveProvider{adapter: a},
		Observe:       observeProvider{adapter: a},
		Invoke:        invokeProvider{adapter: a},
		Reconcile:     reconcileProvider{adapter: a},
		Ready:         a.Ready,
	}
}

type analyzeProvider struct{ adapter *Adapter }

func (p analyzeProvider) Analyze(ctx context.Context, owner string, req coreexecutionv2.AnalyzeRequest) (map[string]any, error) {
	if p.adapter == nil || !p.adapter.Ready() || ctx == nil || strings.TrimSpace(owner) == "" {
		return nil, ErrNotReady
	}
	digest, err := canonicalDigest(struct {
		Project string
		Source  coreexecutionv2.Source
	}{req.ProjectID, req.Source})
	if err != nil {
		return nil, ErrInvalid
	}
	return map[string]any{
		"analysis_id": deterministicID(owner, "analysis", req.ProjectID+"\x00"+digest),
		"project_id":  req.ProjectID,
		"status":      "ready",
		"source": map[string]any{
			"kind": req.Source.Kind, "location": req.Source.Location, "commit": req.Source.Commit,
			"artifact_id": req.Source.ArtifactID, "immutable": req.Source.Immutable,
		},
		"source_digest": digest,
		"provider":      "agent.execution.v2.source-analyzer-v1",
	}, nil
}

type importProvider struct{ adapter *Adapter }

func (p importProvider) ImportTarget(ctx context.Context, owner string, req coreexecutionv2.TargetImportRequest) (map[string]any, error) {
	a := p.adapter
	if a == nil || !a.Ready() {
		return nil, ErrNotReady
	}
	if err := a.ensureProbe(ctx); err != nil {
		return nil, err
	}
	if req.CredentialID != a.cfg.CredentialReference {
		return nil, ErrConflict
	}
	if err := a.checkCredentialRevision(ctx, req.CredentialID, req.CredentialRevision); err != nil {
		return nil, err
	}
	h, err := a.cfg.Credentials.ResolveCredential(ctx, req.CredentialID)
	if err != nil || h.ReferenceID != req.CredentialID {
		return nil, ErrUnavailable
	}
	target := a.cfg.ImportTarget
	target.InstanceID = req.InstanceID
	target.Identity.InstanceID = req.InstanceID
	target.Region, target.AccountID = h.Region, h.AccountID
	target.Identity.Region, target.Identity.AccountID = h.Region, h.AccountID
	if err := target.ValidateProviderTarget(coreworkload.TargetAWSEC2SSM); err != nil {
		return nil, ErrConflict
	}
	inspection, err := a.cfg.Inspector.Inspect(ctx, target, h)
	if err != nil || inspection.State != "ready" || inspection.InstanceID != req.InstanceID || inspection.AccountID != h.AccountID || inspection.Region != h.Region {
		return nil, ErrUnavailable
	}
	targetID := deterministicID(owner, "aws-ec2-ssm-target", h.AccountID+"\x00"+h.Region+"\x00"+req.InstanceID)
	observationID := deterministicID(owner, "target-observation", req.IdempotencyKey)
	return map[string]any{
		"target_id": targetID, "provider": "aws", "kind": "aws_ec2_instance", "revision": uint64(1),
		"account_id": h.AccountID, "region": h.Region, "instance_id": req.InstanceID,
		"infrastructure_profile_id": "aws-ec2-ssm-v1", "credential_id": req.CredentialID, "credential_revision": req.CredentialRevision,
		"capabilities":    []any{"transport.aws_ssm", "target.aws_ec2_instance"},
		"target_settings": targetSettingsMap(target),
		"observation_id":  observationID,
		"observation":     observationMap(targetID, 1, inspection),
	}, nil
}

type reserveProvider struct{ adapter *Adapter }

func (p reserveProvider) ReserveTarget(ctx context.Context, owner string, req coreexecutionv2.TargetReserveRequest) (map[string]any, error) {
	a := p.adapter
	if a == nil || !a.Ready() {
		return nil, ErrNotReady
	}
	if err := a.ensureProbe(ctx); err != nil {
		return nil, err
	}
	if err := a.checkCredentialRevision(ctx, req.CredentialID, req.CredentialRevision); err != nil {
		return nil, err
	}
	h, err := a.cfg.Credentials.ResolveCredential(ctx, req.CredentialID)
	if err != nil || h.ReferenceID != req.CredentialID {
		return nil, ErrUnavailable
	}
	offer, err := a.cfg.Reservations.ResolveReservation(ctx, h, req.InstanceType, req.VolumeGiB)
	if err != nil || offer.InstanceType != req.InstanceType || offer.VolumeGiB != req.VolumeGiB || offer.Architecture != "x86_64" || offer.ManagementTransport != "aws_ssm" || !offer.PublicIP || offer.PublicInbound || offer.CostAmount == "" || offer.CostCurrency == "" || offer.CostExpiresAt.IsZero() || !offer.CostExpiresAt.After(a.cfg.Now().UTC()) {
		return nil, ErrUnavailable
	}
	targetID := deterministicID(owner, "aws-compute-reservation", req.IdempotencyKey)
	return map[string]any{
		"target_id": targetID, "provider": "aws", "kind": "aws_compute_reservation", "revision": uint64(1),
		"account_id": h.AccountID, "region": h.Region, "architecture": offer.Architecture,
		"infrastructure_profile_id": offer.InfrastructureProfileID, "credential_id": req.CredentialID, "credential_revision": req.CredentialRevision,
		"capabilities":    []any{"compute.catalog", "compute.provision", "target.aws_compute_reservation"},
		"network":         map[string]any{"mode": "restricted"},
		"credential_refs": []any{map[string]any{"ref": req.CredentialID, "purpose": "aws", "revision": req.CredentialRevision, "binding_digest": credentialBindingDigest(owner, req.CredentialID, req.CredentialRevision)}},
		"compute_reservation": map[string]any{
			"infrastructure_profile_id": offer.InfrastructureProfileID, "ami_parameter": offer.AMIParameter,
			"instance_type": offer.InstanceType, "availability_zone": offer.AvailabilityZone, "volume_gib": offer.VolumeGiB,
			"architecture": offer.Architecture, "management_transport": offer.ManagementTransport, "public_ip": offer.PublicIP,
			"public_inbound": offer.PublicInbound, "cost_quote": map[string]any{"amount": offer.CostAmount, "currency": offer.CostCurrency, "expires_at": offer.CostExpiresAt.UTC().Format(time.RFC3339Nano)},
		},
	}, nil
}

type observeProvider struct{ adapter *Adapter }

func (p observeProvider) Observe(ctx context.Context, owner string, req coreexecutionv2.TargetObserveRequest) (map[string]any, error) {
	a := p.adapter
	if a == nil || !a.Ready() || a.cfg.Store == nil {
		return nil, ErrNotReady
	}
	if err := a.ensureProbe(ctx); err != nil {
		return nil, err
	}
	record, err := a.cfg.Store.Read(ctx, owner, "target", req.TargetID, req.TargetRevision)
	if err != nil {
		return nil, err
	}
	target, credential, err := a.targetFromRecord(ctx, record)
	if err != nil {
		return nil, err
	}
	inspection, err := a.cfg.Inspector.Inspect(ctx, target, credential)
	if err != nil && inspection.TargetID == "" {
		return nil, ErrUnavailable
	}
	if inspection.TargetID != "" && inspection.TargetID != req.TargetID {
		return nil, ErrConflict
	}
	return observationMap(req.TargetID, req.TargetRevision, inspection), nil
}

type invokeProvider struct{ adapter *Adapter }

func (p invokeProvider) Invoke(ctx context.Context, owner string, req coreexecutionv2.InvokeRequest) (map[string]any, error) {
	a := p.adapter
	if a == nil || !a.Ready() || a.cfg.Invoker == nil {
		return nil, ErrNotReady
	}
	if err := a.ensureProbe(ctx); err != nil {
		return nil, err
	}
	if !contains(a.allowed, req.Operation) {
		return nil, coreexecutionv2.ErrUnsupported
	}
	result, err := a.cfg.Invoker.Invoke(ctx, owner, req)
	if err != nil {
		return nil, ErrUnavailable
	}
	return sanitizeMap(result)
}

type reconcileProvider struct{ adapter *Adapter }

func (p reconcileProvider) Reconcile(ctx context.Context, owner string, req coreexecutionv2.ReconcileRequest) (map[string]any, error) {
	a := p.adapter
	if a == nil || !a.Ready() || a.cfg.Reconciler == nil {
		return nil, ErrNotReady
	}
	if err := a.ensureProbe(ctx); err != nil {
		return nil, err
	}
	result, err := a.cfg.Reconciler.Reconcile(ctx, owner, req)
	if err != nil {
		return nil, ErrUnavailable
	}
	return sanitizeMap(result)
}

type storeInvoker struct{ adapter *Adapter }

func (i storeInvoker) Ready() bool {
	return i.adapter != nil && i.adapter.cfg.Store != nil && i.adapter.cfg.Inspector != nil && i.adapter.cfg.Credentials != nil
}
func (i storeInvoker) Invoke(ctx context.Context, owner string, req coreexecutionv2.InvokeRequest) (map[string]any, error) {
	if !i.Ready() || req.Operation != "target.observe" {
		return nil, coreexecutionv2.ErrUnsupported
	}
	targetID := stringValue(req.Input, "target_id")
	if targetID == "" {
		record, err := i.adapter.cfg.Store.Read(ctx, owner, "binding", req.BindingID, req.ExpectedRevision)
		if err != nil {
			return nil, err
		}
		targetID = stringValue(record.Payload, "target_id")
	}
	if !coreworkload.ValidUUID(targetID) {
		return nil, ErrConflict
	}
	targetRevision := uintValue(req.Input, "target_revision")
	if targetRevision == 0 {
		targetRevision = 1
	}
	return observeProvider{adapter: i.adapter}.Observe(ctx, owner, coreexecutionv2.TargetObserveRequest{TargetID: targetID, TargetRevision: targetRevision, IdempotencyKey: req.IdempotencyKey})
}

type storeReconciler struct{ adapter *Adapter }

func (r storeReconciler) Ready() bool {
	return r.adapter != nil && r.adapter.cfg.Store != nil && r.adapter.cfg.Inspector != nil && r.adapter.cfg.Credentials != nil
}
func (r storeReconciler) Reconcile(ctx context.Context, owner string, req coreexecutionv2.ReconcileRequest) (map[string]any, error) {
	if !r.Ready() {
		return nil, ErrNotReady
	}
	run, err := r.adapter.cfg.Store.Read(ctx, owner, "run", req.RunID, 0)
	if err != nil {
		return nil, err
	}
	planID := stringValue(run.Payload, "plan_id")
	if !coreworkload.ValidUUID(planID) {
		return nil, ErrConflict
	}
	plan, err := r.adapter.cfg.Store.Read(ctx, owner, "plan", planID, 0)
	if err != nil {
		return nil, err
	}
	targetID := stringValue(plan.Payload, "target_id")
	if !coreworkload.ValidUUID(targetID) {
		return nil, ErrConflict
	}
	targetRevision := uintValue(plan.Payload, "target_revision")
	if targetRevision == 0 {
		targetRevision = 1
	}
	observation, err := observeProvider{adapter: r.adapter}.Observe(ctx, owner, coreexecutionv2.TargetObserveRequest{TargetID: targetID, TargetRevision: targetRevision, IdempotencyKey: req.IdempotencyKey})
	if err != nil {
		return nil, err
	}
	status := "uncertain"
	if stringValue(observation, "state") == "ready" {
		status = "succeeded"
	}
	return map[string]any{"run_id": req.RunID, "stage_id": req.StageID, "status": status, "target_id": targetID, "observation": observation}, nil
}

func (a *Adapter) checkCredentialRevision(ctx context.Context, ref string, revision uint64) error {
	if revision == 0 || ref == "" || a == nil || a.cfg.CredentialRevision == nil {
		return ErrInvalid
	}
	actual, err := a.cfg.CredentialRevision(ctx, ref)
	if err != nil || actual != revision {
		return ErrConflict
	}
	return nil
}

func (a *Adapter) targetFromRecord(ctx context.Context, record coreexecutionv2.Record) (coreworkload.TargetSettings, workaws.CredentialHandle, error) {
	if record.Kind != "target" || record.Revision == 0 {
		return coreworkload.TargetSettings{}, workaws.CredentialHandle{}, ErrConflict
	}
	settings, err := targetSettingsFromMap(record.Payload["target_settings"])
	if err != nil {
		return coreworkload.TargetSettings{}, workaws.CredentialHandle{}, err
	}
	credentialID := stringValue(record.Payload, "credential_id")
	credentialRevision := uintValue(record.Payload, "credential_revision")
	if credentialID == "" || credentialRevision == 0 {
		return coreworkload.TargetSettings{}, workaws.CredentialHandle{}, ErrConflict
	}
	if err = a.checkCredentialRevision(ctx, credentialID, credentialRevision); err != nil {
		return coreworkload.TargetSettings{}, workaws.CredentialHandle{}, err
	}
	credential, err := a.cfg.Credentials.ResolveCredential(ctx, credentialID)
	if err != nil {
		return coreworkload.TargetSettings{}, workaws.CredentialHandle{}, ErrUnavailable
	}
	return settings, credential, nil
}

func targetSettingsMap(target coreworkload.TargetSettings) map[string]any {
	return map[string]any{
		"region": target.Region, "account_id": target.AccountID, "instance_id": target.InstanceID,
		"ec2_document_version": target.EC2DocumentVersion, "ec2_systemd_service": target.EC2SystemdService,
		"required_instance_tags": cloneStringMap(target.RequiredInstanceTags),
		"identity":               map[string]any{"kind": string(target.Identity.Kind), "region": target.Identity.Region, "account_id": target.Identity.AccountID, "instance_id": target.Identity.InstanceID},
	}
}

func targetSettingsFromMap(raw any) (coreworkload.TargetSettings, error) {
	b, err := json.Marshal(raw)
	if err != nil {
		return coreworkload.TargetSettings{}, ErrConflict
	}
	var target coreworkload.TargetSettings
	if err = json.Unmarshal(b, &target); err != nil {
		return coreworkload.TargetSettings{}, ErrConflict
	}
	if err = target.ValidateProviderTarget(coreworkload.TargetAWSEC2SSM); err != nil {
		return coreworkload.TargetSettings{}, ErrConflict
	}
	return target, nil
}

type Inspection struct {
	TargetID   string
	State      string
	AccountID  string
	Region     string
	InstanceID string
	Facts      map[string]string
}

func observationMap(targetID string, revision uint64, inspection Inspection) map[string]any {
	facts := map[string]any{}
	keys := make([]string, 0, len(inspection.Facts))
	for key := range inspection.Facts {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		facts[key] = inspection.Facts[key]
	}
	return map[string]any{"target_id": targetID, "target_revision": revision, "state": inspection.State, "account_id": inspection.AccountID, "region": inspection.Region, "instance_id": inspection.InstanceID, "facts": facts, "observed_at": time.Now().UTC().Format(time.RFC3339Nano)}
}

func credentialBindingDigest(owner, ref string, revision uint64) string {
	sum := sha256.Sum256([]byte("execution-v2-credential\x00" + owner + "\x00" + ref + "\x00" + fmt.Sprint(revision)))
	return hex.EncodeToString(sum[:])
}

func deterministicID(owner, namespace, key string) string {
	return uuid.NewSHA1(uuid.NameSpaceOID, []byte(namespace+"\x00"+strings.TrimSpace(owner)+"\x00"+key)).String()
}

func canonicalDigest(value any) (string, error) {
	b, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}

func sanitizeMap(value map[string]any) (map[string]any, error) {
	if value == nil {
		return nil, coreexecutionv2.ErrUnsafeOutput
	}
	if err := sanitizeValue(value, 0); err != nil {
		return nil, err
	}
	b, err := json.Marshal(value)
	if err != nil || len(b) > 1<<20 {
		return nil, coreexecutionv2.ErrUnsafeOutput
	}
	var out map[string]any
	if err := json.Unmarshal(b, &out); err != nil {
		return nil, coreexecutionv2.ErrUnsafeOutput
	}
	return out, nil
}

func sanitizeValue(value any, depth int) error {
	if depth > 16 {
		return coreexecutionv2.ErrUnsafeOutput
	}
	switch v := value.(type) {
	case map[string]any:
		for key, child := range v {
			normalized := strings.ToLower(strings.NewReplacer("-", "_", ".", "_").Replace(strings.TrimSpace(key)))
			switch normalized {
			case "authorization", "password", "passwd", "secret", "token", "access_token", "api_key", "private_key", "aws_access_key_id", "aws_secret_access_key", "cookie", "set_cookie", "owner_id":
				return coreexecutionv2.ErrUnsafeOutput
			}
			if err := sanitizeValue(child, depth+1); err != nil {
				return err
			}
		}
	case []any:
		for _, child := range v {
			if err := sanitizeValue(child, depth+1); err != nil {
				return err
			}
		}
	case string:
		if len(v) > 16<<10 || strings.ContainsAny(v, "\x00\r\n") {
			return coreexecutionv2.ErrUnsafeOutput
		}
	case nil, bool, float32, float64,
		int, int8, int16, int32, int64,
		uint, uint8, uint16, uint32, uint64:
	default:
		return coreexecutionv2.ErrUnsafeOutput
	}
	return nil
}

func sanitizeProviderError(err error) string {
	if err == nil {
		return ""
	}
	return "typed provider unavailable"
}

func redactProviderError(err error) string { return sanitizeProviderError(err) }
func contains(values []string, value string) bool {
	for _, item := range values {
		if item == value {
			return true
		}
	}
	return false
}
func stringValue(values map[string]any, key string) string {
	value, _ := values[key].(string)
	return strings.TrimSpace(value)
}
func uintValue(values map[string]any, key string) uint64 {
	switch value := values[key].(type) {
	case float64:
		if value >= 0 && value == float64(uint64(value)) {
			return uint64(value)
		}
	case uint64:
		return value
	case int:
		if value >= 0 {
			return uint64(value)
		}
	case int64:
		if value >= 0 {
			return uint64(value)
		}
	}
	return 0
}
func cloneStringMap(in map[string]string) map[string]string {
	out := make(map[string]string, len(in))
	for key, value := range in {
		out[key] = value
	}
	return out
}

var _ coreexecutionv2.AnalyzeProvider = analyzeProvider{}
var _ coreexecutionv2.TargetImportProvider = importProvider{}
var _ coreexecutionv2.TargetReserveProvider = reserveProvider{}
var _ coreexecutionv2.TargetObserveProvider = observeProvider{}
var _ coreexecutionv2.BindingInvokeProvider = invokeProvider{}
var _ coreexecutionv2.RunReconcileProvider = reconcileProvider{}
