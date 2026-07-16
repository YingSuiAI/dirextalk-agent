package workerrunner

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/installer"
)

const (
	executionBundleSchemaV1 = 1
	maxBundleBytes          = 8 << 20
	maxActions              = 256
)

var (
	ErrInvalidBundle   = errors.New("invalid Worker execution bundle")
	ErrDigestMismatch  = errors.New("Worker bundle digest mismatch")
	ErrUnknownAction   = errors.New("Worker action is not registered")
	ErrInstallerAction = errors.New("Worker installer execution failed")
	actionIDPattern    = regexp.MustCompile(`^[a-z][a-z0-9_.-]{0,63}$`)
)

// ExecutionBundleV1 contains only typed registry actions. Installer actions
// may carry an immutable signed capability containing exact argv, but there is
// no unsigned runtime shell, command, argv, or generic environment field.
type ExecutionBundleV1 struct {
	SchemaVersion int        `json:"schema_version"`
	RecipeSHA256  string     `json:"recipe_sha256"`
	Actions       []ActionV1 `json:"actions"`
}

type ActionV1 struct {
	ID             string                   `json:"id"`
	Kind           string                   `json:"kind"`
	TimeoutSeconds uint32                   `json:"timeout_seconds"`
	Noop           *NoopInputV1             `json:"noop,omitempty"`
	Installer      *InstallerExecuteInputV1 `json:"installer,omitempty"`
}

type NoopInputV1 struct {
	DelayMillis uint32 `json:"delay_millis"`
}

// InstallerExecuteInputV1 selects one exact command from a signed,
// deployment-scoped delivery. Its mutable selector is command_id; it has no
// runtime argv, environment, path, AWS parameter, or secret value field.
type InstallerExecuteInputV1 struct {
	CommandID string               `json:"command_id"`
	Delivery  installer.DeliveryV1 `json:"delivery"`
	// LeaseGrant is injected only from the claimed WorkerAssignment after the
	// immutable execution bundle has passed digest verification.
	LeaseGrant *installer.SignedLeaseGrantV1 `json:"-"`
}

type ActionResult struct {
	Status string
}

type ActionHandler interface {
	Kind() string
	Validate(ActionV1) error
	Execute(context.Context, ActionV1) (ActionResult, error)
}

type Registry struct{ handlers map[string]ActionHandler }

func NewRegistry(handlers ...ActionHandler) (*Registry, error) {
	registry := &Registry{handlers: make(map[string]ActionHandler, len(handlers))}
	for _, handler := range handlers {
		if handler == nil || !actionIDPattern.MatchString(handler.Kind()) {
			return nil, fmt.Errorf("%w: invalid action handler", ErrInvalidBundle)
		}
		if _, duplicate := registry.handlers[handler.Kind()]; duplicate {
			return nil, fmt.Errorf("%w: duplicate action handler", ErrInvalidBundle)
		}
		registry.handlers[handler.Kind()] = handler
	}
	return registry, nil
}

func DefaultRegistry() *Registry {
	registry, _ := NewRegistry(NoopAction{})
	return registry
}

func (registry *Registry) Validate(bundle ExecutionBundleV1) error {
	if registry == nil || len(registry.handlers) == 0 {
		return ErrUnknownAction
	}
	for _, action := range bundle.Actions {
		handler, ok := registry.handlers[action.Kind]
		if !ok {
			return fmt.Errorf("%w: %s", ErrUnknownAction, action.Kind)
		}
		if err := handler.Validate(action); err != nil {
			return err
		}
	}
	return nil
}

func (registry *Registry) Execute(ctx context.Context, action ActionV1) (ActionResult, error) {
	if registry == nil {
		return ActionResult{}, ErrUnknownAction
	}
	handler, ok := registry.handlers[action.Kind]
	if !ok {
		return ActionResult{}, fmt.Errorf("%w: %s", ErrUnknownAction, action.Kind)
	}
	if err := handler.Validate(action); err != nil {
		return ActionResult{}, err
	}
	return handler.Execute(ctx, action)
}

type NoopAction struct{}

func (NoopAction) Kind() string { return "worker.noop" }

func (NoopAction) Validate(action ActionV1) error {
	if action.Kind != (NoopAction{}).Kind() || action.Noop == nil || action.Installer != nil || action.Noop.DelayMillis > 10_000 {
		return fmt.Errorf("%w: worker.noop input is invalid", ErrInvalidBundle)
	}
	return nil
}

func (NoopAction) Execute(ctx context.Context, action ActionV1) (ActionResult, error) {
	if err := (NoopAction{}).Validate(action); err != nil {
		return ActionResult{}, err
	}
	timer := time.NewTimer(time.Duration(action.Noop.DelayMillis) * time.Millisecond)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ActionResult{}, ctx.Err()
	case <-timer.C:
		return ActionResult{Status: "ok"}, nil
	}
}

func parseExecutionBundle(raw, recipeDigest []byte, executionTimeout time.Duration) (ExecutionBundleV1, error) {
	if len(raw) == 0 || len(raw) > maxBundleBytes || len(recipeDigest) != 32 {
		return ExecutionBundleV1{}, ErrInvalidBundle
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var bundle ExecutionBundleV1
	if err := decoder.Decode(&bundle); err != nil {
		return ExecutionBundleV1{}, fmt.Errorf("%w: decode typed actions", ErrInvalidBundle)
	}
	if err := requireJSONEOF(decoder); err != nil {
		return ExecutionBundleV1{}, err
	}
	if bundle.SchemaVersion != executionBundleSchemaV1 || bundle.RecipeSHA256 != hex.EncodeToString(recipeDigest) || len(bundle.Actions) == 0 || len(bundle.Actions) > maxActions {
		return ExecutionBundleV1{}, ErrInvalidBundle
	}
	seen := make(map[string]struct{}, len(bundle.Actions))
	for _, action := range bundle.Actions {
		if !actionIDPattern.MatchString(action.ID) || !actionIDPattern.MatchString(action.Kind) || action.TimeoutSeconds == 0 ||
			time.Duration(action.TimeoutSeconds)*time.Second > executionTimeout {
			return ExecutionBundleV1{}, ErrInvalidBundle
		}
		if _, duplicate := seen[action.ID]; duplicate {
			return ExecutionBundleV1{}, ErrInvalidBundle
		}
		seen[action.ID] = struct{}{}
	}
	return bundle, nil
}

func requireJSONEOF(decoder *json.Decoder) error {
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return fmt.Errorf("%w: trailing JSON data", ErrInvalidBundle)
	}
	return nil
}
