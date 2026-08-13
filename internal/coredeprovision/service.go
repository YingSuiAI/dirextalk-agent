// Package coredeprovision owns the single-owner Agent account purge boundary.
// It is deliberately not exposed through the public Core RPC surface; the
// neutral Capability server is the only caller.
package coredeprovision

import (
	"context"
	"errors"
	"strings"

	"github.com/google/uuid"
)

const Confirmation = "deprovision_account"

var (
	ErrInvalid         = errors.New("invalid account deprovision request")
	ErrConflict        = errors.New("account deprovision idempotency conflict")
	ErrNotReady        = errors.New("account deprovision is not ready")
	ErrRetainedWorkers = errors.New("retained Workers must be destroyed before account deprovision")
	ErrExternalPurge   = errors.New("account external purge failed")
)

const RetainedWorkersMessage = "Destroy all retained Workers before deprovisioning the Agent account"

type Command struct {
	OwnerID           string
	AccountGeneration int64
	IdempotencyKey    string
	Confirmation      string
}

type Result struct {
	Status         string `json:"status"`
	DatabasePurged bool   `json:"database_purged"`
	ExternalPurged bool   `json:"external_purged"`
}

// Store performs the durable database phase and invokes the supplied
// idempotent external purge between its database phases. The implementation
// persists progress so a retry after a process restart resumes cleanup rather
// than re-running arbitrary business operations.
type Store interface {
	Deprovision(context.Context, Command, func(context.Context) error, func(context.Context) error) (Result, error)
}

// DeprovisionPreconditionChecker validates external state that must survive
// account deprovision. Implementations are read-only and must fail closed when
// they cannot establish whether the precondition is satisfied.
type DeprovisionPreconditionChecker interface {
	CheckDeprovision(context.Context, Command) error
}

type AdmissionChecker interface {
	CheckAdmission(context.Context, string, int64) error
}

type FenceStateReader interface {
	HasDeprovisionFence(context.Context) (bool, error)
}

type Service struct {
	store        Store
	fence        *LifecycleFence
	precondition DeprovisionPreconditionChecker
}

func NewService(store Store, fences ...*LifecycleFence) (*Service, error) {
	if store == nil {
		return nil, ErrInvalid
	}
	fence := NewLifecycleFence()
	if len(fences) > 0 && fences[0] != nil {
		fence = fences[0]
	}
	return &Service{store: store, fence: fence}, nil
}

// SetDeprovisionPrecondition binds the read-only external-state check before
// the service is published. The service reuses the same check at admission
// and at the store mutation boundary after process-local writers are drained.
func (s *Service) SetDeprovisionPrecondition(checker DeprovisionPreconditionChecker) error {
	if s == nil || s.store == nil || s.fence == nil || checker == nil {
		return ErrInvalid
	}
	s.precondition = checker
	return nil
}

func (s *Service) Deprovision(ctx context.Context, command Command, externalPurge func(context.Context) error) (Result, error) {
	if s == nil || s.store == nil || s.fence == nil || ctx == nil || strings.TrimSpace(command.OwnerID) == "" || command.AccountGeneration <= 0 || !validUUID(command.IdempotencyKey) || command.Confirmation != Confirmation || externalPurge == nil {
		return Result{}, ErrInvalid
	}
	checkPrecondition := func(checkCtx context.Context) error {
		if s.precondition == nil {
			// A restored durable fence means the database phase already committed;
			// its replay must finish external cleanup without recreating state.
			if s.fence.IsSealed() {
				return nil
			}
			return ErrInvalid
		}
		return s.precondition.CheckDeprovision(checkCtx, command)
	}
	if err := checkPrecondition(ctx); err != nil {
		return Result{}, err
	}
	lease, err := s.fence.BeginPurge(ctx)
	if err != nil {
		return Result{}, err
	}
	result, err := s.store.Deprovision(ctx, command, checkPrecondition, externalPurge)
	if err != nil {
		if result.DatabasePurged {
			lease.Finish()
		} else {
			lease.Abort()
		}
		return result, err
	}
	lease.Finish()
	return result, nil
}

// CheckAdmission is used by the neutral operation ledger before admitting or
// executing any non-deprovision capability. Once the durable fence exists the
// single-owner Agent is fail-closed until the exact deprovision replay is
// handled; this prevents writers and background callbacks from recreating data.
func (s *Service) CheckAdmission(ctx context.Context, owner string, generation int64) error {
	if s == nil || s.store == nil || s.fence == nil || strings.TrimSpace(owner) == "" || generation <= 0 {
		return ErrInvalid
	}
	s.fence.mu.Lock()
	sealed := s.fence.sealed || s.fence.writer
	s.fence.mu.Unlock()
	if sealed {
		return ErrNotReady
	}
	checker, ok := s.store.(AdmissionChecker)
	if !ok {
		return nil
	}
	return checker.CheckAdmission(ctx, owner, generation)
}

// EnterMutation is the common process-local gate used by capability
// execution, task workers, and background reconciliation loops.
func (s *Service) EnterMutation(ctx context.Context) (func(), error) {
	if s == nil || s.fence == nil {
		return nil, ErrInvalid
	}
	return s.fence.Enter(ctx)
}

// Enter implements the shared coreruntime.MutationGuard contract without
// coupling the deprovision domain to the runtime package.
func (s *Service) Enter(ctx context.Context) (func(), error) {
	return s.EnterMutation(ctx)
}

func (s *Service) LifecycleFence() *LifecycleFence {
	if s == nil {
		return nil
	}
	return s.fence
}

// RestoreFence must run before publishing any Core/capability listener. A
// durable deprovision receipt is a fail-closed account lifecycle marker even
// when the previous process stopped between the database and external purge
// phases.
func (s *Service) RestoreFence(ctx context.Context) error {
	if s == nil || s.store == nil || s.fence == nil {
		return ErrInvalid
	}
	reader, ok := s.store.(FenceStateReader)
	if !ok {
		return nil
	}
	sealed, err := reader.HasDeprovisionFence(ctx)
	if err != nil {
		return err
	}
	if sealed {
		return s.fence.RestoreSealed()
	}
	return nil
}

func validUUID(value string) bool {
	_, err := uuid.Parse(strings.TrimSpace(value))
	return err == nil
}
