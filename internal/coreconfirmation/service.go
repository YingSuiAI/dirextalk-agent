package coreconfirmation

import (
	"context"
	"strings"
	"time"
)

// Service validates the shared domain contract. Request/Consume/Expire are
// intentionally domain APIs; the public gRPC surface exposes only Get/List/
// Confirm/Reject.
type Service struct {
	repository    Repository
	now           func() time.Time
	bindingReader TargetBindingReader
	currentReader CurrentTargetBindingReader
}

type TargetBindingReader interface {
	ReadTargetBinding(context.Context, string) (Binding, error)
}
type CurrentTargetBindingReader interface {
	ReadCurrentTargetBinding(context.Context, string, string) (Binding, error)
}

// Authority is the signed account identity carried by the authenticated
// Capability call. Confirmation IDs are opaque references, never an
// authorization boundary by themselves.
type Authority struct {
	OwnerID           string
	AccountGeneration uint64
}

func (a Authority) normalize() (Authority, error) {
	a.OwnerID = strings.TrimSpace(a.OwnerID)
	if a.OwnerID == "" || a.AccountGeneration == 0 {
		return Authority{}, ErrInvalid
	}
	return a, nil
}

func authorizeConfirmation(value Confirmation, authority Authority) error {
	authority, err := authority.normalize()
	if err != nil {
		return err
	}
	storedOwner := strings.TrimSpace(value.OwnerID)
	boundOwner := strings.TrimSpace(value.Binding.OwnerID)
	if (storedOwner != "" && storedOwner != authority.OwnerID) ||
		(boundOwner != "" && boundOwner != authority.OwnerID) {
		// Do not disclose the existence of another owner's confirmation.
		return ErrNotFound
	}
	if value.Binding.OperationDomain == "cloud_worker.execute" || value.Binding.OperationDomain == "execution_v2.run" || value.Binding.OperationDomain == "extension.execute" {
		// Durable execution authorization is account-generation fenced because
		// an owner identifier may be recreated after deprovisioning. A missing
		// owner/generation is stale authority, not permission for the new account.
		if storedOwner != authority.OwnerID || boundOwner != authority.OwnerID ||
			value.Binding.AccountGeneration != authority.AccountGeneration {
			return ErrStale
		}
	}
	return nil
}

func NewService(repository Repository, now ...func() time.Time) (*Service, error) {
	if repository == nil {
		return nil, ErrInvalid
	}
	clock := time.Now
	if len(now) > 0 && now[0] != nil {
		clock = now[0]
	}
	service := &Service{repository: repository, now: clock}
	if reader, ok := repository.(TargetBindingReader); ok {
		service.bindingReader = reader
	}
	if reader, ok := repository.(CurrentTargetBindingReader); ok {
		service.currentReader = reader
	}
	return service, nil
}

func (s *Service) Request(ctx context.Context, command RequestCommand) (Confirmation, error) {
	if s == nil || !validateUUID(command.IdempotencyKey) {
		return Confirmation{}, ErrInvalid
	}
	binding, err := command.Binding.normalized()
	if err != nil || !validateUUID(command.TaskID) || command.ExpiresAt.IsZero() || command.ExpiresAt.Location() != time.UTC {
		return Confirmation{}, ErrInvalid
	}
	now := command.At
	if now.IsZero() {
		now = s.now().UTC()
	}
	if now.Location() != time.UTC || !command.ExpiresAt.After(now) {
		return Confirmation{}, ErrInvalid
	}
	command.Binding = binding
	command.TaskID = strings.TrimSpace(command.TaskID)
	command.At = now
	command.RequestDigest = requestDigest(command)
	return s.repository.Request(ctx, command)
}

func (s *Service) Get(ctx context.Context, id string) (Confirmation, error) {
	if s == nil || !validateUUID(id) {
		return Confirmation{}, ErrInvalid
	}
	return s.repository.Get(ctx, strings.TrimSpace(id))
}

// GetAuthorized resolves the immutable confirmation before applying the
// signed owner/account-generation fence. Public Capability adapters must use
// this method instead of authorizing by caller-supplied UUID alone.
func (s *Service) GetAuthorized(ctx context.Context, authority Authority, id string) (Confirmation, error) {
	value, err := s.Get(ctx, id)
	if err != nil {
		return Confirmation{}, err
	}
	if err := authorizeConfirmation(value, authority); err != nil {
		return Confirmation{}, err
	}
	return value, nil
}

func (s *Service) List(ctx context.Context, query ListQuery) (Page, error) {
	if s == nil || query.PageSize < 0 || query.PageSize > 100 {
		return Page{}, ErrInvalid
	}
	return s.repository.List(ctx, query)
}

// ListAuthorized removes foreign-owner and stale-generation records before
// they cross the public Capability boundary. The repository cursor remains
// opaque; callers may receive a short page and continue with NextPageToken.
func (s *Service) ListAuthorized(ctx context.Context, authority Authority, query ListQuery) (Page, error) {
	if _, err := authority.normalize(); err != nil {
		return Page{}, err
	}
	page, err := s.List(ctx, query)
	if err != nil {
		return Page{}, err
	}
	filtered := make([]Confirmation, 0, len(page.Confirmations))
	for _, value := range page.Confirmations {
		if authorizeConfirmation(value, authority) == nil {
			filtered = append(filtered, value)
		}
	}
	page.Confirmations = filtered
	return page, nil
}

func (s *Service) Confirm(ctx context.Context, command ConfirmCommand) (Confirmation, error) {
	if s == nil || !validateUUID(command.IdempotencyKey) || !validateUUID(command.ConfirmationID) || command.ExpectedRevision < 1 {
		return Confirmation{}, ErrInvalid
	}
	if s.bindingReader == nil && s.currentReader == nil {
		return Confirmation{}, ErrBindingUnavailable
	}
	if _, sameMemory := s.repository.(*MemoryRepository); !sameMemory && s.currentReader == nil {
		command.ResolveBinding = func(_ context.Context) (Binding, error) {
			return s.bindingReader.ReadTargetBinding(ctx, command.ConfirmationID)
		}
	}
	if command.At.IsZero() {
		command.At = s.now().UTC()
	}
	command.RequestDigest = confirmDigest(command)
	return s.repository.Confirm(ctx, command)
}

// ConfirmAuthorized performs the authority check before the repository is
// allowed to execute the idempotent confirmation mutation.
func (s *Service) ConfirmAuthorized(ctx context.Context, authority Authority, command ConfirmCommand) (Confirmation, error) {
	current, err := s.GetAuthorized(ctx, authority, command.ConfirmationID)
	if err != nil {
		return Confirmation{}, err
	}
	// Memory/test repositories validate an explicitly supplied immutable
	// binding; PostgreSQL independently resolves the current target binding in
	// the confirmation transaction. Supplying the authorized stored binding is
	// safe for both and never trusts a caller-provided snapshot.
	command.Binding = current.Binding
	return s.Confirm(ctx, command)
}

func (s *Service) Reject(ctx context.Context, command RejectCommand) (Confirmation, error) {
	if s == nil || !validateUUID(command.IdempotencyKey) || !validateUUID(command.ConfirmationID) || command.ExpectedRevision < 1 {
		return Confirmation{}, ErrInvalid
	}
	command.Reason = strings.TrimSpace(command.Reason)
	command.Note = strings.TrimSpace(command.Note)
	if len(command.Reason) > 256 || len(command.Note) > 256 || strings.ContainsAny(command.Reason+command.Note, "\r\n") {
		return Confirmation{}, ErrInvalid
	}
	if command.At.IsZero() {
		command.At = s.now().UTC()
	}
	command.RequestDigest = rejectDigest(command)
	return s.repository.Reject(ctx, command)
}

// RejectAuthorized performs the authority check before the repository is
// allowed to execute the rejection mutation.
func (s *Service) RejectAuthorized(ctx context.Context, authority Authority, command RejectCommand) (Confirmation, error) {
	if _, err := s.GetAuthorized(ctx, authority, command.ConfirmationID); err != nil {
		return Confirmation{}, err
	}
	return s.Reject(ctx, command)
}

func (s *Service) Consume(ctx context.Context, command ConsumeCommand) (Confirmation, error) {
	if s == nil || !validateUUID(command.IdempotencyKey) || !validateUUID(command.ConfirmationID) || !validateUUID(command.TaskID) || command.Attempt == 0 || command.LeaseEpoch == 0 || command.ExpectedRevision < 1 || command.ExpectedTaskRevision < 1 {
		return Confirmation{}, ErrInvalid
	}
	if s.bindingReader == nil && s.currentReader == nil {
		return Confirmation{}, ErrBindingUnavailable
	}
	if _, sameMemory := s.repository.(*MemoryRepository); !sameMemory && s.currentReader == nil {
		command.ResolveBinding = func(_ context.Context) (Binding, error) {
			return s.bindingReader.ReadTargetBinding(ctx, command.ConfirmationID)
		}
	}
	if command.At.IsZero() {
		command.At = s.now().UTC()
	}
	command.RequestDigest = consumeDigest(command)
	return s.repository.Consume(ctx, command)
}

func (s *Service) Expire(ctx context.Context, command ExpireCommand) (Confirmation, error) {
	if s == nil || !validateUUID(command.IdempotencyKey) || !validateUUID(command.ConfirmationID) || command.ExpectedRevision < 1 {
		return Confirmation{}, ErrInvalid
	}
	command.Reason = strings.TrimSpace(command.Reason)
	if command.Reason != ReasonExpired && command.Reason != ReasonStale {
		return Confirmation{}, ErrInvalid
	}
	if command.At.IsZero() {
		command.At = s.now().UTC()
	}
	command.RequestDigest = expireDigest(command)
	return s.repository.Expire(ctx, command)
}

func (s *Service) ReleaseReservation(ctx context.Context, command ReleaseReservationCommand) (Confirmation, error) {
	if s == nil || !validateUUID(command.IdempotencyKey) || !validateUUID(command.ConfirmationID) || !validateUUID(command.TaskID) || command.AcquiredAttempt == 0 || command.AcquiredLeaseEpoch == 0 || command.TerminalAttempt == 0 || command.TerminalLeaseEpoch == 0 || command.ExpectedTaskRevision < 1 {
		return Confirmation{}, ErrInvalid
	}
	command.RequestDigest = releaseDigest(command)
	return s.repository.ReleaseReservation(ctx, command)
}

// AcknowledgeExtensionExecutionUncertain is an explicit reconciliation
// acknowledgement. It never retries or dispatches the uncertain operation.
func (s *Service) AcknowledgeExtensionExecutionUncertain(ctx context.Context, command AcknowledgeExtensionExecutionUncertainCommand) (AcknowledgeExtensionExecutionUncertainResult, error) {
	command.OwnerID = strings.TrimSpace(command.OwnerID)
	if s == nil || command.OwnerID == "" || command.AccountGeneration == 0 || !validateUUID(command.IdempotencyKey) || !validateUUID(command.ConfirmationID) || !validateUUID(command.TaskID) || !validateUUID(command.InstallationID) || command.ExpectedTaskRevision < 1 || command.ExpectedConfirmationRevision < 1 || command.Resolution != ExtensionUncertainAcknowledgedUnknownNoRetry {
		return AcknowledgeExtensionExecutionUncertainResult{}, ErrInvalid
	}
	ack, ok := s.repository.(ExtensionUncertainAcknowledger)
	if !ok {
		return AcknowledgeExtensionExecutionUncertainResult{}, ErrBindingUnavailable
	}
	return ack.AcknowledgeExtensionExecutionUncertain(ctx, command)
}

// TerminalizeTask is a preparation seam for the generic task terminal writer.
// Wiring belongs to the ledger owner: this service deliberately does not race
// it by writing task rows itself.
func (s *Service) TerminalizeTask(ctx context.Context, command TaskTerminalCommand) error {
	if s == nil || !validateUUID(command.TaskID) || (command.Reason != "canceled" && command.Reason != "timed_out") {
		return ErrInvalid
	}
	terminalizer, ok := s.repository.(TaskTerminalizer)
	if !ok {
		return ErrBindingUnavailable
	}
	if command.At.IsZero() {
		command.At = s.now().UTC()
	}
	return terminalizer.TerminalizeTask(ctx, command)
}
