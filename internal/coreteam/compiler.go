package coreteam

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"
)

type RuntimeCatalog interface {
	ResolveRuntime(context.Context, string) (RuntimeBinding, error)
}

type QuoteProvider interface {
	Quote(context.Context, QuoteRequest) (QuoteBinding, error)
}

type IDGenerator func() (string, error)
type CompilerOption func(*Compiler)

type Compiler struct {
	catalog RuntimeCatalog
	quotes  QuoteProvider
	now     func() time.Time
	newID   IDGenerator
}

func NewCompiler(catalog RuntimeCatalog, quotes QuoteProvider, options ...CompilerOption) *Compiler {
	compiler := &Compiler{
		catalog: catalog,
		quotes:  quotes,
		now:     time.Now,
		newID:   func() (string, error) { return uuid.NewString(), nil },
	}
	for _, option := range options {
		if option != nil {
			option(compiler)
		}
	}
	return compiler
}

func WithClock(now func() time.Time) CompilerOption {
	return func(compiler *Compiler) { compiler.now = now }
}

func WithIDGenerator(generator IDGenerator) CompilerOption {
	return func(compiler *Compiler) { compiler.newID = generator }
}

func (c *Compiler) Compile(ctx context.Context, command CompileCommand) (Plan, error) {
	if ctx == nil || c == nil || c.catalog == nil || c.quotes == nil || c.now == nil || c.newID == nil {
		return Plan{}, ErrInvalid
	}
	if err := ctx.Err(); err != nil {
		return Plan{}, err
	}
	if err := validateCompileCommand(command); err != nil {
		return Plan{}, err
	}
	runtimeID := command.RuntimeID
	if runtimeID == "" {
		runtimeID = OfficialRuntimeID
	}
	runtime, err := c.catalog.ResolveRuntime(ctx, runtimeID)
	if err != nil || validateRuntime(runtime, runtimeID) != nil {
		if contextErr := ctx.Err(); contextErr != nil {
			return Plan{}, contextErr
		}
		return Plan{}, ErrRuntimeUnavailable
	}
	if err := ctx.Err(); err != nil {
		return Plan{}, err
	}
	quote, err := c.quotes.Quote(ctx, QuoteRequest{
		RuntimeID: runtimeID, Region: OsakaRegion, InstanceType: MVPInstanceType, RoleCount: uint32(len(command.Roles)),
	})
	if err != nil || validateQuote(quote) != nil || !quote.ExpiresAt.After(c.now().UTC()) {
		if contextErr := ctx.Err(); contextErr != nil {
			return Plan{}, contextErr
		}
		return Plan{}, ErrQuoteUnavailable
	}
	if err := ctx.Err(); err != nil {
		return Plan{}, err
	}
	ids := make([]string, 3)
	seenIDs := make(map[string]struct{}, len(ids))
	for i := range ids {
		ids[i], err = c.newID()
		if err != nil || !validUUID(ids[i]) {
			return Plan{}, ErrIdentityUnavailable
		}
		if _, duplicate := seenIDs[ids[i]]; duplicate {
			return Plan{}, ErrIdentityUnavailable
		}
		seenIDs[ids[i]] = struct{}{}
	}
	roles := make([]Role, len(command.Roles))
	for i, proposal := range command.Roles {
		roles[i] = Role{
			RoleID: proposal.RoleID, Goal: strings.TrimSpace(proposal.Goal),
			DependsOn:    append([]string(nil), proposal.DependsOn...),
			Capabilities: append([]Capability(nil), proposal.Capabilities...),
		}
	}
	plan := Plan{
		PlanID: ids[0], OwnerID: command.OwnerID, AccountGeneration: command.AccountGeneration,
		TaskID: ids[1], ConversationID: command.ConversationID, CredentialID: command.CredentialID,
		ConfirmationID: ids[2], Revision: 1, CredentialRevision: command.CredentialRevision,
		Goal: strings.TrimSpace(command.Goal), Runtime: runtime, Quote: normalizedQuote(quote),
		Roles: canonicalRoles(roles), Status: PlanWaitingUser,
	}
	plan.Digest, err = plan.SemanticDigest()
	if err != nil || plan.Validate() != nil {
		return Plan{}, ErrInvalid
	}
	return plan, nil
}

func IsTerminal(status ExecutionStatus) bool {
	switch status {
	case ExecutionCompleted, ExecutionFailed, ExecutionCanceled, ExecutionTimedOut:
		return true
	case ExecutionQueued, ExecutionRunning, ExecutionCleaningUp:
		return false
	default:
		return false
	}
}

func validateExecutionStatus(status ExecutionStatus) error {
	switch status {
	case ExecutionQueued, ExecutionRunning, ExecutionCleaningUp, ExecutionCompleted, ExecutionFailed, ExecutionCanceled, ExecutionTimedOut:
		return nil
	default:
		return errors.Join(ErrInvalid, errors.New("invalid execution status"))
	}
}
