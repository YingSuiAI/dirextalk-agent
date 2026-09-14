package main

import (
	"context"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/cloudworker/sshflow"
	"github.com/YingSuiAI/dirextalk-agent/internal/coreconversation"
)

// groupAuthorizationPoll is the revalidation cadence while a group-approved
// Worker runs. Tests may shorten it; zero falls back to the production value so
// executor literals stay valid.
const defaultGroupAuthorizationPoll = 2 * time.Second

func (executor *sshWorkerExecutor) groupAuthorizationInterval() time.Duration {
	if executor.groupAuthorizationPoll > 0 {
		return executor.groupAuthorizationPoll
	}
	return defaultGroupAuthorizationPoll
}

// The persisted turn, not the request's context or its human-written goal,
// determines whether execution originated in a group. It is checked again
// after the private owner has approved the quote and before any remote start.
func (executor *sshWorkerExecutor) groupWorkerOrigin(ctx context.Context, request sshflow.Request) (*coreconversation.GroupOrigin, error) {
	if executor.groupTurnReader == nil {
		return nil, coreconversation.ErrGroupAuthorization
	}
	turn, err := executor.groupTurnReader.GetTurn(ctx, request.TurnID)
	if err != nil {
		return nil, err
	}
	if turn.GroupOrigin == nil {
		return nil, nil
	}
	if executor.groupAuthorization == nil || request.OwnerID != turn.OwnerID || request.AccountGeneration != turn.AccountGeneration ||
		request.GitHubBinding != nil || request.ReuseOnly || request.ReuseWorkerID != "" || len(request.InputManifest.Items) != 0 || request.ModelSnapshot.SystemPrompt != "" {
		return nil, coreconversation.ErrGroupAuthorization
	}
	if err := executor.groupAuthorization.ValidateGroupOrigin(ctx, *turn.GroupOrigin); err != nil {
		return nil, err
	}
	origin := *turn.GroupOrigin
	return &origin, nil
}

// workerExecutionScope is the authorization a paid Worker run executes under:
// the caller's context, the group origin the durable turn proved (nil for the
// owner's own work), and the revocation watch to stop.
type workerExecutionScope struct {
	ctx    context.Context
	origin *coreconversation.GroupOrigin
	stop   func()
}

// authorizedWorkerScope scopes a paid Worker run to the origin the durable turn
// already proved, and watches that origin for revocation while the run is live.
// The approved quote was priced and bound from the group's own AWS credential,
// so a run that lost this scope would resolve the owner's personal credential
// instead, fail the credential revision fence and refuse to spend. Private
// turns keep the caller's context untouched and get a no-op stop.
func (executor *sshWorkerExecutor) authorizedWorkerScope(ctx context.Context, request sshflow.Request) (workerExecutionScope, error) {
	noop := func() {}
	origin, err := executor.groupWorkerOrigin(ctx, request)
	if err != nil {
		return workerExecutionScope{ctx: ctx, stop: noop}, err
	}
	if origin == nil {
		return workerExecutionScope{ctx: ctx, stop: noop}, nil
	}
	scoped, stop := executor.watchGroupWorkerAuthorization(coreconversation.WithGroupOrigin(ctx, *origin), *origin)
	return workerExecutionScope{ctx: scoped, origin: origin, stop: stop}, nil
}

func (executor *sshWorkerExecutor) watchGroupWorkerAuthorization(ctx context.Context, origin coreconversation.GroupOrigin) (context.Context, func()) {
	workCtx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() {
		defer close(done)
		ticker := time.NewTicker(executor.groupAuthorizationInterval())
		defer ticker.Stop()
		for {
			select {
			case <-workCtx.Done():
				return
			case <-ticker.C:
				if executor.groupAuthorization.ValidateGroupOrigin(workCtx, origin) != nil {
					// Cancellation asks the executor to stop/safely retain its
					// resources. It does not destroy the owner's paid server.
					cancel()
					return
				}
			}
		}
	}()
	return workCtx, func() { cancel(); <-done }
}
