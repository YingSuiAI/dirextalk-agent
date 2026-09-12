package main

import (
	"context"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/cloudworker/sshflow"
	"github.com/YingSuiAI/dirextalk-agent/internal/coreconversation"
)

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

func (executor *sshWorkerExecutor) watchGroupWorkerAuthorization(ctx context.Context, origin coreconversation.GroupOrigin) (context.Context, func()) {
	workCtx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() {
		defer close(done)
		ticker := time.NewTicker(2 * time.Second)
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
