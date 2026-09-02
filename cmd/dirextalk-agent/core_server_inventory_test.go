package main

import (
	"context"
	"errors"
	"testing"

	"github.com/YingSuiAI/dirextalk-agent/internal/cloudworker/localartifact"
	"github.com/YingSuiAI/dirextalk-agent/internal/coreserver"
	"github.com/google/uuid"
)

func TestServerArtifactCleanupAcceptsAlreadyDeletedBodyWithNewOperationKey(t *testing.T) {
	for _, kind := range []string{"cloud_worker_artifact", "local_sandbox_artifact"} {
		t.Run(kind, func(t *testing.T) {
			repository, err := localartifact.NewRepository(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			authority := localartifact.Authority{OwnerID: "owner", AccountGeneration: 7}
			executionID := uuid.NewString()
			bind, list := repository.Bind, repository.List
			if kind == "local_sandbox_artifact" {
				bind, list = repository.BindLocalSandbox, repository.ListLocalSandbox
			}
			sink, err := bind(authority, executionID)
			if err != nil {
				t.Fatal(err)
			}
			if err := sink.StoreText(context.Background(), []byte("result"), nil, 0); err != nil {
				t.Fatal(err)
			}
			artifacts, _, err := list(context.Background(), authority, executionID, "", 10)
			if err != nil || len(artifacts) != 1 {
				t.Fatalf("artifacts=%+v err=%v", artifacts, err)
			}
			deleter := coreServerArtifactDeleter{artifacts: repository}
			serverAuthority := coreserver.Authority{OwnerID: authority.OwnerID, AccountGeneration: authority.AccountGeneration}
			artifact := coreserver.Artifact{SourceKind: kind, SourceID: artifacts[0].ArtifactID}
			for i := 0; i < 2; i++ {
				if err := deleter.DeleteArtifact(context.Background(), serverAuthority, artifact, uuid.NewString()); err != nil {
					t.Fatalf("operation %d: %v", i, err)
				}
			}
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			if err := deleter.DeleteArtifact(ctx, serverAuthority, artifact, uuid.NewString()); !errors.Is(err, localartifact.ErrInvalid) {
				t.Fatalf("infrastructure/input error was hidden: %v", err)
			}
		})
	}
}
