package cloudapp

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/awsfoundation"
	cloudfoundation "github.com/YingSuiAI/dirextalk-agent/internal/cloud/foundation"
	"github.com/google/uuid"
)

type foundationLifecycleBootstrapperStub struct {
	err error
}

func (stub foundationLifecycleBootstrapperStub) Mutate(context.Context, []byte, awsfoundation.LifecycleRequest) (awsfoundation.LifecycleResult, error) {
	return awsfoundation.LifecycleResult{}, stub.err
}

func TestFoundationTemplateChangeRequiresFreshApproval(t *testing.T) {
	now := time.Date(2026, time.July, 31, 3, 45, 0, 0, time.UTC)
	scope := cloudfoundation.ScopeV1{
		SchemaVersion: cloudfoundation.ScopeSchemaV1, AgentInstanceID: uuid.NewString(),
		OwnerID: "dirextalk-project:demo2.dirextalk.ai", Action: cloudfoundation.ActionUpgrade,
		ConnectionID: uuid.NewString(), ExpectedConnectionRevision: 7,
		AccountID: "123456789012", Region: "ap-northeast-3",
		BootstrapSessionID: uuid.NewString(), ExpectedBootstrapRevision: 2,
		ExpectedCredentialGeneration: 3, IdentityObservedAt: now.Add(-time.Minute),
		IdentityExpiresAt:        now.Add(4 * time.Minute),
		FoundationTemplateDigest: "sha256:" + strings.Repeat("a", 64),
		ReaperImageURI:           "reaper:v0.1.0-alpha.1@sha256:" + strings.Repeat("b", 64),
		ReleaseEnvironment: cloudfoundation.ReleaseEnvironmentV1{
			PrivateSubnetCIDR: "10.255.0.0/26", ZeroIngress: true,
			ArtifactBucket: "dtx-agent-test", KMSAlias: "alias/dtx-agent-test",
			BucketVersioned: true, BucketSSEKMS: true,
		},
	}
	operation := cloudfoundation.OperationV1{
		Caller: cloudfoundation.MutationScope{ClientID: "message-server", CredentialID: uuid.NewString()},
		Challenge: cloudfoundation.ChallengeV1{
			OperationID: uuid.NewString(), ChallengeID: uuid.NewString(), ApprovalID: uuid.NewString(),
			SignerKeyID: "device-key", Scope: scope, ScopeDigest: "sha256:" + strings.Repeat("c", 64),
			IssuedAt: now, ExpiresAt: now.Add(5 * time.Minute), Revision: 1,
		},
		Status: cloudfoundation.StatusRunning,
	}
	mutator, err := NewAWSFoundationLifecycleMutator(foundationLifecycleBootstrapperStub{err: awsfoundation.ErrFoundationTemplateChanged})
	if err != nil {
		t.Fatal(err)
	}
	_, err = mutator.MutateFoundation(context.Background(), []byte("synthetic bootstrap payload"), operation)
	if !errors.Is(err, cloudfoundation.ErrProviderAuthorizationExpired) {
		t.Fatalf("template change error = %v", err)
	}
}
