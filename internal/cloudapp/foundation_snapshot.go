package cloudapp

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/awsfoundation"
	cloudfoundation "github.com/YingSuiAI/dirextalk-agent/internal/cloud/foundation"
	"github.com/YingSuiAI/dirextalk-agent/internal/cloudstatus"
	"github.com/YingSuiAI/dirextalk-agent/internal/secretbootstrap"
	"github.com/aws/aws-sdk-go-v2/aws/arn"
	"github.com/google/uuid"
)

// FoundationSnapshotReader builds the server-authoritative scope signed for
// an independent Foundation lifecycle operation. Worker Plans, quotes, and
// release-operator credential chains never enter this boundary.
type FoundationSnapshotReader struct {
	agentInstanceID string
	templateDigest  string
	reaperImageURI  string
	secrets         SecretBootstrapLifecycle
	identities      AWSIdentityRepository
	connections     cloudstatus.Reader
	teardownGuard   FoundationTeardownGuard
	now             func() time.Time
}

// FoundationTeardownGuard proves that a Connection has no durable resource or
// release facts that would be stranded by removing its Foundation. The
// production implementation performs this check again in the approval
// transaction, where it also fences the Connection against new launches.
type FoundationTeardownGuard interface {
	CheckFoundationTeardown(context.Context, string, string, string, string) error
}

func NewFoundationSnapshotReader(agentInstanceID string, template []byte, reaperImageURI string, secrets SecretBootstrapLifecycle, identities AWSIdentityRepository, connections cloudstatus.Reader, teardownGuard FoundationTeardownGuard, now func() time.Time) (*FoundationSnapshotReader, error) {
	parsed, err := uuid.Parse(strings.TrimSpace(agentInstanceID))
	if err != nil || parsed == uuid.Nil || awsfoundation.ValidateTemplate(template) != nil || strings.TrimSpace(reaperImageURI) == "" || secrets == nil || identities == nil || connections == nil || teardownGuard == nil || now == nil {
		return nil, cloudfoundation.ErrInvalid
	}
	digest := sha256.Sum256(template)
	return &FoundationSnapshotReader{agentInstanceID: parsed.String(), templateDigest: "sha256:" + hex.EncodeToString(digest[:]), reaperImageURI: reaperImageURI,
		secrets: secrets, identities: identities, connections: connections, teardownGuard: teardownGuard, now: now}, nil
}

func (reader *FoundationSnapshotReader) SnapshotFoundation(ctx context.Context, caller cloudfoundation.MutationScope, ownerID string, action cloudfoundation.Action, connectionID, bootstrapSessionID string, expectedBootstrapRevision uint64) (cloudfoundation.Snapshot, error) {
	if reader == nil || ctx == nil || caller.Validate() != nil || strings.TrimSpace(ownerID) == "" || expectedBootstrapRevision == 0 {
		return cloudfoundation.Snapshot{}, cloudfoundation.ErrInvalid
	}
	session, err := reader.secrets.Get(ctx, caller.ClientID, bootstrapSessionID)
	if err != nil {
		return cloudfoundation.Snapshot{}, mapFoundationSnapshotError(err)
	}
	purpose := "aws_foundation_" + string(action)
	if session.AgentInstanceID != reader.agentInstanceID || session.OwnerID != ownerID || session.TargetID != connectionID || session.Purpose != purpose ||
		session.Status != secretbootstrap.StatusUploaded || session.Revision != expectedBootstrapRevision || !reader.now().UTC().Before(session.ExpiresAt) {
		return cloudfoundation.Snapshot{}, cloudfoundation.ErrRevisionConflict
	}
	evidence, err := reader.identities.GetAWSIdentityEvidence(ctx, bootstrapSessionID, expectedBootstrapRevision)
	if err != nil {
		return cloudfoundation.Snapshot{}, mapFoundationSnapshotError(err)
	}
	if evidence.AgentInstanceID != reader.agentInstanceID || evidence.OwnerID != ownerID || evidence.TargetID != connectionID ||
		evidence.BootstrapSessionID != bootstrapSessionID || evidence.SessionRevision != expectedBootstrapRevision ||
		evidence.Identity.AccountID == "" || evidence.Identity.Region == "" || !reader.now().UTC().Before(evidence.ExpiresAt) {
		return cloudfoundation.Snapshot{}, cloudfoundation.ErrApprovalRequired
	}
	principal, err := arn.Parse(evidence.Identity.PrincipalARN)
	if err != nil || principal.Partition == "" || principal.AccountID != evidence.Identity.AccountID {
		return cloudfoundation.Snapshot{}, cloudfoundation.ErrApprovalRequired
	}
	spec, err := awsfoundation.BuildSpec(awsfoundation.SpecInput{AgentInstanceID: reader.agentInstanceID, Partition: principal.Partition, AccountID: evidence.Identity.AccountID, Region: evidence.Identity.Region})
	if err != nil {
		return cloudfoundation.Snapshot{}, cloudfoundation.ErrInvalid
	}
	alias, err := awsfoundation.KMSAliasForAgent(reader.agentInstanceID)
	if err != nil {
		return cloudfoundation.Snapshot{}, cloudfoundation.ErrInvalid
	}
	scope := cloudfoundation.ScopeV1{SchemaVersion: cloudfoundation.ScopeSchemaV1, AgentInstanceID: reader.agentInstanceID, OwnerID: ownerID,
		Action: action, ConnectionID: connectionID, AccountID: evidence.Identity.AccountID, Region: evidence.Identity.Region,
		BootstrapSessionID: bootstrapSessionID, ExpectedBootstrapRevision: expectedBootstrapRevision,
		IdentityObservedAt: evidence.ObservedAt, IdentityExpiresAt: evidence.ExpiresAt,
		FoundationTemplateDigest: reader.templateDigest, ReaperImageURI: reader.reaperImageURI,
		ReleaseEnvironment: cloudfoundation.ReleaseEnvironmentV1{PrivateSubnetCIDR: "10.255.0.0/26", ZeroIngress: true,
			ArtifactBucket: spec.ArtifactBucketName, KMSAlias: alias, BucketVersioned: true, BucketSSEKMS: true}}
	if action != cloudfoundation.ActionEstablish {
		connection, err := reader.connections.GetConnection(ctx, ownerID, connectionID)
		if err != nil {
			return cloudfoundation.Snapshot{}, mapFoundationSnapshotError(err)
		}
		if connection.OwnerID != ownerID || connection.ConnectionID != connectionID || connection.AccountID != scope.AccountID || connection.Region != scope.Region || connection.Revision < 1 || connection.CredentialGeneration < 1 {
			return cloudfoundation.Snapshot{}, cloudfoundation.ErrRevisionConflict
		}
		switch action {
		case cloudfoundation.ActionUpgrade, cloudfoundation.ActionTeardown:
			if connection.Status != "active" && connection.Status != "degraded" && connection.Status != "teardown_blocked" {
				return cloudfoundation.Snapshot{}, cloudfoundation.ErrRevisionConflict
			}
		case cloudfoundation.ActionRemediate:
			if connection.Status != "teardown_blocked" {
				return cloudfoundation.Snapshot{}, cloudfoundation.ErrRevisionConflict
			}
		default:
			return cloudfoundation.Snapshot{}, cloudfoundation.ErrInvalid
		}
		scope.ExpectedConnectionRevision = connection.Revision
		scope.ExpectedCredentialGeneration = uint64(connection.CredentialGeneration)
		if action == cloudfoundation.ActionTeardown || action == cloudfoundation.ActionRemediate {
			if err := reader.teardownGuard.CheckFoundationTeardown(ctx, ownerID, connectionID, scope.AccountID, scope.Region); err != nil {
				return cloudfoundation.Snapshot{}, mapFoundationSnapshotError(err)
			}
		}
	} else if _, err := reader.connections.GetConnection(ctx, ownerID, connectionID); err == nil {
		return cloudfoundation.Snapshot{}, cloudfoundation.ErrRevisionConflict
	} else if !errors.Is(err, cloudstatus.ErrNotFound) {
		return cloudfoundation.Snapshot{}, mapFoundationSnapshotError(err)
	}
	if scope.Validate() != nil {
		return cloudfoundation.Snapshot{}, cloudfoundation.ErrInvalid
	}
	return cloudfoundation.Snapshot{Scope: scope, SessionUploadedAt: evidence.ObservedAt, SessionExpiresAt: session.ExpiresAt}, nil
}

func mapFoundationSnapshotError(err error) error {
	switch {
	case errors.Is(err, cloudfoundation.ErrNotFound):
		return cloudfoundation.ErrNotFound
	case errors.Is(err, cloudfoundation.ErrRevisionConflict):
		return cloudfoundation.ErrRevisionConflict
	case errors.Is(err, cloudfoundation.ErrInvalid):
		return cloudfoundation.ErrInvalid
	case errors.Is(err, ErrNotFound), errors.Is(err, cloudstatus.ErrNotFound), errors.Is(err, secretbootstrap.ErrNotFound):
		return cloudfoundation.ErrNotFound
	case errors.Is(err, ErrRevisionConflict), errors.Is(err, secretbootstrap.ErrRevisionConflict):
		return cloudfoundation.ErrRevisionConflict
	default:
		return cloudfoundation.ErrUnavailable
	}
}
