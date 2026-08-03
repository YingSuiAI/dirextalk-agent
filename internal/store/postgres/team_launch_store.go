package postgres

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/teamlaunch"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

func persistTeamLaunchAuthorization(
	ctx context.Context,
	tx pgx.Tx,
	instanceID uuid.UUID,
	plan TeamPlanRecord,
	authorization teamlaunch.AuthorizationV1,
	now time.Time,
) (string, error) {
	if ctx == nil ||
		tx == nil ||
		instanceID == uuid.Nil ||
		authorization.ValidateAt(now) != nil ||
		authorization.ValidateAgainst(plan.Plan) != nil ||
		authorization.AgentInstanceID != instanceID.String() ||
		authorization.OwnerID != plan.Plan.OwnerID ||
		authorization.PlanID != plan.Plan.PlanID ||
		authorization.PlanRevision != plan.Plan.Revision ||
		authorization.PlanDigest != plan.PlanDigest {
		return "", ErrTeamFactInvalid
	}
	digest, err := authorization.Digest()
	if err != nil {
		return "", ErrTeamFactInvalid
	}
	encoded, err := json.Marshal(authorization)
	if err != nil {
		return "", ErrTeamFactInvalid
	}
	cbor, err := authorization.CanonicalCBOR()
	if err != nil {
		return "", ErrTeamFactInvalid
	}
	authorizationID, _ := uuid.Parse(authorization.AuthorizationID)
	approvalID, _ := uuid.Parse(authorization.ApprovalID)
	planID, _ := uuid.Parse(authorization.PlanID)
	if _, err := tx.Exec(ctx, `
		INSERT INTO team_launch_authorizations
		    (authorization_id, approval_id, agent_instance_id, owner_id,
		     plan_id, plan_revision, plan_digest,
		     provider, connection_id, connection_revision, account_id, region,
		     authorization_digest, authorization_json, authorization_cbor,
		     launch_not_before, launch_not_after)
		VALUES (
		    $1,$2,$3,$4,$5,$6,$7,
		    $8,$9,$10,$11,$12,
		    $13,$14,$15,$16,$17
		)`,
		authorizationID,
		approvalID,
		instanceID,
		authorization.OwnerID,
		planID,
		int64(authorization.PlanRevision),
		authorization.PlanDigest,
		string(authorization.ProviderScope.Provider),
		authorization.ProviderScope.ConnectionID,
		int64(authorization.ProviderScope.ConnectionRevision),
		authorization.ProviderScope.AccountID,
		authorization.Region,
		digest,
		encoded,
		cbor,
		authorization.LaunchNotBefore.UTC(),
		authorization.LaunchNotAfter.UTC(),
	); err != nil {
		return "", fmt.Errorf("insert Team launch authorization: %w", err)
	}
	return digest, nil
}

func readTeamLaunchAuthorization(
	ctx context.Context,
	query teamApprovalQuerier,
	instanceID uuid.UUID,
	authorizationID uuid.UUID,
	expectedDigest string,
) (teamlaunch.AuthorizationV1, error) {
	if ctx == nil ||
		query == nil ||
		instanceID == uuid.Nil ||
		authorizationID == uuid.Nil ||
		!teamDigestPattern.MatchString(expectedDigest) {
		return teamlaunch.AuthorizationV1{}, ErrTeamFactInvalid
	}
	var (
		approvalID, storedAgentID, planID, connectionID  uuid.UUID
		ownerID, planDigest, provider, accountID, region string
		storedDigest                                     string
		encoded, storedCBOR                              []byte
		planRevision, connectionRevision                 int64
		launchNotBefore, launchNotAfter                  time.Time
		authorization                                    teamlaunch.AuthorizationV1
	)
	if err := query.QueryRow(ctx, `
		SELECT approval_id, agent_instance_id, owner_id,
		       plan_id, plan_revision, plan_digest,
		       provider, connection_id, connection_revision, account_id, region,
		       authorization_digest, authorization_json, authorization_cbor,
		       launch_not_before, launch_not_after
		FROM team_launch_authorizations
		WHERE authorization_id=$1 AND agent_instance_id=$2`,
		authorizationID,
		instanceID,
	).Scan(
		&approvalID,
		&storedAgentID,
		&ownerID,
		&planID,
		&planRevision,
		&planDigest,
		&provider,
		&connectionID,
		&connectionRevision,
		&accountID,
		&region,
		&storedDigest,
		&encoded,
		&storedCBOR,
		&launchNotBefore,
		&launchNotAfter,
	); err != nil {
		if err == pgx.ErrNoRows {
			return teamlaunch.AuthorizationV1{}, ErrTeamFactNotFound
		}
		return teamlaunch.AuthorizationV1{}, fmt.Errorf(
			"read Team launch authorization: %w",
			err,
		)
	}
	if planRevision <= 0 ||
		connectionRevision <= 0 ||
		json.Unmarshal(encoded, &authorization) != nil ||
		authorization.Validate() != nil {
		return teamlaunch.AuthorizationV1{}, ErrTeamFactCorrupt
	}
	actualDigest, err := authorization.Digest()
	if err != nil {
		return teamlaunch.AuthorizationV1{}, ErrTeamFactCorrupt
	}
	actualCBOR, err := authorization.CanonicalCBOR()
	if err != nil ||
		!bytes.Equal(actualCBOR, storedCBOR) ||
		storedAgentID != instanceID ||
		authorization.AuthorizationID != authorizationID.String() ||
		authorization.ApprovalID != approvalID.String() ||
		authorization.AgentInstanceID != instanceID.String() ||
		authorization.OwnerID != ownerID ||
		authorization.PlanID != planID.String() ||
		authorization.PlanRevision != uint64(planRevision) ||
		authorization.PlanDigest != planDigest ||
		string(authorization.ProviderScope.Provider) != provider ||
		authorization.ProviderScope.ConnectionID != connectionID.String() ||
		authorization.ProviderScope.ConnectionRevision !=
			uint64(connectionRevision) ||
		authorization.ProviderScope.AccountID != accountID ||
		authorization.Region != region ||
		storedDigest != expectedDigest ||
		actualDigest != expectedDigest ||
		!authorization.LaunchNotBefore.Equal(launchNotBefore.UTC()) ||
		!authorization.LaunchNotAfter.Equal(launchNotAfter.UTC()) {
		return teamlaunch.AuthorizationV1{}, ErrTeamFactCorrupt
	}
	return authorization, nil
}
