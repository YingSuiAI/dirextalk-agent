package rpcapi

import (
	"math"
	"slices"

	agentv1 "github.com/YingSuiAI/dirextalk-agent/api/gen/dirextalk/agent/v1"
	"github.com/YingSuiAI/dirextalk-agent/internal/teamartifact"
	"github.com/YingSuiAI/dirextalk-agent/internal/teamexecution"
	"github.com/YingSuiAI/dirextalk-agent/internal/teamplan"
	"github.com/YingSuiAI/dirextalk-agent/internal/teamreport"
	"github.com/YingSuiAI/dirextalk-agent/internal/workerruntime"
)

func teamExecutionToProto(
	fact teamexecution.Fact,
	report *teamreport.Fact,
	artifacts []teamartifact.ArtifactV1,
) (*agentv1.TeamExecutionV3, error) {
	digest, err := fact.Execution.Digest()
	if err != nil ||
		digest != fact.ExecutionDigest ||
		fact.RecordRevision == 0 ||
		fact.RecordRevision > math.MaxInt64 ||
		fact.Execution.PlanRevision > math.MaxInt64 ||
		fact.CreatedAt.IsZero() ||
		fact.UpdatedAt.IsZero() ||
		fact.UpdatedAt.Before(fact.CreatedAt) {
		return nil, teamexecution.ErrFactMismatch
	}
	status, err := teamExecutionStatusToProto(fact.Status)
	if err != nil {
		return nil, err
	}
	createdAt, err := checkedTeamTimestamp(fact.CreatedAt)
	if err != nil {
		return nil, err
	}
	updatedAt, err := checkedTeamTimestamp(fact.UpdatedAt)
	if err != nil {
		return nil, err
	}
	var projectedReport *agentv1.TeamExecutionReportV3
	projectedArtifacts := make(
		[]*agentv1.TeamExecutionArtifactV3,
		0,
		len(artifacts),
	)
	if report != nil {
		if fact.Status != teamexecution.StatusCompleted ||
			report.Report.ExecutionID !=
				fact.Execution.ExecutionID ||
			report.Report.OwnerID != fact.Execution.OwnerID ||
			report.Report.TaskID != fact.Execution.TaskID ||
			report.Report.PlanID != fact.Execution.PlanID ||
			report.Report.PlanRevision !=
				fact.Execution.PlanRevision ||
			report.Report.PlanDigest != fact.Execution.PlanDigest {
			return nil, teamexecution.ErrFactMismatch
		}
		projectedReport, err = teamExecutionReportToProto(*report)
		if err != nil {
			return nil, err
		}
		if len(artifacts) == 0 {
			return nil, teamexecution.ErrFactMismatch
		}
		for _, artifact := range artifacts {
			projected, projectErr := teamExecutionArtifactToProto(
				artifact,
				fact,
			)
			if projectErr != nil {
				return nil, projectErr
			}
			projectedArtifacts = append(projectedArtifacts, projected)
		}
	} else if fact.Status == teamexecution.StatusCompleted {
		return nil, teamexecution.ErrFactMismatch
	} else if len(artifacts) != 0 {
		return nil, teamexecution.ErrFactMismatch
	}
	inputSnapshot, err := teamInputSnapshotToProto(
		fact.Execution.InputSnapshot,
	)
	if err != nil {
		return nil, err
	}
	taskInput, err := teamTaskInputToProto(fact.Execution.TaskInput)
	if err != nil {
		return nil, err
	}
	return &agentv1.TeamExecutionV3{
		SchemaVersion:        fact.Execution.SchemaVersion,
		ExecutionId:          fact.Execution.ExecutionID,
		OwnerId:              fact.Execution.OwnerID,
		TaskId:               fact.Execution.TaskID,
		PlanId:               fact.Execution.PlanID,
		PlanRevision:         int64(fact.Execution.PlanRevision),
		PlanDigest:           fact.Execution.PlanDigest,
		InputSnapshot:        inputSnapshot,
		TaskInput:            taskInput,
		Status:               status,
		WorkerCount:          fact.Execution.WorkerCount,
		MaxConcurrentWorkers: fact.Execution.MaxConcurrentWorkers,
		RecordRevision:       int64(fact.RecordRevision),
		CreatedAt:            createdAt,
		UpdatedAt:            updatedAt,
		Report:               projectedReport,
		Artifacts:            projectedArtifacts,
	}, nil
}

func teamExecutionArtifactToProto(
	artifact teamartifact.ArtifactV1,
	execution teamexecution.Fact,
) (*agentv1.TeamExecutionArtifactV3, error) {
	if artifact.Validate() != nil ||
		artifact.OwnerID != execution.Execution.OwnerID ||
		artifact.ExecutionID != execution.Execution.ExecutionID ||
		artifact.TaskID != execution.Execution.TaskID ||
		artifact.PlanID != execution.Execution.PlanID ||
		artifact.PlanRevision != execution.Execution.PlanRevision {
		return nil, teamexecution.ErrFactMismatch
	}
	createdAt, err := checkedTeamTimestamp(artifact.CreatedAt)
	if err != nil {
		return nil, err
	}
	expiresAt, err := checkedTeamTimestamp(artifact.RetentionExpires)
	if err != nil {
		return nil, err
	}
	return &agentv1.TeamExecutionArtifactV3{
		SchemaVersion:      artifact.SchemaVersion,
		ArtifactId:         artifact.ArtifactID,
		RoleId:             artifact.RoleID,
		ActionId:           artifact.ActionID,
		Name:               artifact.Name,
		Kind:               string(artifact.Kind),
		MediaType:          artifact.MediaType,
		SizeBytes:          artifact.SizeBytes,
		Sha256:             artifact.SHA256,
		Verification:       string(artifact.Verification),
		CreatedAt:          createdAt,
		RetentionExpiresAt: expiresAt,
	}, nil
}

func teamExecutionReportToProto(
	fact teamreport.Fact,
) (*agentv1.TeamExecutionReportV3, error) {
	if fact.Validate() != nil ||
		fact.Report.PlanRevision > math.MaxInt64 {
		return nil, teamexecution.ErrFactMismatch
	}
	generatedAt, err := checkedTeamTimestamp(fact.GeneratedAt)
	if err != nil {
		return nil, err
	}
	roles := make(
		[]*agentv1.TeamExecutionRoleReportV3,
		0,
		len(fact.Report.Roles),
	)
	for _, role := range fact.Report.Roles {
		family, mapErr := teamRuntimeFamilyToProto(
			role.RuntimeFamily,
		)
		if mapErr != nil {
			return nil, mapErr
		}
		adapter, mapErr := teamRuntimeAdapterToProto(
			teamplan.RuntimeAdapter(role.RuntimeAdapter),
		)
		if mapErr != nil {
			return nil, mapErr
		}
		finals := make(
			[]*agentv1.TeamExecutionFinalV3,
			0,
			len(role.Finals),
		)
		for _, final := range role.Finals {
			finalAdapter, finalErr := teamRuntimeAdapterToProto(
				teamplan.RuntimeAdapter(final.Adapter),
			)
			if finalErr != nil {
				return nil, finalErr
			}
			finals = append(finals, &agentv1.TeamExecutionFinalV3{
				ActionId:       final.ActionID,
				RuntimeAdapter: finalAdapter,
				Usage:          teamRuntimeUsageToProto(final.Usage),
				Status:         final.Status,
				Summary:        final.Summary,
				Deliverables:   slices.Clone(final.Deliverables),
				Tests:          slices.Clone(final.Tests),
				Risks:          slices.Clone(final.Risks),
				ArtifactSha256: final.ArtifactSHA256,
			})
		}
		roles = append(roles, &agentv1.TeamExecutionRoleReportV3{
			RoleId:               role.RoleID,
			Title:                role.Title,
			RuntimeFamily:        family,
			RuntimeAdapter:       adapter,
			Outcome:              string(role.Outcome),
			ResultEvidenceDigest: role.ResultEvidenceDigest,
			Finals:               finals,
		})
	}
	return &agentv1.TeamExecutionReportV3{
		SchemaVersion: fact.Report.SchemaVersion,
		ExecutionId:   fact.Report.ExecutionID,
		OwnerId:       fact.Report.OwnerID,
		TaskId:        fact.Report.TaskID,
		PlanId:        fact.Report.PlanID,
		PlanRevision:  int64(fact.Report.PlanRevision),
		PlanDigest:    fact.Report.PlanDigest,
		Roles:         roles,
		TotalUsage:    teamRuntimeUsageToProto(fact.Report.TotalUsage),
		ReportDigest:  fact.ReportDigest,
		GeneratedAt:   generatedAt,
	}, nil
}

func teamRuntimeUsageToProto(
	usage workerruntime.Usage,
) *agentv1.TeamRuntimeUsageV3 {
	return &agentv1.TeamRuntimeUsageV3{
		InputTokens:           usage.InputTokens,
		CachedInputTokens:     usage.CachedInputTokens,
		OutputTokens:          usage.OutputTokens,
		ReasoningOutputTokens: usage.ReasoningOutputTokens,
	}
}

func teamExecutionStatusToProto(
	value teamexecution.Status,
) (agentv1.TeamExecutionStatusV3, error) {
	switch value {
	case teamexecution.StatusMaterialized:
		return agentv1.TeamExecutionStatusV3_TEAM_EXECUTION_STATUS_V3_MATERIALIZED, nil
	case teamexecution.StatusDispatching:
		return agentv1.TeamExecutionStatusV3_TEAM_EXECUTION_STATUS_V3_DISPATCHING, nil
	case teamexecution.StatusRunning:
		return agentv1.TeamExecutionStatusV3_TEAM_EXECUTION_STATUS_V3_RUNNING, nil
	case teamexecution.StatusVerifying:
		return agentv1.TeamExecutionStatusV3_TEAM_EXECUTION_STATUS_V3_VERIFYING, nil
	case teamexecution.StatusCompleted:
		return agentv1.TeamExecutionStatusV3_TEAM_EXECUTION_STATUS_V3_COMPLETED, nil
	case teamexecution.StatusFailed:
		return agentv1.TeamExecutionStatusV3_TEAM_EXECUTION_STATUS_V3_FAILED, nil
	case teamexecution.StatusCanceled:
		return agentv1.TeamExecutionStatusV3_TEAM_EXECUTION_STATUS_V3_CANCELED, nil
	default:
		return agentv1.TeamExecutionStatusV3_TEAM_EXECUTION_STATUS_V3_UNSPECIFIED,
			teamexecution.ErrFactMismatch
	}
}
