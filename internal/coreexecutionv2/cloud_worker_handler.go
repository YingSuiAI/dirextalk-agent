package coreexecutionv2

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
)

func (s *Service) handleCloudWorker(ctx context.Context, authority Authority, action string, in map[string]any) (map[string]any, error) {
	if s.cloudWorker == nil {
		return nil, ErrMissingPort
	}
	pageRequest := func() CloudWorkerListRequest {
		return CloudWorkerListRequest{Authority: authority, PageToken: stringParam(in, "page_token"), PageSize: intParam(in, "page_size", 100)}
	}
	switch action {
	case "agent.execution.v2.plans.get":
		planID, _ := idParam(in, "plan_id")
		value, err := s.cloudWorker.GetPlan(ctx, CloudWorkerPlanGetRequest{Authority: authority, PlanID: planID, Revision: uintParam(in, "revision")})
		if err != nil {
			return nil, err
		}
		plan, err := validateCloudWorkerOwnedObject(value, authority, "plan_id", planID)
		if err != nil {
			return nil, err
		}
		if revision := uintParam(in, "revision"); revision > 0 && uintParam(plan, "revision") != revision {
			return nil, fmt.Errorf("%w: Cloud Worker plan revision mismatch", ErrUnsafeOutput)
		}
		return map[string]any{"plan": plan}, nil
	case "agent.execution.v2.plans.list":
		page, err := s.cloudWorker.ListPlans(ctx, pageRequest())
		if err != nil {
			return nil, err
		}
		items, err := validateCloudWorkerPage(page, authority, "plan_id")
		if err != nil {
			return nil, err
		}
		return map[string]any{"plans": items, "next_page_token": page.NextPageToken}, nil
	case "agent.execution.v2.runs.get":
		runID, _ := idParam(in, "run_id")
		value, err := s.cloudWorker.GetRun(ctx, CloudWorkerRunGetRequest{Authority: authority, RunID: runID})
		if err != nil {
			return nil, err
		}
		run, err := validateCloudWorkerOwnedObject(value, authority, "run_id", runID)
		if err != nil {
			return nil, err
		}
		return map[string]any{"run": run}, nil
	case "agent.execution.v2.runs.list":
		if stringParam(in, "project_id") != "" || stringParam(in, "deployment_id") != "" {
			return nil, fmt.Errorf("%w: legacy run filters do not apply to cloud_worker", ErrInvalid)
		}
		page, err := s.cloudWorker.ListRuns(ctx, pageRequest())
		if err != nil {
			return nil, err
		}
		items, err := validateCloudWorkerPage(page, authority, "run_id")
		if err != nil {
			return nil, err
		}
		return map[string]any{"runs": items, "next_page_token": page.NextPageToken}, nil
	case "agent.execution.v2.runs.cancel":
		runID, _ := idParam(in, "run_id")
		value, err := s.cloudWorker.CancelRun(ctx, CloudWorkerRunCancelRequest{
			Authority: authority, RunID: runID, ExpectedRevision: uintParam(in, "expected_revision"), IdempotencyKey: stringParam(in, "idempotency_key"),
		})
		if err != nil {
			return nil, err
		}
		run, err := validateCloudWorkerOwnedObject(value, authority, "run_id", runID)
		if err != nil {
			return nil, err
		}
		if uintParam(run, "revision") <= uintParam(in, "expected_revision") {
			return nil, fmt.Errorf("%w: Cloud Worker cancel did not advance the run revision", ErrUnsafeOutput)
		}
		return map[string]any{"run": run}, nil
	case "agent.execution.v2.runs.events":
		runID, _ := idParam(in, "run_id")
		after := uintParam(in, "after_sequence")
		page, err := s.cloudWorker.RunEvents(ctx, CloudWorkerRunEventsRequest{Authority: authority, RunID: runID, AfterSequence: after, Limit: intParam(in, "limit", 100)})
		if err != nil {
			return nil, err
		}
		events, err := validateCloudWorkerEvents(page, authority, runID, after)
		if err != nil {
			return nil, err
		}
		return map[string]any{"events": events, "next_sequence": page.NextSequence}, nil
	case "agent.execution.v2.artifacts.get":
		artifactID, _ := idParam(in, "artifact_id")
		value, err := s.cloudWorker.GetArtifact(ctx, CloudWorkerArtifactGetRequest{Authority: authority, ArtifactID: artifactID})
		if err != nil {
			return nil, err
		}
		artifact, err := validateCloudWorkerOwnedObject(value, authority, "artifact_id", artifactID)
		if err != nil {
			return nil, fmt.Errorf("%w: Cloud Worker artifact identity mismatch", ErrUnsafeOutput)
		}
		return map[string]any{"artifact": artifact}, nil
	case "agent.execution.v2.artifacts.download":
		artifactID, _ := idParam(in, "artifact_id")
		request := CloudWorkerArtifactDownloadRequest{
			Authority: authority, ArtifactID: artifactID,
			OffsetBytes: uintParam(in, "offset_bytes"), MaxChunkBytes: uintParam(in, "max_chunk_bytes"),
		}
		chunk, err := s.cloudWorker.DownloadArtifact(ctx, request)
		if err != nil {
			return nil, err
		}
		defer clear(chunk.Data)
		if !validCloudWorkerArtifactChunk(chunk, request) {
			return nil, fmt.Errorf("%w: Cloud Worker artifact chunk is invalid", ErrUnsafeOutput)
		}
		return map[string]any{
			"owner_id": chunk.OwnerID, "account_generation": chunk.AccountGeneration,
			"artifact_id": chunk.ArtifactID, "execution_id": chunk.ExecutionID,
			"offset_bytes": chunk.OffsetBytes, "data_base64": base64.StdEncoding.EncodeToString(chunk.Data),
			"chunk_sha256": chunk.ChunkSHA256, "artifact_sha256": chunk.ArtifactSHA256,
			"size_bytes": chunk.SizeBytes, "next_offset_bytes": chunk.NextOffsetBytes, "eof": chunk.EOF,
		}, nil
	default:
		return nil, ErrUnsupported
	}
}

func validCloudWorkerArtifactChunk(chunk CloudWorkerArtifactChunk, request CloudWorkerArtifactDownloadRequest) bool {
	if chunk.OwnerID != request.OwnerID || chunk.AccountGeneration != request.AccountGeneration ||
		chunk.ArtifactID != request.ArtifactID || chunk.OffsetBytes != request.OffsetBytes ||
		chunk.ExecutionID == "" || len(chunk.Data) == 0 || uint64(len(chunk.Data)) > request.MaxChunkBytes ||
		!sha256RE.MatchString(chunk.ChunkSHA256) || !sha256RE.MatchString(chunk.ArtifactSHA256) ||
		chunk.SizeBytes == 0 || chunk.NextOffsetBytes <= chunk.OffsetBytes ||
		chunk.NextOffsetBytes > chunk.SizeBytes || chunk.NextOffsetBytes-chunk.OffsetBytes != uint64(len(chunk.Data)) ||
		chunk.EOF != (chunk.NextOffsetBytes == chunk.SizeBytes) {
		return false
	}
	if _, err := idParam(map[string]any{"execution_id": chunk.ExecutionID}, "execution_id"); err != nil {
		return false
	}
	digest := sha256.Sum256(chunk.Data)
	return hex.EncodeToString(digest[:]) == chunk.ChunkSHA256
}

func normalizeCloudWorkerObject(value CloudWorkerObject) (map[string]any, error) {
	if value == nil {
		return nil, ErrUnsafeOutput
	}
	normalized := cloneMap(map[string]any(value))
	if len(normalized) == 0 || len(normalized) != len(value) {
		return nil, ErrUnsafeOutput
	}
	if _, present := normalized["record_kind"]; present {
		return nil, fmt.Errorf("%w: record_kind is a request discriminator", ErrUnsafeOutput)
	}
	if err := validateSafeInput(normalized); err != nil {
		return nil, err
	}
	return normalized, nil
}

func validateCloudWorkerOwnedObject(value CloudWorkerObject, authority Authority, idField, expectedID string) (map[string]any, error) {
	normalized, err := normalizeCloudWorkerObject(value)
	if err != nil {
		return nil, err
	}
	if stringParam(normalized, "owner_id") != authority.OwnerID || uintParam(normalized, "account_generation") != authority.AccountGeneration || stringParam(normalized, idField) != expectedID {
		return nil, fmt.Errorf("%w: Cloud Worker owner, generation, or resource identity mismatch", ErrUnsafeOutput)
	}
	return normalized, nil
}

func validateCloudWorkerPage(page CloudWorkerPage, authority Authority, idField string) ([]any, error) {
	if !validCloudWorkerPageToken(page.NextPageToken) {
		return nil, fmt.Errorf("%w: invalid Cloud Worker page token", ErrUnsafeOutput)
	}
	items := make([]any, 0, len(page.Items))
	seen := make(map[string]struct{}, len(page.Items))
	for _, value := range page.Items {
		normalized, err := normalizeCloudWorkerObject(value)
		if err != nil {
			return nil, err
		}
		id := stringParam(normalized, idField)
		if id == "" || stringParam(normalized, "owner_id") != authority.OwnerID || uintParam(normalized, "account_generation") != authority.AccountGeneration {
			return nil, fmt.Errorf("%w: invalid Cloud Worker page item authority", ErrUnsafeOutput)
		}
		if _, duplicate := seen[id]; duplicate {
			return nil, fmt.Errorf("%w: duplicate Cloud Worker page item", ErrUnsafeOutput)
		}
		seen[id] = struct{}{}
		items = append(items, normalized)
	}
	return items, nil
}

func validCloudWorkerPageToken(value string) bool {
	if len(value) > 2048 {
		return false
	}
	for _, current := range value {
		if (current >= 'a' && current <= 'z') || (current >= 'A' && current <= 'Z') ||
			(current >= '0' && current <= '9') || current == '-' || current == '_' {
			continue
		}
		return false
	}
	return true
}

func validateCloudWorkerEvents(page CloudWorkerEventPage, authority Authority, runID string, after uint64) ([]any, error) {
	events := make([]any, 0, len(page.Events))
	sequence := after
	for _, value := range page.Events {
		normalized, err := normalizeCloudWorkerObject(value)
		if err != nil {
			return nil, err
		}
		next := uintParam(normalized, "sequence")
		if stringParam(normalized, "owner_id") != authority.OwnerID || uintParam(normalized, "account_generation") != authority.AccountGeneration || stringParam(normalized, "run_id") != runID || next <= sequence {
			return nil, fmt.Errorf("%w: invalid Cloud Worker event authority or sequence", ErrUnsafeOutput)
		}
		sequence = next
		events = append(events, normalized)
	}
	if page.NextSequence != sequence {
		return nil, fmt.Errorf("%w: invalid Cloud Worker next sequence", ErrUnsafeOutput)
	}
	return events, nil
}
