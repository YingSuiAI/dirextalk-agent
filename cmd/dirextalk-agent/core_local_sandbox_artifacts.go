package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"

	"github.com/YingSuiAI/dirextalk-agent/internal/cloudworker/localartifact"
	"github.com/YingSuiAI/dirextalk-agent/internal/coreexecutionv2"
	"github.com/YingSuiAI/dirextalk-agent/internal/coreextension/execution"
	"github.com/YingSuiAI/dirextalk-agent/internal/coretask"
)

func collectLocalSandboxArtifacts(ctx context.Context, repository *localartifact.Repository, ownerID string, accountGeneration uint64, executionID string, receipt *execution.LocalToolReceipt) (coretask.Result, error) {
	if repository == nil || receipt == nil || len(receipt.Result.Files) != len(receipt.ResultFiles) {
		return coretask.Result{}, localartifact.ErrInvalid
	}
	var envelope struct {
		Structured struct {
			Stdout   string `json:"stdout"`
			Stderr   string `json:"stderr"`
			ExitCode int    `json:"exit_code"`
		} `json:"structuredContent"`
	}
	if json.Unmarshal(receipt.Result.JSON, &envelope) != nil {
		return coretask.Result{}, localartifact.ErrInvalid
	}
	authority := localartifact.Authority{OwnerID: ownerID, AccountGeneration: accountGeneration}
	sink, err := repository.BindLocalSandbox(authority, executionID)
	if err != nil {
		return coretask.Result{}, err
	}
	if err = sink.StoreText(ctx, []byte(envelope.Structured.Stdout), []byte(envelope.Structured.Stderr), envelope.Structured.ExitCode); err != nil {
		return coretask.Result{}, err
	}
	for index, metadata := range receipt.Result.Files {
		file := receipt.ResultFiles[index]
		if file == nil {
			return coretask.Result{}, localartifact.ErrInvalid
		}
		if _, err = file.Seek(0, io.SeekStart); err != nil {
			return coretask.Result{}, err
		}
		if err = sink.StoreArtifact(ctx, metadata.Path, file, metadata.Size); err != nil {
			return coretask.Result{}, err
		}
	}
	artifacts, next, err := repository.ListLocalSandbox(ctx, authority, executionID, "", 200)
	if err != nil || next != "" {
		return coretask.Result{}, errors.Join(err, localartifact.ErrInvalid)
	}
	return attachLocalSandboxArtifacts(receipt.Result, artifacts)
}

func attachLocalSandboxArtifacts(result coretask.Result, artifacts []localartifact.Artifact) (coretask.Result, error) {
	var payload map[string]any
	if json.Unmarshal(result.JSON, &payload) != nil {
		return coretask.Result{}, localartifact.ErrInvalid
	}
	structured, ok := payload["structuredContent"].(map[string]any)
	if !ok {
		return coretask.Result{}, localartifact.ErrInvalid
	}
	values := make([]any, 0, len(artifacts))
	for _, artifact := range artifacts {
		values = append(values, map[string]any{
			"account_generation": artifact.AccountGeneration,
			"artifact_id":        artifact.ArtifactID,
			"execution_id":       artifact.ExecutionID,
			"media_type":         artifact.MediaType,
			"name":               artifact.Name,
			"record_kind":        coreexecutionv2.RecordKindLocalSandbox,
			"sha256":             artifact.SHA256,
			"size_bytes":         artifact.SizeBytes,
		})
	}
	structured["artifacts"] = values
	payload["structuredContent"] = structured
	raw, err := json.Marshal(payload)
	if err != nil {
		return coretask.Result{}, err
	}
	result.JSON = raw
	return result, result.Validate()
}
