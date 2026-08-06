package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"

	agentv1 "github.com/YingSuiAI/dirextalk-agent/api/gen/dirextalk/agent/v1"
	"github.com/YingSuiAI/dirextalk-agent/internal/coreteamworker"
	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"
)

const (
	receiptSchemaVersion          = 1
	receiptLaunchCommitted        = "launch_committed"
	receiptCompletionPending      = "completion_pending"
	receiptCompletionAcknowledged = "completion_acked"
	maxReceiptBytes               = 1 << 20
)

var receiptRolePattern = regexp.MustCompile(`^[a-z][a-z0-9-]{0,62}$`)

type receiptKey struct {
	ExecutionID string
	RoleID      string
	Attempt     uint32
}

func (key receiptKey) validate() error {
	if uuid.Validate(key.ExecutionID) != nil || !receiptRolePattern.MatchString(key.RoleID) || key.Attempt == 0 {
		return errInput
	}
	return nil
}

func (key receiptKey) String() string {
	return fmt.Sprintf("%s/%s/%d", key.ExecutionID, key.RoleID, key.Attempt)
}

type executionReceipt struct {
	SchemaVersion     uint32 `json:"schema_version"`
	ExecutionID       string `json:"execution_id"`
	RoleID            string `json:"role_id"`
	Attempt           uint32 `json:"attempt"`
	State             string `json:"state"`
	CompletionRequest []byte `json:"completion_request,omitempty"`
}

type roleReceiptState interface {
	load() (executionReceipt, bool, error)
	commitLaunch(*agentv1.CoreTeamWorkerServiceCompleteRequest) error
	commitPending(*agentv1.CoreTeamWorkerServiceCompleteRequest) error
	commitAcknowledged() error
}

func (receipt executionReceipt) validate(key receiptKey) error {
	if key.validate() != nil || receipt.SchemaVersion != receiptSchemaVersion || receipt.ExecutionID != key.ExecutionID ||
		receipt.RoleID != key.RoleID || receipt.Attempt != key.Attempt {
		return errInput
	}
	switch receipt.State {
	case receiptLaunchCommitted:
		request, err := parseCompleteRequest(receipt.CompletionRequest, key)
		if err != nil || request.GetOutcome() != agentv1.CoreTeamWorkerCompletionOutcome_CORE_TEAM_WORKER_COMPLETION_OUTCOME_FAILED ||
			request.GetFailureCode() != agentv1.CoreTeamWorkerFailureCode_CORE_TEAM_WORKER_FAILURE_CODE_EXECUTION_UNCERTAIN {
			return errInput
		}
	case receiptCompletionPending, receiptCompletionAcknowledged:
		if _, err := parseCompleteRequest(receipt.CompletionRequest, key); err != nil {
			return errInput
		}
	default:
		return errInput
	}
	return nil
}

func newExecutionReceipt(key receiptKey, state string, completion []byte) executionReceipt {
	return executionReceipt{
		SchemaVersion: receiptSchemaVersion, ExecutionID: key.ExecutionID, RoleID: key.RoleID,
		Attempt: key.Attempt, State: state, CompletionRequest: append([]byte(nil), completion...),
	}
}

func marshalCompleteRequest(request *agentv1.CoreTeamWorkerServiceCompleteRequest, key receiptKey) ([]byte, error) {
	if validateCompleteRequest(request, key) != nil {
		return nil, errInput
	}
	raw, err := proto.MarshalOptions{Deterministic: true}.Marshal(request)
	if err != nil || len(raw) == 0 || len(raw) > maxReceiptBytes/2 {
		clear(raw)
		return nil, errInput
	}
	return raw, nil
}

func parseCompleteRequest(raw []byte, key receiptKey) (*agentv1.CoreTeamWorkerServiceCompleteRequest, error) {
	if len(raw) == 0 || len(raw) > maxReceiptBytes/2 {
		return nil, errInput
	}
	request := &agentv1.CoreTeamWorkerServiceCompleteRequest{}
	if proto.Unmarshal(raw, request) != nil || validateCompleteRequest(request, key) != nil {
		return nil, errInput
	}
	canonical, err := proto.MarshalOptions{Deterministic: true}.Marshal(request)
	if err != nil || !bytes.Equal(canonical, raw) {
		clear(canonical)
		return nil, errInput
	}
	clear(canonical)
	return request, nil
}

func validateCompleteRequest(request *agentv1.CoreTeamWorkerServiceCompleteRequest, key receiptKey) error {
	if request == nil || request.GetFence() == nil || uuid.Validate(request.GetFence().GetWorkerId()) != nil ||
		request.GetFence().GetExecutionId() != key.ExecutionID || request.GetFence().GetRoleId() != key.RoleID ||
		request.GetFence().GetAttempt() != key.Attempt || request.GetFence().GetLeaseEpoch() == 0 ||
		request.GetCompletionId() != stableOperationID(key.ExecutionID, key.RoleID, key.Attempt, "complete") {
		return errInput
	}
	switch request.GetOutcome() {
	case agentv1.CoreTeamWorkerCompletionOutcome_CORE_TEAM_WORKER_COMPLETION_OUTCOME_SUCCEEDED:
		metadata := coreteamworker.ResultMetadata{
			SchemaVersion: request.GetResultSchemaVersion(), Digest: request.GetResultDigest(),
			SizeBytes: request.GetResultSizeBytes(), PayloadJSON: request.GetResultJson(),
		}
		if request.GetFailureCode() != agentv1.CoreTeamWorkerFailureCode_CORE_TEAM_WORKER_FAILURE_CODE_UNSPECIFIED || metadata.Validate() != nil {
			return errInput
		}
	case agentv1.CoreTeamWorkerCompletionOutcome_CORE_TEAM_WORKER_COMPLETION_OUTCOME_FAILED:
		if request.GetResultSchemaVersion() != 0 || request.GetResultDigest() != "" || request.GetResultSizeBytes() != 0 || len(request.GetResultJson()) != 0 ||
			!validWireFailure(request.GetFailureCode()) {
			return errInput
		}
	default:
		return errInput
	}
	return nil
}

func validWireFailure(code agentv1.CoreTeamWorkerFailureCode) bool {
	switch code {
	case agentv1.CoreTeamWorkerFailureCode_CORE_TEAM_WORKER_FAILURE_CODE_PROCESS,
		agentv1.CoreTeamWorkerFailureCode_CORE_TEAM_WORKER_FAILURE_CODE_PI,
		agentv1.CoreTeamWorkerFailureCode_CORE_TEAM_WORKER_FAILURE_CODE_INVALID_RESULT,
		agentv1.CoreTeamWorkerFailureCode_CORE_TEAM_WORKER_FAILURE_CODE_TIMEOUT,
		agentv1.CoreTeamWorkerFailureCode_CORE_TEAM_WORKER_FAILURE_CODE_CANCELED,
		agentv1.CoreTeamWorkerFailureCode_CORE_TEAM_WORKER_FAILURE_CODE_INTERNAL,
		agentv1.CoreTeamWorkerFailureCode_CORE_TEAM_WORKER_FAILURE_CODE_EXECUTION_UNCERTAIN:
		return true
	default:
		return false
	}
}

func decodeReceipt(raw []byte, key receiptKey) (executionReceipt, error) {
	if len(raw) == 0 || len(raw) > maxReceiptBytes {
		return executionReceipt{}, errInput
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var receipt executionReceipt
	if decoder.Decode(&receipt) != nil {
		return executionReceipt{}, errInput
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) || receipt.validate(key) != nil {
		return executionReceipt{}, errInput
	}
	canonical, err := json.Marshal(receipt)
	if err != nil || !bytes.Equal(canonical, raw) {
		clear(canonical)
		return executionReceipt{}, errInput
	}
	clear(canonical)
	return receipt, nil
}
