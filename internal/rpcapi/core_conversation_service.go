package rpcapi

import (
	"context"
	"encoding/json"
	"errors"
	agentv1 "github.com/YingSuiAI/dirextalk-agent/api/gen/dirextalk/agent/v1"
	"github.com/YingSuiAI/dirextalk-agent/internal/coreconversation"
	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"
	"strconv"
	"strings"
)

type CoreConversationService struct {
	agentv1.UnimplementedConversationServiceServer
	service *coreconversation.Service
}

func NewCoreConversationService(service *coreconversation.Service) (*CoreConversationService, error) {
	if service == nil {
		return nil, errors.New("conversation service required")
	}
	return &CoreConversationService{service: service}, nil
}
func mapErr(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, coreconversation.ErrInvalid) {
		return status.Error(codes.InvalidArgument, "invalid conversation request")
	}
	if errors.Is(err, coreconversation.ErrExtensionsUnsupported) {
		return status.Error(codes.InvalidArgument, "conversation extensions require durable turn")
	}
	if errors.Is(err, coreconversation.ErrConflict) {
		return status.Error(codes.Aborted, "conversation conflict")
	}
	if errors.Is(err, coreconversation.ErrInFlight) {
		return status.Error(codes.Aborted, "request in flight")
	}
	if errors.Is(err, coreconversation.ErrChatFailed) {
		return status.Error(codes.FailedPrecondition, "chat failed")
	}
	if errors.Is(err, coreconversation.ErrCanceled) {
		return status.Error(codes.Canceled, "conversation turn canceled")
	}
	if errors.Is(err, coreconversation.ErrDeleted) {
		return status.Error(codes.NotFound, "conversation not found")
	}
	return status.Error(codes.Internal, "conversation operation failed")
}

func turnProto(t coreconversation.Turn) *agentv1.CoreConversationTurn {
	out := &agentv1.CoreConversationTurn{TurnId: t.ID, RequestId: t.RequestID, ConversationId: t.ConversationID, Message: t.Prompt, ModelProfileId: t.ProfileID, Revision: int64(t.Revision), State: string(t.State), TerminalCode: t.TerminalCode, TerminalSummary: t.TerminalSummary, LastSequence: t.LastSequence, CreatedAt: timestamppb.New(t.CreatedAt), UpdatedAt: timestamppb.New(t.UpdatedAt)}
	if t.ProfileSnapshot.Revision > 0 {
		revision := t.ProfileSnapshot.Revision
		out.ModelProfileRevision = &revision
	}
	if t.ProfileSnapshot.CredentialVersion > 0 {
		credentialVersion := t.ProfileSnapshot.CredentialVersion
		out.CredentialVersion = &credentialVersion
	}
	if t.ExpectedRevision != nil {
		out.ExpectedRevision = int64(*t.ExpectedRevision)
	}
	if t.Response != nil {
		sequence := uint64(t.Response.Revision)
		if sequence > uint64(1<<63-1) {
			sequence = uint64(1<<63 - 1)
		}
		out.Result = msgProto(t.Response.Message, int64(sequence), t.Response.ConversationID)
	}
	return out
}

func turnEventProto(e coreconversation.TurnEvent) (*agentv1.ConversationServiceWatchTurnEventsResponse, error) {
	if e.Revision == 0 || (e.Kind == coreconversation.TurnEventWaitingConfirmation && e.ValidateWaitingConfirmationAuthority() != nil) {
		return nil, coreconversation.ErrChatFailed
	}
	out := &agentv1.CoreConversationTurnEvent{TurnId: e.TurnID, Sequence: e.Sequence, Revision: e.Revision, Kind: string(e.Kind), Text: e.Text, ReasoningContent: e.ReasoningContent, ErrorCode: e.ErrorCode, ErrorSummary: e.ErrorSummary, FirstSequence: e.FirstSequence, LastSequence: e.LastSequence, ReplayGap: e.ReplayGap, CreatedAt: timestamppb.New(e.CreatedAt), ConfirmationId: e.ConfirmationID, ExecutionId: e.ExecutionID, Status: e.Status, Phase: e.Phase, RelatedTaskIds: append([]string(nil), e.RelatedTaskIDs...), RelatedPlanIds: append([]string(nil), e.RelatedPlanIDs...), References: referenceProtos(e.References)}
	if e.ToolResult != nil {
		out.ToolResult = toolResultProto(*e.ToolResult)
	}
	if e.Message != nil {
		conversationID := e.TurnID
		if e.Response != nil {
			conversationID = e.Response.ConversationID
		}
		out.Message = msgProto(*e.Message, e.Sequence, conversationID)
	}
	return &agentv1.ConversationServiceWatchTurnEventsResponse{Event: out}, nil
}

func referenceProto(r coreconversation.Reference) *agentv1.CoreConversationReference {
	return &agentv1.CoreConversationReference{
		Kind: r.Kind, AccountGeneration: r.AccountGeneration, TaskId: r.TaskID,
		PlanId: r.PlanID, PlanRevision: r.PlanRevision, PlanDigest: r.PlanDigest,
		RunId: r.RunID, RunRevision: r.RunRevision, RunDigest: r.RunDigest,
		ExecutionId: r.ExecutionID, ConfirmationId: r.ConfirmationID,
		ConfirmationRevision: r.ConfirmationRevision, BindingDigest: r.BindingDigest,
		QuoteDigest: r.QuoteDigest, ExecutionDigest: r.ExecutionDigest,
		Status: r.Status, State: r.State, RoomId: r.RoomID, RoomType: r.RoomType,
		ChannelId: r.ChannelID, PostId: r.PostID, Title: r.Title, Preview: r.Preview,
		RecordKind: r.RecordKind, ArtifactId: r.ArtifactID, Name: r.Name, MediaType: r.MediaType,
		SizeBytes: r.SizeBytes, Sha256: r.SHA256,
	}
}

func referenceProtos(values []coreconversation.Reference) []*agentv1.CoreConversationReference {
	out := make([]*agentv1.CoreConversationReference, 0, len(values))
	for _, value := range values {
		out = append(out, referenceProto(value))
	}
	return out
}

func toolResultProto(value coreconversation.ToolResult) *agentv1.CoreToolResult {
	return &agentv1.CoreToolResult{ToolName: value.ToolName, Summary: value.Summary, RelatedTaskIds: append([]string(nil), value.RelatedTaskIDs...), ToolSummaries: summaryList(value.Summary), RelatedPlanIds: append([]string(nil), value.RelatedPlanIDs...), References: referenceProtos(value.References)}
}
func convProto(c coreconversation.Conversation) *agentv1.CoreConversation {
	return &agentv1.CoreConversation{ConversationId: c.ID, Title: c.Title, Revision: int64(c.Revision), CreatedAt: timestamppb.New(c.CreatedAt), UpdatedAt: timestamppb.New(c.UpdatedAt)}
}
func msgProto(m coreconversation.Message, seq int64, conversationID ...string) *agentv1.CoreConversationMessage {
	payload := (*structpb.Struct)(nil)
	if raw, e := json.Marshal(m); e == nil {
		var value map[string]any
		if json.Unmarshal(raw, &value) == nil {
			payload, _ = structpb.NewStruct(value)
		}
	}
	id := ""
	if len(conversationID) > 0 {
		id = conversationID[0]
	}
	return &agentv1.CoreConversationMessage{MessageId: m.ID, ConversationId: id, Sequence: seq, Role: string(m.Role), Content: m.Content, ReasoningContent: m.ReasoningContent, ModelProfileId: m.ModelProfileID, Payload: payload, RelatedTaskIds: append([]string(nil), m.RelatedTaskIDs...), ToolSummaries: append([]string(nil), m.ToolSummaries...), CreatedAt: timestamppb.New(m.CreatedAt), RelatedPlanIds: append([]string(nil), m.RelatedPlanIDs...), References: referenceProtos(m.References)}
}
func extensionCommands(in []*agentv1.CoreExtensionSelection) []coreconversation.ExtensionSelection {
	if len(in) == 0 {
		return nil
	}
	out := make([]coreconversation.ExtensionSelection, 0, len(in))
	for _, x := range in {
		if x == nil {
			continue
		}
		out = append(out, coreconversation.ExtensionSelection{
			Kind:         coreconversation.ExtensionKind(x.GetKind()),
			ID:           x.GetId(),
			Version:      x.GetPinnedVersion(),
			Digest:       x.GetDigest(),
			AllowedTools: append([]string(nil), x.GetAllowedTools()...),
		})
	}
	return out
}
func validateRPCChatRequest(extensions []*agentv1.CoreExtensionSelection, knowledge []string) error {
	if len(knowledge) > 0 {
		return status.Error(codes.InvalidArgument, "knowledge references are unavailable")
	}
	if len(extensions) > 0 {
		return status.Error(codes.InvalidArgument, "extension selections are unavailable")
	}
	return nil
}

func rpcExecutionMode(value string) (coreconversation.TurnExecutionMode, error) {
	mode, err := coreconversation.NormalizeClientTurnExecutionMode(coreconversation.TurnExecutionMode(value))
	if err != nil {
		return "", status.Error(codes.InvalidArgument, "unsupported execution mode")
	}
	return mode, nil
}
func summaryList(summary string) []string {
	if summary == "" {
		return nil
	}
	return []string{summary}
}
func (s *CoreConversationService) Create(ctx context.Context, r *agentv1.ConversationServiceCreateRequest) (*agentv1.ConversationServiceCreateResponse, error) {
	key := r.GetIdempotencyKey()
	id := uuid.NewSHA1(uuid.NameSpaceOID, []byte("conversation:"+key)).String()
	c := coreconversation.Conversation{ID: id, Title: r.GetTitle(), Revision: 1}
	out, e := s.service.CreateConversation(ctx, c, key)
	if e != nil {
		return nil, mapErr(e)
	}
	return &agentv1.ConversationServiceCreateResponse{Conversation: convProto(out)}, nil
}
func (s *CoreConversationService) Get(ctx context.Context, r *agentv1.ConversationServiceGetRequest) (*agentv1.ConversationServiceGetResponse, error) {
	c, e := s.service.GetConversation(ctx, r.GetConversationId())
	if e != nil {
		return nil, mapErr(e)
	}
	out := &agentv1.ConversationServiceGetResponse{Conversation: convProto(c)}
	start := 0
	if token := strings.TrimSpace(r.GetPageToken()); token != "" {
		var e error
		start, e = strconv.Atoi(token)
		if e != nil || start < 0 || start > len(c.Messages) {
			return nil, status.Error(codes.InvalidArgument, "invalid page token")
		}
	}
	end := len(c.Messages)
	if size := int(r.GetPageSize()); size > 0 {
		if size > 1000 {
			return nil, status.Error(codes.InvalidArgument, "invalid page size")
		}
		if end > start+size {
			end = start + size
		}
	}
	for i := start; i < end; i++ {
		out.Messages = append(out.Messages, msgProto(c.Messages[i], int64(i+1), c.ID))
	}
	if end < len(c.Messages) {
		out.NextPageToken = strconv.Itoa(end)
	}
	return out, nil
}
func (s *CoreConversationService) List(ctx context.Context, r *agentv1.ConversationServiceListRequest) (*agentv1.ConversationServiceListResponse, error) {
	cs, next, e := s.service.ListConversations(ctx, r.GetPageToken(), int(r.GetPageSize()))
	if e != nil {
		return nil, mapErr(e)
	}
	out := &agentv1.ConversationServiceListResponse{NextPageToken: next}
	for _, c := range cs {
		out.Conversations = append(out.Conversations, convProto(c))
	}
	return out, nil
}
func (s *CoreConversationService) Delete(ctx context.Context, r *agentv1.ConversationServiceDeleteRequest) (*agentv1.ConversationServiceDeleteResponse, error) {
	if e := s.service.DeleteConversation(ctx, r.GetConversationId(), uint64(r.GetExpectedRevision()), r.GetIdempotencyKey()); e != nil {
		return nil, mapErr(e)
	}
	return &agentv1.ConversationServiceDeleteResponse{}, nil
}
func (s *CoreConversationService) Chat(ctx context.Context, r *agentv1.ConversationServiceChatRequest) (*agentv1.ConversationServiceChatResponse, error) {
	if e := validateRPCChatRequest(r.GetExtensions(), r.GetKnowledgeRefs()); e != nil {
		return nil, e
	}
	executionMode, e := rpcExecutionMode(r.GetExecutionMode())
	if e != nil {
		return nil, e
	}
	cmd := coreconversation.ChatCommand{RequestID: r.GetIdempotencyKey(), ConversationID: r.GetConversationId(), Prompt: r.GetMessage(), ProfileID: r.GetModelProfileId(), ExpectedProfileRevision: r.GetModelProfileRevision(), ExpectedCredentialVersion: r.GetCredentialVersion(), Extensions: extensionCommands(r.GetExtensions()), ExecutionMode: executionMode}
	if r.ExpectedRevision != nil {
		x := uint64(r.GetExpectedRevision())
		cmd.ExpectedRevision = &x
	}
	res, e := s.service.Chat(ctx, cmd)
	if e != nil {
		return nil, mapErr(e)
	}
	return &agentv1.ConversationServiceChatResponse{Conversation: &agentv1.CoreConversation{ConversationId: res.ConversationID, Revision: int64(res.Revision)}, Message: msgProto(res.Message, int64(res.Revision), res.ConversationID), RelatedTaskIds: append([]string(nil), res.RelatedTaskIDs...), RelatedPlanIds: append([]string(nil), res.RelatedPlanIDs...), References: referenceProtos(res.References)}, nil
}

func durableTurnProgressProto(event coreconversation.StreamEvent) *agentv1.ConversationServiceStreamChatResponse {
	name, progress := "", event.Status
	switch event.Kind {
	case coreconversation.EventAccepted:
		progress = "accepted"
	case coreconversation.EventStarted:
		progress = "started"
	case coreconversation.EventWaitingConfirmation:
		name = "confirmation"
		if progress == "" {
			progress = "waiting_confirmation"
		}
	case coreconversation.EventWorkerStatus:
		name = "cloud_worker"
	case coreconversation.EventSteered:
		name = "steer"
		if progress == "" {
			progress = "applied"
		}
	default:
		return nil
	}
	return &agentv1.ConversationServiceStreamChatResponse{Event: &agentv1.ConversationServiceStreamChatResponse_Tool{
		Tool: &agentv1.CoreStreamChatToolProgress{Name: name, Status: progress},
	}}
}

func (s *CoreConversationService) StreamChat(r *agentv1.ConversationServiceStreamChatRequest, stream agentv1.ConversationService_StreamChatServer) error {
	if e := validateRPCChatRequest(r.GetExtensions(), r.GetKnowledgeRefs()); e != nil {
		return e
	}
	executionMode, e := rpcExecutionMode(r.GetExecutionMode())
	if e != nil {
		return e
	}
	cmd := coreconversation.ChatCommand{RequestID: r.GetIdempotencyKey(), ConversationID: r.GetConversationId(), Prompt: r.GetMessage(), ProfileID: r.GetModelProfileId(), ExpectedProfileRevision: r.GetModelProfileRevision(), ExpectedCredentialVersion: r.GetCredentialVersion(), Extensions: extensionCommands(r.GetExtensions()), ExecutionMode: executionMode}
	if r.ExpectedRevision != nil {
		x := uint64(r.GetExpectedRevision())
		cmd.ExpectedRevision = &x
	}
	ch, e := s.service.StreamChat(stream.Context(), cmd)
	if e != nil {
		return mapErr(e)
	}
	for ev := range ch {
		out := durableTurnProgressProto(ev)
		switch ev.Kind {
		case coreconversation.EventDelta:
			out = &agentv1.ConversationServiceStreamChatResponse{Event: &agentv1.ConversationServiceStreamChatResponse_Delta{Delta: &agentv1.CoreStreamChatDelta{Text: ev.Text, ReasoningContent: ev.ReasoningContent}}}
		case coreconversation.EventToolCall:
			if ev.ToolCall != nil {
				out = &agentv1.ConversationServiceStreamChatResponse{Event: &agentv1.ConversationServiceStreamChatResponse_Tool{Tool: &agentv1.CoreStreamChatToolProgress{Name: ev.ToolCall.Name, Status: "started"}}}
			}
		case coreconversation.EventToolResult:
			if ev.ToolResult != nil {
				out = &agentv1.ConversationServiceStreamChatResponse{Event: &agentv1.ConversationServiceStreamChatResponse_Tool{Tool: &agentv1.CoreStreamChatToolProgress{Name: ev.ToolResult.ToolName, Status: "completed", RelatedTaskIds: append([]string(nil), ev.ToolResult.RelatedTaskIDs...), ToolSummaries: summaryList(ev.ToolResult.Summary), RelatedPlanIds: append([]string(nil), ev.ToolResult.RelatedPlanIDs...), References: referenceProtos(ev.ToolResult.References)}}}
			}
		case coreconversation.EventDone:
			if ev.Response != nil {
				results := make([]*agentv1.CoreToolResult, 0, len(ev.Response.ToolResults))
				for _, tr := range ev.Response.ToolResults {
					results = append(results, toolResultProto(tr))
				}
				out = &agentv1.ConversationServiceStreamChatResponse{Event: &agentv1.ConversationServiceStreamChatResponse_Done{Done: &agentv1.CoreStreamChatDone{Message: msgProto(ev.Response.Message, int64(ev.Response.Revision), ev.Response.ConversationID), RelatedTaskIds: append([]string(nil), ev.Response.RelatedTaskIDs...), ToolResults: results, RelatedPlanIds: append([]string(nil), ev.Response.RelatedPlanIDs...), References: referenceProtos(ev.Response.References)}}}
			}
		case coreconversation.EventError:
			return mapStreamError(ev.ErrCode)
		}
		if out != nil {
			if e := stream.Send(out); e != nil {
				return e
			}
		}
	}
	return nil
}

func mapStreamError(code string) error {
	switch code {
	case "canceled":
		return status.Error(codes.Canceled, "conversation turn canceled")
	case "conflict":
		return status.Error(codes.Aborted, "conversation conflict")
	case "in_flight":
		return status.Error(codes.Aborted, "request in flight")
	case "claim_failed", "execution_failed":
		return status.Error(codes.FailedPrecondition, "chat failed")
	default:
		return status.Error(codes.FailedPrecondition, "chat failed")
	}
}

func (s *CoreConversationService) StartTurn(ctx context.Context, r *agentv1.ConversationServiceStartTurnRequest) (*agentv1.ConversationServiceStartTurnResponse, error) {
	executionMode, e := rpcExecutionMode(r.GetExecutionMode())
	if e != nil {
		return nil, e
	}
	cmd := coreconversation.TurnStartCommand{RequestID: r.GetIdempotencyKey(), ConversationID: r.GetConversationId(), Prompt: r.GetMessage(), ProfileID: r.GetModelProfileId(), ExpectedProfileRevision: r.GetModelProfileRevision(), ExpectedCredentialVersion: r.GetCredentialVersion(), Extensions: extensionCommands(r.GetExtensions()), ExecutionMode: executionMode}
	if r.ExpectedRevision != nil {
		x := uint64(r.GetExpectedRevision())
		cmd.ExpectedRevision = &x
	}
	// The domain binds the immutable profile snapshot before acceptance. The
	// existing service resolver is intentionally reused only at this boundary.
	if cmd.ProfileID == "" {
		return nil, status.Error(codes.InvalidArgument, "model profile is required")
	}
	turn, e := s.service.StartTurn(ctx, cmd)
	if e != nil {
		return nil, mapErr(e)
	}
	return &agentv1.ConversationServiceStartTurnResponse{Turn: turnProto(turn)}, nil
}

func (s *CoreConversationService) GetTurn(ctx context.Context, r *agentv1.ConversationServiceGetTurnRequest) (*agentv1.ConversationServiceGetTurnResponse, error) {
	turn, e := s.service.GetTurn(ctx, r.GetTurnId())
	if e != nil {
		return nil, mapErr(e)
	}
	return &agentv1.ConversationServiceGetTurnResponse{Turn: turnProto(turn)}, nil
}

func (s *CoreConversationService) WatchTurnEvents(r *agentv1.ConversationServiceWatchTurnEventsRequest, stream agentv1.ConversationService_WatchTurnEventsServer) error {
	ch, e := s.service.WatchTurnEvents(stream.Context(), r.GetTurnId(), r.GetAfterSequence(), int(r.GetLimit()))
	if e != nil {
		return mapErr(e)
	}
	for event := range ch {
		if event.Err != nil {
			return mapErr(event.Err)
		}
		response, projectionErr := turnEventProto(event)
		if projectionErr != nil {
			return mapErr(projectionErr)
		}
		if e := stream.Send(response); e != nil {
			return e
		}
	}
	return nil
}

func (s *CoreConversationService) CancelTurn(ctx context.Context, r *agentv1.ConversationServiceCancelTurnRequest) (*agentv1.ConversationServiceCancelTurnResponse, error) {
	turn, e := s.service.CancelTurn(ctx, coreconversation.TurnCancelCommand{RequestID: r.GetIdempotencyKey(), TurnID: r.GetTurnId()})
	if e != nil {
		return nil, mapErr(e)
	}
	return &agentv1.ConversationServiceCancelTurnResponse{Turn: turnProto(turn)}, nil
}

func (s *CoreConversationService) SteerTurn(ctx context.Context, r *agentv1.ConversationServiceSteerTurnRequest) (*agentv1.ConversationServiceSteerTurnResponse, error) {
	turn, e := s.service.SteerTurn(ctx, coreconversation.TurnSteerCommand{
		RequestID: r.GetIdempotencyKey(), TurnID: r.GetTurnId(),
		ExpectedRevision: uint64(r.GetExpectedRevision()), Instruction: r.GetInstruction(),
		AcceptedAttachmentIDs: append([]string(nil), r.GetAcceptedAttachmentIds()...),
	})
	if e != nil {
		return nil, mapErr(e)
	}
	return &agentv1.ConversationServiceSteerTurnResponse{Turn: turnProto(turn)}, nil
}
