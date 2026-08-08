package agentcapability

import (
	"context"
	"fmt"
	"strings"

	capabilityclient "github.com/YingSuiAI/dirextalk-agent/internal/capability/client"
	"github.com/YingSuiAI/dirextalk-agent/internal/coreimagetool"
	capv1 "github.com/YingSuiAI/dirextalk-capability-api/gen/go/dirextalk/capability/v1"
)

const (
	imageBeginInputSchema      = `{"additionalProperties":false,"properties":{"content_sha256":{"pattern":"^[a-f0-9]{64}$","type":"string"},"declared_size":{"maximum":8388608,"minimum":1,"type":"integer"},"idempotency_key":{"format":"uuid","type":"string"},"image_request_id":{"format":"uuid","type":"string"},"mime_type":{"enum":["image/jpeg","image/png","image/webp"],"type":"string"},"name":{"maxLength":255,"minLength":1,"type":"string"}},"required":["idempotency_key","image_request_id","name","mime_type","declared_size","content_sha256"],"type":"object"}`
	imageAppendInputSchema     = `{"additionalProperties":false,"properties":{"chunk_sha256":{"pattern":"^[a-f0-9]{64}$","type":"string"},"data_base64":{"maxLength":1398104,"minLength":4,"type":"string"},"expected_revision":{"minimum":1,"type":"integer"},"idempotency_key":{"format":"uuid","type":"string"},"offset_bytes":{"minimum":0,"type":"integer"},"ordinal":{"minimum":0,"type":"integer"},"upload_id":{"format":"uuid","type":"string"}},"required":["idempotency_key","upload_id","expected_revision","ordinal","offset_bytes","data_base64","chunk_sha256"],"type":"object"}`
	imageCommitInputSchema     = `{"additionalProperties":false,"properties":{"content_sha256":{"pattern":"^[a-f0-9]{64}$","type":"string"},"expected_revision":{"minimum":1,"type":"integer"},"idempotency_key":{"format":"uuid","type":"string"},"upload_id":{"format":"uuid","type":"string"}},"required":["idempotency_key","upload_id","expected_revision","content_sha256"],"type":"object"}`
	imageExecuteInputSchema    = `{"additionalProperties":false,"properties":{"idempotency_key":{"format":"uuid","type":"string"},"source_id":{"format":"uuid","type":"string"},"source_revision":{"const":1,"type":"integer"}},"required":["idempotency_key","source_id","source_revision"],"type":"object"}`
	imageTranslateInputSchema  = `{"additionalProperties":false,"properties":{"idempotency_key":{"format":"uuid","type":"string"},"source_id":{"format":"uuid","type":"string"},"source_revision":{"const":1,"type":"integer"},"target_locale":{"maxLength":64,"minLength":1,"type":"string"}},"required":["idempotency_key","source_id","source_revision","target_locale"],"type":"object"}`
	imageUploadResultSchema    = `{"additionalProperties":false,"properties":{"expires_at":{"format":"date-time","type":"string"},"image_request_id":{"format":"uuid","type":"string"},"max_chunk_bytes":{"const":1048576,"type":"integer"},"received_size":{"minimum":0,"type":"integer"},"revision":{"minimum":1,"type":"integer"},"source_id":{"format":"uuid","type":"string"},"status":{"enum":["receiving","committed","consumed"],"type":"string"},"upload_id":{"format":"uuid","type":"string"}},"required":["upload_id","source_id","image_request_id","status","received_size","max_chunk_bytes","revision","expires_at"],"type":"object"}`
	imageCommitResultSchema    = `{"additionalProperties":false,"properties":{"expires_at":{"format":"date-time","type":"string"},"image_request_id":{"format":"uuid","type":"string"},"mime_type":{"enum":["image/jpeg","image/png","image/webp"],"type":"string"},"name":{"maxLength":255,"minLength":1,"type":"string"},"sha256":{"pattern":"^[a-f0-9]{64}$","type":"string"},"size_bytes":{"maximum":8388608,"minimum":1,"type":"integer"},"source_id":{"format":"uuid","type":"string"},"source_revision":{"const":1,"type":"integer"},"status":{"const":"committed","type":"string"}},"required":["source_id","source_revision","image_request_id","name","mime_type","size_bytes","sha256","status","expires_at"],"type":"object"}`
	imageExtractResultSchema   = `{"additionalProperties":false,"properties":{"idempotency_key":{"format":"uuid","type":"string"},"source_id":{"format":"uuid","type":"string"},"source_revision":{"const":1,"type":"integer"},"text":{"maxLength":65536,"type":"string"}},"required":["idempotency_key","source_id","source_revision","text"],"type":"object"}`
	imageTranslateResultSchema = `{"additionalProperties":false,"properties":{"idempotency_key":{"format":"uuid","type":"string"},"source_id":{"format":"uuid","type":"string"},"source_revision":{"const":1,"type":"integer"},"target_locale":{"maxLength":64,"minLength":1,"type":"string"},"text":{"maxLength":65536,"type":"string"}},"required":["idempotency_key","source_id","source_revision","text","target_locale"],"type":"object"}`
)

type coreImageToolCapability struct{ service *coreimagetool.Service }

func NewCoreImageToolCapability(service *coreimagetool.Service) Capability {
	return &coreImageToolCapability{service: service}
}
func (c *coreImageToolCapability) Descriptor() *capv1.CapabilityDescriptor {
	d := capabilityDescriptor("agent.image_tools.v1", "Image Tools", "Agent-owned one-shot image text extraction and translation", []capabilityOperation{
		{ID: "upload_begin", DisplayName: "Begin image upload", Description: "Begin a bounded ephemeral image upload.", Type: capv1.OperationType_OPERATION_TYPE_MUTATION, Scope: "agent:image_tools:upload", InputSchema: imageBeginInputSchema, ResultSchema: imageUploadResultSchema},
		{ID: "upload_append", DisplayName: "Append image upload", Description: "Append one verified image chunk.", Type: capv1.OperationType_OPERATION_TYPE_MUTATION, Scope: "agent:image_tools:upload", InputSchema: imageAppendInputSchema, ResultSchema: imageUploadResultSchema},
		{ID: "upload_commit", DisplayName: "Commit image upload", Description: "Verify and commit the ephemeral image source.", Type: capv1.OperationType_OPERATION_TYPE_MUTATION, Scope: "agent:image_tools:upload", InputSchema: imageCommitInputSchema, ResultSchema: imageCommitResultSchema},
		{ID: "extract_text", DisplayName: "Extract image text", Description: "Extract visible text without conversation persistence.", Type: capv1.OperationType_OPERATION_TYPE_MUTATION, Scope: "agent:image_tools:execute", InputSchema: imageExecuteInputSchema, ResultSchema: imageExtractResultSchema},
		{ID: "translate_text", DisplayName: "Translate image text", Description: "Extract and translate visible text to a canonical locale.", Type: capv1.OperationType_OPERATION_TYPE_MUTATION, Scope: "agent:image_tools:execute", InputSchema: imageTranslateInputSchema, ResultSchema: imageTranslateResultSchema},
	})
	for _, op := range d.Operations {
		op.Audience = []capv1.Audience{capv1.Audience_AUDIENCE_OWNER_CLIENT}
		if op.OperationId == "upload_append" {
			op.MaxRequestSizeBytes = 2 << 20
		}
		if op.OperationId == "extract_text" || op.OperationId == "translate_text" {
			op.TimeoutClass = "medium"
		}
	}
	return d
}
func (c *coreImageToolCapability) HandleOperation(ctx context.Context, op string, raw []byte) ([]byte, error) {
	if c == nil || c.service == nil {
		return nil, coreimagetool.ErrRepository
	}
	if err := requireCapabilityIdentity(ctx); err != nil {
		return nil, err
	}
	p, _ := capabilityclient.PermissionFromContext(ctx)
	owner, generation := strings.TrimSpace(p.GetAuthenticatedOwnerId()), p.GetAccountGeneration()
	switch op {
	case "upload_begin":
		var r struct {
			IdempotencyKey string `json:"idempotency_key"`
			ImageRequestID string `json:"image_request_id"`
			Name           string `json:"name"`
			MIMEType       string `json:"mime_type"`
			DeclaredSize   uint64 `json:"declared_size"`
			ContentSHA256  string `json:"content_sha256"`
		}
		if decodeStrictObject(raw, &r) != nil {
			return nil, coreimagetool.ErrInvalid
		}
		v, e := c.service.Begin(ctx, coreimagetool.BeginCommand{OwnerID: owner, AccountGeneration: generation, IdempotencyKey: r.IdempotencyKey, ImageRequestID: r.ImageRequestID, Name: r.Name, MIMEType: r.MIMEType, DeclaredSize: r.DeclaredSize, ContentSHA256: r.ContentSHA256})
		return marshalResult(v, e)
	case "upload_append":
		defer clear(raw)
		var r struct {
			IdempotencyKey   string `json:"idempotency_key"`
			UploadID         string `json:"upload_id"`
			ExpectedRevision uint64 `json:"expected_revision"`
			Ordinal          uint32 `json:"ordinal"`
			OffsetBytes      uint64 `json:"offset_bytes"`
			DataBase64       string `json:"data_base64"`
			ChunkSHA256      string `json:"chunk_sha256"`
		}
		if decodeStrictObject(raw, &r) != nil {
			return nil, coreimagetool.ErrInvalid
		}
		data, e := decodeCanonicalAttachmentChunk(r.DataBase64)
		if e != nil {
			return nil, coreimagetool.ErrInvalid
		}
		defer clear(data)
		v, e := c.service.Append(ctx, coreimagetool.AppendCommand{OwnerID: owner, AccountGeneration: generation, IdempotencyKey: r.IdempotencyKey, UploadID: r.UploadID, ExpectedRevision: r.ExpectedRevision, Ordinal: r.Ordinal, OffsetBytes: r.OffsetBytes, Data: data, ChunkSHA256: r.ChunkSHA256})
		return marshalResult(v, e)
	case "upload_commit":
		var r struct {
			IdempotencyKey   string `json:"idempotency_key"`
			UploadID         string `json:"upload_id"`
			ExpectedRevision uint64 `json:"expected_revision"`
			ContentSHA256    string `json:"content_sha256"`
		}
		if decodeStrictObject(raw, &r) != nil {
			return nil, coreimagetool.ErrInvalid
		}
		v, e := c.service.Commit(ctx, coreimagetool.CommitCommand{OwnerID: owner, AccountGeneration: generation, IdempotencyKey: r.IdempotencyKey, UploadID: r.UploadID, ExpectedRevision: r.ExpectedRevision, ContentSHA256: r.ContentSHA256})
		return marshalResult(v, e)
	case "extract_text", "translate_text":
		var r struct {
			IdempotencyKey string `json:"idempotency_key"`
			SourceID       string `json:"source_id"`
			SourceRevision uint64 `json:"source_revision"`
			TargetLocale   string `json:"target_locale"`
		}
		if decodeStrictObject(raw, &r) != nil {
			return nil, coreimagetool.ErrInvalid
		}
		cmd := coreimagetool.ExecuteCommand{OwnerID: owner, AccountGeneration: generation, IdempotencyKey: r.IdempotencyKey, SourceID: r.SourceID, SourceRevision: r.SourceRevision, TargetLocale: r.TargetLocale}
		if op == "extract_text" {
			v, e := c.service.ExtractText(ctx, cmd)
			return marshalResult(v, e)
		}
		v, e := c.service.TranslateText(ctx, cmd)
		return marshalResult(v, e)
	default:
		return nil, fmt.Errorf("unknown image tool operation %q", op)
	}
}
