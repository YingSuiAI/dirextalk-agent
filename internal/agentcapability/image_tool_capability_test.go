package agentcapability

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"testing"

	capabilityclient "github.com/YingSuiAI/dirextalk-agent/internal/capability/client"
	"github.com/YingSuiAI/dirextalk-agent/internal/coreimagetool"
	"github.com/YingSuiAI/dirextalk-agent/internal/coremodel"
	"github.com/YingSuiAI/dirextalk-agent/internal/coretexttool"
	capv1 "github.com/YingSuiAI/dirextalk-capability-api/gen/go/dirextalk/capability/v1"
)

type imageCapabilityRepo struct{}

func (imageCapabilityRepo) Begin(context.Context, coreimagetool.BeginCommand) (coreimagetool.Upload, error) {
	return coreimagetool.Upload{}, coreimagetool.ErrInvalid
}
func (imageCapabilityRepo) Append(context.Context, coreimagetool.AppendCommand) (coreimagetool.Upload, error) {
	return coreimagetool.Upload{}, coreimagetool.ErrInvalid
}
func (imageCapabilityRepo) Commit(context.Context, coreimagetool.CommitCommand) (coreimagetool.Source, error) {
	return coreimagetool.Source{}, coreimagetool.ErrInvalid
}
func (imageCapabilityRepo) Consume(context.Context, coreimagetool.ConsumeCommand) (coreimagetool.ConsumedSource, error) {
	return coreimagetool.ConsumedSource{}, coreimagetool.ErrInvalid
}

type imageCapabilityConfig struct{}

func (imageCapabilityConfig) Get(context.Context, string, int64) (coretexttool.Config, error) {
	return coretexttool.Config{}, nil
}

type imageCapabilityModels struct{}

func (imageCapabilityModels) ResolveDefaultToolProfile(context.Context) (coremodel.Profile, error) {
	return coremodel.Profile{}, errors.New("unused")
}

func TestImageToolDescriptorExactOwnerSurface(t *testing.T) {
	d := NewCoreImageToolCapability(nil).Descriptor()
	if d.CapabilityId != "agent.image_tools.v1" || !d.Readiness || len(d.Operations) != 5 {
		t.Fatalf("descriptor=%+v", d)
	}
	want := map[string]struct{ scope, input, result string }{
		"upload_begin": {"agent:image_tools:upload", imageBeginInputSchema, imageUploadResultSchema}, "upload_append": {"agent:image_tools:upload", imageAppendInputSchema, imageUploadResultSchema}, "upload_commit": {"agent:image_tools:upload", imageCommitInputSchema, imageCommitResultSchema}, "extract_text": {"agent:image_tools:execute", imageExecuteInputSchema, imageExtractResultSchema}, "translate_text": {"agent:image_tools:execute", imageTranslateInputSchema, imageTranslateResultSchema},
	}
	for _, op := range d.Operations {
		w, ok := want[op.OperationId]
		if !ok {
			t.Fatalf("unexpected op %q", op.OperationId)
		}
		if len(op.Audience) != 1 || op.Audience[0] != capv1.Audience_AUDIENCE_OWNER_CLIENT || len(op.RequiredScopes) != 1 || op.RequiredScopes[0] != w.scope || op.OperationType != capv1.OperationType_OPERATION_TYPE_MUTATION {
			t.Fatalf("authority %s=%+v", op.OperationId, op)
		}
		if op.InputSchemaJson != w.input || op.ResultSchemaJson != w.result {
			t.Fatalf("schema drift %s", op.OperationId)
		}
		var in, out map[string]any
		if json.Unmarshal([]byte(w.input), &in) != nil || json.Unmarshal([]byte(w.result), &out) != nil {
			t.Fatalf("invalid schema %s", op.OperationId)
		}
		t.Logf("%s input=%s result=%s", op.OperationId, hex.EncodeToString(op.InputSchemaDigest), hex.EncodeToString(op.ResultSchemaDigest))
	}
}

func TestImageToolHandlerRejectsUnknownFieldsAndMissingIdentity(t *testing.T) {
	service, err := coreimagetool.NewService(imageCapabilityRepo{}, imageCapabilityConfig{}, imageCapabilityModels{}, func(coremodel.Profile) (coremodel.Client, error) { return nil, errors.New("unused") })
	if err != nil {
		t.Fatal(err)
	}
	capability := NewCoreImageToolCapability(service)
	valid := []byte(`{"idempotency_key":"00000000-0000-4000-8000-000000000001","image_request_id":"00000000-0000-4000-8000-000000000002","name":"a.png","mime_type":"image/png","declared_size":1,"content_sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}`)
	if _, err = capability.HandleOperation(context.Background(), "upload_begin", valid); err == nil {
		t.Fatal("missing identity accepted")
	}
	ctx := capabilityclient.WithCallContext(context.Background(), &capv1.CallContext{ChainId: "00000000-0000-4000-8000-000000000003", RootOperationId: "00000000-0000-4000-8000-000000000004"}, &capv1.PermissionContext{AuthenticatedOwnerId: "owner", AccountGeneration: 1})
	unknown := append(valid[:len(valid)-1], []byte(`,"extra":true}`)...)
	if _, err = capability.HandleOperation(ctx, "upload_begin", unknown); !errors.Is(err, coreimagetool.ErrInvalid) {
		t.Fatalf("unknown field error=%v", err)
	}
}
